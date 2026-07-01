''' Extract X.509 certificates from enterprise (802.1X) EAP-TLS/PEAP/TTLS
exchanges in a .cap file and store them in the Certificate table. '''
# -*- coding: utf-8 -*-
import binascii
import subprocess  # nosec B404 - only used with a fixed, absolute-path command

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import (NameOID, ExtensionOID,
                                   AuthorityInformationAccessOID)

from utils import database_utils
from utils.cap_common import _safe


def _name_attribute(name, oid):
    '''Return the first value of an X.509 Name attribute (OID) or ""'''
    try:
        attributes = name.get_attributes_for_oid(oid)
        if attributes:
            return attributes[0].value
    except Exception as error:
        # A missing/invalid attribute is expected for many certificates;
        # fall back to an empty string instead of failing the whole parse.
        print("Error in _name_attribute: ", error)
    return ""


def _public_key_algorithm(public_key):
    '''Map a cryptography public key object to a readable algorithm name'''
    class_name = type(public_key).__name__
    if 'RSA' in class_name:
        return 'RSA'
    if 'EllipticCurve' in class_name:
        return 'EC'
    if 'DSA' in class_name:
        return 'DSA'
    if 'Ed25519' in class_name:
        return 'Ed25519'
    if 'Ed448' in class_name:
        return 'Ed448'
    return class_name


def _subject_alt_names(cert):
    '''Return the Subject Alternative Names (DNS, IP, email) as a string'''
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        values = []
        for general_name in ext:
            try:
                values.append(str(general_name.value))
            except Exception:
                values.append(str(general_name))
        return ", ".join(values)
    except Exception:
        return ""


def _key_usage(cert):
    '''Return the Key Usage flags as a comma separated string'''
    try:
        usage = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE).value
        flags = [
            ('digital_signature', 'digitalSignature'),
            ('content_commitment', 'contentCommitment'),
            ('key_encipherment', 'keyEncipherment'),
            ('data_encipherment', 'dataEncipherment'),
            ('key_agreement', 'keyAgreement'),
            ('key_cert_sign', 'keyCertSign'),
            ('crl_sign', 'cRLSign'),
        ]
        result = [label for attr, label in flags
                  if getattr(usage, attr, False)]
        # encipher_only/decipher_only are only valid when key_agreement is set
        # (any unexpected error is handled by the outer except).
        if getattr(usage, 'key_agreement', False):
            if usage.encipher_only:
                result.append('encipherOnly')
            if usage.decipher_only:
                result.append('decipherOnly')
        return ", ".join(result)
    except Exception:
        return ""


def _ext_key_usage(cert):
    '''Return the Extended Key Usage OIDs (e.g. serverAuth, clientAuth)'''
    try:
        eku = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE).value
        # pylint: disable=protected-access
        return ", ".join(getattr(o, '_name', None) or o.dotted_string
                         for o in eku)
    except Exception:
        return ""


def _basic_constraints(cert):
    '''Return (is_ca, path_length) from the Basic Constraints extension'''
    try:
        constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value
        is_ca = 'True' if constraints.ca else 'False'
        return is_ca, constraints.path_length
    except Exception:
        return "", None


def _key_identifier(cert, oid, attribute):
    '''Return a hex key identifier (authority or subject) or ""'''
    def _read():
        value = cert.extensions.get_extension_for_oid(oid).value
        identifier = getattr(value, attribute, None)
        return identifier.hex() if identifier else ""
    return _safe(_read)


def _crl_urls(cert):
    '''Return the CRL distribution point URLs as a string'''
    try:
        points = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        urls = []
        for point in points:
            if point.full_name:
                for general_name in point.full_name:
                    urls.append(str(general_name.value))
        return ", ".join(urls)
    except Exception:
        return ""


def _ocsp_urls(cert):
    '''Return the OCSP responder URLs from Authority Information Access'''
    try:
        descriptions = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        urls = []
        for description in descriptions:
            if description.access_method == AuthorityInformationAccessOID.OCSP:
                urls.append(str(description.access_location.value))
        return ", ".join(urls)
    except Exception:
        return ""


def _cert_datetime(cert, attr):
    '''Return the not_valid_before/after datetime, preferring the timezone
    aware *_utc accessors added in cryptography 42.0.'''
    return getattr(cert, attr + '_utc', None) or getattr(cert, attr)


def _public_key_details(cert):
    '''Return (algorithm, size, curve, exponent) describing the public key.'''
    public_key = cert.public_key()
    algorithm = _public_key_algorithm(public_key)
    size = _safe(lambda: public_key.key_size, 0)
    curve = ""
    exponent = ""
    if algorithm == 'EC':
        curve = _safe(lambda: public_key.curve.name)
    elif algorithm == 'RSA':
        exponent = _safe(lambda: str(public_key.public_numbers().e))
    return algorithm, size, curve, exponent


def _cert_names(cert):
    '''Subject/issuer CN/O/OU attributes for a certificate.'''
    return {
        'subject_cn': _name_attribute(cert.subject, NameOID.COMMON_NAME),
        'subject_o': _name_attribute(cert.subject, NameOID.ORGANIZATION_NAME),
        'subject_ou': _name_attribute(
            cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        'issuer_cn': _name_attribute(cert.issuer, NameOID.COMMON_NAME),
        'issuer_o': _name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME),
        'issuer_ou': _name_attribute(
            cert.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
    }


def _extract_cert_fields(der, cert_index):
    '''Parse a DER encoded X.509 certificate and return all its fields
    as a dict ready to be inserted in the Certificate table.'''
    cert = x509.load_der_x509_certificate(der)

    not_before_dt = _safe(lambda: _cert_datetime(cert, 'not_valid_before'),
                          None)
    not_after_dt = _safe(lambda: _cert_datetime(cert, 'not_valid_after'), None)

    def _fmt(value):
        return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""

    algorithm, size, curve, exponent = _safe(
        lambda: _public_key_details(cert), ("", 0, "", ""))
    is_ca, path_length = _basic_constraints(cert)

    # cryptography exposes the readable OID name only via the internal
    # `_name` attribute; SHA1 is used solely as the standard cert thumbprint.
    # pylint: disable=protected-access
    return {
        'cert_index': cert_index,
        'version': _safe(lambda: cert.version.name),
        'serial_number': _safe(lambda: format(cert.serial_number, 'x')),
        'signature_algorithm': _safe(
            lambda: cert.signature_algorithm_oid._name),
        'issuer': _safe(lambda: cert.issuer.rfc4514_string()),
        'subject': _safe(lambda: cert.subject.rfc4514_string()),
        'not_before': _fmt(not_before_dt),
        'not_after': _fmt(not_after_dt),
        **_cert_names(cert),
        'public_key_algorithm': algorithm,
        'public_key_size': size,
        'public_key_curve': curve,
        'public_key_exponent': exponent,
        'subject_alt_names': _subject_alt_names(cert),
        'key_usage': _key_usage(cert),
        'ext_key_usage': _ext_key_usage(cert),
        'is_ca': is_ca,
        'path_length': path_length,
        'self_signed': _safe(
            lambda: 'True' if cert.subject == cert.issuer else 'False'),
        'authority_key_id': _key_identifier(
            cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER, 'key_identifier'),
        'subject_key_id': _key_identifier(
            cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER, 'digest'),
        'crl_urls': _crl_urls(cert),
        'ocsp_urls': _ocsp_urls(cert),
        'validity_days': _safe(
            lambda: (not_after_dt - not_before_dt).days, None),
        'sha1_fingerprint': _safe(
            lambda: cert.fingerprint(hashes.SHA1()).hex()),  # nosec B303
        'sha256_fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
    }


def _cert_attribution(columns):
    '''Resolve (cert_field, bssid, mac, cert_type) for one tshark line.

    Uses the EAP direction to know whose certificate this is: the authenticator
    (AP) sends EAP-Request packets (code 1) carrying the server certificate,
    while the supplicant sends EAP-Response packets (code 2) carrying the client
    certificate. Either way the BSSID stored is the AP and the MAC the client.'''
    cert_field = columns[0]
    src = columns[1] if len(columns) > 1 else ""
    dst = columns[2] if len(columns) > 2 else ""
    eap_code = columns[3] if len(columns) > 3 else ""
    if eap_code == '2':  # EAP-Response: certificate sent by the client
        return cert_field, dst, src, 'Client'
    if eap_code == '1':  # EAP-Request: certificate sent by the AP/server
        return cert_field, src, dst, 'AP'
    return cert_field, src, dst, 'Unknown'


def _insert_one_cert(cursor, verbose, file, addr, cert_hex, cert_index):
    '''Parse and store a single hex-encoded certificate. Returns errors (0/1).

    `addr` is the (bssid, mac, cert_type) tuple from `_cert_attribution`.'''
    bssid, mac, cert_type = addr
    try:
        der = binascii.unhexlify(cert_hex.replace(':', ''))
        cert = _extract_cert_fields(der, cert_index)
        if verbose:
            print("Certificate (" + cert_type + ") for AP " +
                  str(bssid) + ": " + str(cert.get('subject')))
        return database_utils.insertCertificate(
            cursor, verbose, bssid, mac, cert_type, file, cert)
    except Exception as error:
        if verbose:
            print("parse_certificates cert error: " + str(error))
        return 1


def _insert_cert_line(cursor, verbose, file, columns):
    '''Insert every certificate found on one `tshark -T fields` output line.

    `columns` is the tab-split line: the certificate column (a chain is joined
    with commas by tshark), wlan.sa, wlan.da and eap.code. Returns the number
    of errors hit while parsing/inserting.'''
    cert_field, bssid, mac, cert_type = _cert_attribution(columns)

    # Without an AP address there is nothing to key the certificate on; skip
    # it rather than create a phantom empty-BSSID AP row.
    if not bssid:
        if verbose:
            print("Certificate without wlan addresses, skip")
        return 0

    errors = 0
    addr = (bssid, mac, cert_type)
    # A single Certificate message can carry a full chain (server, CA, ...);
    # tshark joins those certificates with a comma.
    for cert_index, cert_hex in enumerate(cert_field.split(',')):
        cert_hex = cert_hex.strip()
        if cert_hex:
            errors += _insert_one_cert(cursor, verbose, file, addr,
                                       cert_hex, cert_index)
    return errors


# Get X.509 certificates from EAP-TLS/PEAP/TTLS in .cap
def parse_certificates(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name

        # EAP-TLS certificates are reassembled by tshark across several EAPOL
        # fragments. pyshark's per-packet display-filter iteration does not
        # surface that reassembled `tls.handshake.certificate` field, so it
        # never finds anything. Extract it straight from tshark in `-T fields`
        # mode instead (the approach of the standalone reference tool), pulling
        # the certificate together with the wlan addresses and EAP code needed
        # to attribute it. Fixed absolute-path binary, no shell; the file name
        # is a separate argv element, so it cannot be used for injection.
        completed = subprocess.run(  # nosec B603
            ["/usr/bin/tshark", "-r", file,
             "-Y", "tls.handshake.certificate and eapol",
             "-T", "fields",
             "-e", "tls.handshake.certificate",
             "-e", "wlan.sa", "-e", "wlan.da", "-e", "eap.code"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)

        output = completed.stdout.decode('utf-8', 'replace')
        for raw_line in output.splitlines():
            columns = raw_line.split('\t')
            if not columns[0]:  # no certificate on this line
                continue
            errors += _insert_cert_line(cursor, verbose, file, columns)

        database.commit()
        print(".cap Certificate done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_certificates (CAP): ", error)
        print(".cap Certificate done, errors", errors)
