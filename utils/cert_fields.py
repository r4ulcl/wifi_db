''' X.509 certificate field extraction: turn a DER-encoded certificate into the
flat dict of columns stored in the Certificate table. Split out of
cert_parsers so the tshark-driven parser module stays small; the parser calls
`_extract_cert_fields`. '''
# -*- coding: utf-8 -*-
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import (NameOID, ExtensionOID,
                                   AuthorityInformationAccessOID)

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


# (substring of the public-key class name, readable algorithm name). Checked in
# order; the first match wins, so 'RSA' is tried before falling back to the
# class name itself.
_PUBLIC_KEY_ALGORITHMS = (
    ('RSA', 'RSA'),
    ('EllipticCurve', 'EC'),
    ('DSA', 'DSA'),
    ('Ed25519', 'Ed25519'),
    ('Ed448', 'Ed448'),
)


def _subject_alt_names(cert):
    '''Return the Subject Alternative Names (DNS, IP, email) as a string'''
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        # Every cryptography GeneralName subtype exposes `.value`; the outer
        # except still covers a malformed SAN extension as a whole.
        return ", ".join(str(general_name.value) for general_name in ext)
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
        return ", ".join(
            str(general_name.value)
            for point in points
            for general_name in (point.full_name or []))
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
    # Readable algorithm name from the key class name (first matching substring
    # in _PUBLIC_KEY_ALGORITHMS, else the class name itself).
    class_name = type(public_key).__name__
    algorithm = next((label for needle, label in _PUBLIC_KEY_ALGORITHMS
                      if needle in class_name), class_name)
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
