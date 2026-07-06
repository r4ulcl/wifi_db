''' X.509 certificate field extraction: turn a DER-encoded certificate into the
flat dict of columns stored in the Certificate table. Split out of
cert_parsers so the tshark-driven parser module stays small; the parser calls
`_extract_cert_fields`. '''
# -*- coding: utf-8 -*-
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID

from utils.cap_common import _safe
from utils.cert_extensions import (_subject_alt_names, _key_usage,
                                   _ext_key_usage, _basic_constraints,
                                   _key_identifier, _crl_urls,
                                   _ocsp_urls)  # noqa: F401


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
