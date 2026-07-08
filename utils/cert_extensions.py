''' X.509 certificate extension helpers: pull individual extension values (SAN,
key usage, basic constraints, key identifiers, CRL/OCSP URLs) out of a parsed
certificate. Split out of cert_fields to keep that module's total complexity
down; `_extract_cert_fields` in cert_fields calls these helpers. '''
# -*- coding: utf-8 -*-
from cryptography.x509.oid import (ExtensionOID,
                                   AuthorityInformationAccessOID)

from utils.cap_common import _safe


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
