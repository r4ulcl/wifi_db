'''Coverage for the certificate parsing/field-extraction branches not reached
by the sample capture: the tshark-driven parse_certificates dispatch (verbose
logging, malformed certs, address-less lines, the reassembly error path) and
the cert_fields/cert_extensions helpers that need certificate features (EC and
Ed25519 keys, SAN, encipher/decipher-only key usage, OCSP) absent from the RSA
sample cert.'''
import ipaddress
import unittest
from unittest import mock

from cryptography import x509
from cryptography.x509.oid import (NameOID, ExtendedKeyUsageOID,
                                   AuthorityInformationAccessOID)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ed25519

from utils import cert_parsers, cert_fields, cert_extensions

from test_base import mem_db, colon_hex, build_self_signed


def _rich_cert_der():
    '''A self-signed RSA cert carrying every extension cert_extensions reads:
    SAN, full Key Usage (incl. encipher/decipher-only), Basic Constraints,
    AKI/SKI, CRL distribution points and Authority Info Access (OCSP).'''
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'rich.test'),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Org'),
                      x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                                         'Unit')])
    extensions = [
        (x509.SubjectAlternativeName(
            [x509.DNSName('rich.test'),
             x509.IPAddress(ipaddress.ip_address('10.0.0.1'))]), False),
        (x509.KeyUsage(
            digital_signature=True, content_commitment=False,
            key_encipherment=True, data_encipherment=False,
            key_agreement=True, key_cert_sign=True, crl_sign=True,
            encipher_only=True, decipher_only=True), True),
        (x509.BasicConstraints(ca=True, path_length=1), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
        (x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False),
        (x509.AuthorityKeyIdentifier.from_issuer_public_key(
            key.public_key()), False),
        (x509.CRLDistributionPoints([x509.DistributionPoint(
            full_name=[x509.UniformResourceIdentifier(
                'http://crl.test/ca.crl')],
            relative_name=None, reasons=None, crl_issuer=None)]), False),
        (x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier('http://ocsp.test')),
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier('http://ca.test/ca.crt'))]),
         False),
    ]
    cert = build_self_signed(key, name, extensions, sign_hash=hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


def _key_usage_cert(**flags):
    '''A minimal self-signed cert carrying only a Key Usage extension with the
    given flags, for exercising the individual key-usage branches.'''
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ku.test')])
    usage = dict(digital_signature=True, content_commitment=False,
                 key_encipherment=False, data_encipherment=False,
                 key_agreement=False, key_cert_sign=False, crl_sign=False,
                 encipher_only=False, decipher_only=False)
    usage.update(flags)
    return build_self_signed(key, name, [(x509.KeyUsage(**usage), True)],
                             sign_hash=hashes.SHA256())


def _ed25519_cert_der():
    key = ed25519.Ed25519PrivateKey.generate()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'ed.test')])
    # Ed25519 signs with no separate hash.
    cert = build_self_signed(key, name, sign_hash=None)
    return cert.public_bytes(serialization.Encoding.DER)


class TestCertFieldExtraction(unittest.TestCase):
    def test_rich_cert_extensions(self):
        fields = cert_fields._extract_cert_fields(_rich_cert_der(), 0)
        # SAN join, key usage (incl. encipher/decipher-only) and OCSP URL.
        self.assertIn('rich.test', fields['subject_alt_names'])
        self.assertIn('10.0.0.1', fields['subject_alt_names'])
        self.assertIn('encipherOnly', fields['key_usage'])
        self.assertIn('decipherOnly', fields['key_usage'])
        self.assertEqual(fields['ocsp_urls'], 'http://ocsp.test')
        self.assertEqual(fields['crl_urls'], 'http://crl.test/ca.crl')
        self.assertEqual(fields['is_ca'], 'True')

    def test_public_key_details_ec_curve(self):
        # An EC public key (class name contains 'EllipticCurve') reports its
        # curve name; drive _public_key_details directly since cryptography's
        # concrete class name varies by version.
        class _Curve:
            name = 'secp256r1'

        class EllipticCurvePublicKey:
            key_size = 256
            curve = _Curve()

        class _Cert:
            def public_key(self):
                return EllipticCurvePublicKey()

        algorithm, size, curve, exponent = cert_fields._public_key_details(
            _Cert())
        self.assertEqual(algorithm, 'EC')
        self.assertEqual(curve, 'secp256r1')
        self.assertEqual(exponent, '')

    def test_key_usage_branches(self):
        # key_agreement set but encipher/decipher-only clear: the inner ifs are
        # both skipped (43->45, 45->47), and key_agreement clear skips the
        # whole block (42->47).
        agreement = cert_extensions._key_usage(
            _key_usage_cert(key_agreement=True))
        self.assertIn('keyAgreement', agreement)
        self.assertNotIn('encipherOnly', agreement)
        no_agreement = cert_extensions._key_usage(
            _key_usage_cert(key_encipherment=True))
        self.assertIn('keyEncipherment', no_agreement)

    def test_ed25519_cert_neither_rsa_nor_ec(self):
        fields = cert_fields._extract_cert_fields(_ed25519_cert_der(), 0)
        self.assertEqual(fields['public_key_algorithm'], 'Ed25519')
        # Neither the EC curve nor the RSA exponent branch is taken.
        self.assertEqual(fields['public_key_curve'], '')
        self.assertEqual(fields['public_key_exponent'], '')

    def test_name_attribute_error_is_swallowed(self):
        class _BadName:
            def get_attributes_for_oid(self, _oid):
                raise ValueError("bad name")

        self.assertEqual(
            cert_fields._name_attribute(_BadName(), NameOID.COMMON_NAME), '')


class TestParseCertificates(unittest.TestCase):
    def setUp(self):
        self.database = mem_db()
        self.cursor = self.database.cursor()

    def tearDown(self):
        self.database.close()

    def _run(self, output, verbose):
        completed = mock.Mock()
        completed.stdout = output.encode('utf-8')
        with mock.patch.object(cert_parsers.subprocess, 'run',
                               return_value=completed):
            cert_parsers.parse_certificates('cap.cap', self.database, verbose)

    def test_lines_cover_all_branches(self):
        good = colon_hex(_rich_cert_der())
        lines = [
            "\t\t\t",                                       # empty cert col
            # A chain with a trailing empty element exercises the skip-empty
            # branch inside _insert_cert_line's split(',') loop.
            good + ",\tAA:BB:CC:00:C0:01\tAA:BB:CC:00:C0:02\t1",  # AP cert
            good + "\t\t\t",                                # no wlan addresses
            "zz\tAA:BB:CC:00:C0:03\tAA:BB:CC:00:C0:04\t2",  # malformed hex
        ]
        output = "\n".join(lines)
        for verbose in (True, False):
            self._run(output, verbose)
        row = self.cursor.execute(
            "SELECT cert_type FROM Certificate WHERE bssid = ?",
            ('AA:BB:CC:00:C0:01',)).fetchone()
        self.assertEqual(row, ('AP',))

    def test_subprocess_failure_is_caught(self):
        with mock.patch.object(cert_parsers.subprocess, 'run',
                               side_effect=OSError("tshark missing")):
            # Must not raise; the error is caught and reported.
            cert_parsers.parse_certificates('cap.cap', self.database, False)


if __name__ == '__main__':
    unittest.main()
