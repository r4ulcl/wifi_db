import os
import datetime
import tempfile
import unittest
from unittest import mock

from utils import database_utils

import wifi_db

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# Repo root (tests/ lives one level below it). Used to locate real files the
# suite hashes as sample inputs, e.g. README.md, regardless of cwd.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Fixed validity window shared by every test certificate.
_CERT_NOT_BEFORE = datetime.datetime(2024, 1, 1)
_CERT_NOT_AFTER = datetime.datetime(2030, 1, 1)


def mem_db():
    '''A fresh in-memory database with the schema applied, for tests that need
    a real database but not the on-disk DBTestBase lifecycle.'''
    database = database_utils.connectDatabase(':memory:', False)
    database_utils.createDatabase(database, False)
    return database


def colon_hex(data):
    '''Colon-separated hex of a byte string (b'\\xaa\\xbb' -> 'aa:bb'): the
    form tshark prints certificate DER and SSID octet fields in.'''
    return ':'.join('%02x' % b for b in data)


def build_self_signed(key, name, extensions=(), *, sign_hash):
    '''Build a self-signed certificate (issuer == subject) over the shared
    validity window and return the cryptography Certificate. `extensions` is an
    iterable of (extension, critical) pairs; `sign_hash` is the signature hash
    (None for Ed25519, which signs without one).'''
    builder = (x509.CertificateBuilder()
               .subject_name(name).issuer_name(name)
               .public_key(key.public_key())
               .serial_number(x509.random_serial_number())
               .not_valid_before(_CERT_NOT_BEFORE)
               .not_valid_after(_CERT_NOT_AFTER))
    for extension, critical in extensions:
        builder = builder.add_extension(extension, critical)
    return builder.sign(key, sign_hash)


def run_main(argv):
    '''Invoke wifi_db.main() with argv (minus the program name), patching out
    the update check and vendor download and forcing tool detection off, so the
    CLI runs offline. Shared by the CLI tests.'''
    with mock.patch("wifi_db.sys.argv", ["wifi_db.py"] + argv), \
            mock.patch("wifi_db.update.check_for_update"), \
            mock.patch("wifi_db.oui.load_vendors", return_value={}), \
            mock.patch("wifi_db.detect_tools", return_value=(False, False)):
        wifi_db.main()


class MemDBTempFile(unittest.TestCase):
    '''In-memory database plus a throwaway on-disk file. Some inserts hash the
    capture/file path, so it must really exist on disk. Subclasses set
    `temp_suffix` and read self.database, self.cursor and self.path.'''
    temp_suffix = ''

    def setUp(self):
        self.database = mem_db()
        self.cursor = self.database.cursor()
        handle = tempfile.NamedTemporaryFile(suffix=self.temp_suffix,
                                             delete=False)
        handle.write(b'capture')
        handle.close()
        self.path = handle.name

    def tearDown(self):
        self.database.close()
        if os.path.exists(self.path):
            os.remove(self.path)


def sample_cert():
    '''A parsed certificate dict as built by _extract_cert_fields, for tests.'''
    return {
        'cert_index': 0,
        'version': 'v3',
        'serial_number': 'abcdef',
        'signature_algorithm': 'sha256WithRSAEncryption',
        'issuer': 'CN=Test CA,O=Test Org',
        'subject': 'CN=radius.test.local,O=Test Org',
        'not_before': '2024-01-01 00:00:00',
        'not_after': '2025-01-01 00:00:00',
        'subject_cn': 'radius.test.local',
        'subject_o': 'Test Org',
        'subject_ou': 'IT',
        'issuer_cn': 'Test CA',
        'issuer_o': 'Test Org',
        'issuer_ou': 'IT',
        'public_key_algorithm': 'RSA',
        'public_key_size': 2048,
        'public_key_curve': '',
        'public_key_exponent': '65537',
        'subject_alt_names': 'radius.test.local, 10.0.0.1',
        'key_usage': 'digitalSignature, keyEncipherment',
        'ext_key_usage': 'serverAuth',
        'is_ca': 'False',
        'path_length': None,
        'self_signed': 'False',
        'authority_key_id': 'aabbcc',
        'subject_key_id': 'ddeeff',
        'crl_urls': 'http://crl.test.local/ca.crl',
        'ocsp_urls': 'http://ocsp.test.local',
        'validity_days': 366,
        'sha1_fingerprint': '00aa11bb22cc',
        'sha256_fingerprint': '00aa11bb22cc33dd44ee',
    }


class DBTestBase(unittest.TestCase):
    def setUp(self):
        self.verbose = False
        self.database_name = 'test_database.db'
        self.database = database_utils.connectDatabase(self.database_name,
                                                       self.verbose)
        database_utils.createDatabase(self.database, self.verbose)
        database_utils.createViews(self.database, self.verbose)
        self.c = self.database.cursor()
        self.bssid = "00:11:22:33:44:55"
        self.mac = "55:44:33:22:11:00"
        self.test_database_name = 'test_database.db'
        self.test_database_conn = None

    def tearDown(self):
        self.database.close()
        if self.test_database_conn:
            self.test_database_conn.close()
        if os.path.exists(self.test_database_name):
            os.remove(self.test_database_name)

    def insert_test_ap(self, **overrides):
        '''Insert a standard test AP (self.bssid), assert success and return the
        APRow field values used. Pass keyword overrides to vary a field (e.g.
        ``manuf=...``) and read them back from the returned dict for assertions.'''
        fields = {
            'essid': "Test_AP", 'manuf': "Test_Manufacturer", 'channel': "6",
            'freqmhz': "2437", 'carrier': "test", 'encryption': "WPA2",
            'packets_total': "10", 'lat': "37.7749", 'lon': "-122.4194",
            'cloaked': 'False', 'mfpc': 'False', 'mfpr': 'False',
            'firstTimeSeen': 0,
        }
        fields.update(overrides)
        result = database_utils.insertAP(
            self.c, self.verbose, database_utils.APRow(
                bssid=self.bssid, **fields))
        self.assertEqual(result, 0)
        return fields

    def insert_test_client(self, **overrides):
        '''Insert a standard test Client (self.mac), assert success and return
        the ClientRow field values used. Pass keyword overrides (e.g.
        ``ssid=...``) and read them back from the returned dict for assertions.'''
        fields = {
            'ssid': "", 'manuf': "Test_Manufacturer", 'client_type': "10",
            'packets_total': "-70", 'device': "Misc", 'firstTimeSeen': 0,
        }
        fields.update(overrides)
        result = database_utils.insertClients(
            self.c, self.verbose, database_utils.ClientRow(
                mac=self.mac, **fields))
        self.assertEqual(result, 0)
        return fields

    def insert_test_handshake(self):
        '''Insert a handshake (self.bssid/self.mac) referencing README.md,
        assert success and return the file path used.'''
        path = os.path.join(PROJECT_ROOT, "README.md")
        result = database_utils.insertHandshake(self.c, self.verbose,
                                                self.bssid, self.mac, path)
        self.assertEqual(result, 0)
        return path

    @staticmethod
    def _make_cert_hex(cn):
        '''Build a real self-signed cert and return its colon-separated hex
        DER, exactly as `tshark -e tls.handshake.certificate` emits it.'''
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        cert = build_self_signed(key, name, sign_hash=hashes.SHA256())
        return colon_hex(cert.public_bytes(serialization.Encoding.DER))
