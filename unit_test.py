import os
# import sqlite3
import unittest
# from database_utils import *
from utils import database_utils
from utils import oui
# from utils import update
# from utils import wifi_db_aircrack

import wifi_db
import nest_asyncio


class TestFunctions(unittest.TestCase):
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

    def test_connectDatabase(self):
        self.assertIsNotNone(self.database)

    def test_createDatabase(self):
        self.test_database_conn = database_utils.connectDatabase(
            self.test_database_name, False
        )
        database_utils.createDatabase(self.test_database_conn, self.verbose)
        cursor = self.test_database_conn.cursor()
        # Verify that the tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        expected_tables = [
            ('AP',),
            ('Client',),
            ('SeenClient',),
            ('Connected',),
            ('SeenAp',),
            ('Probe',),
            ('Handshake',),
            ('Identity',),
            ('Files',),
            ('Certificate',),
            ('EAPMD5',)
        ]
        self.assertEqual(tables, expected_tables)

    def test_createViews(self):
        self.test_database_conn = database_utils.connectDatabase(
            self.test_database_name, False
        )
        # Create tables first
        database_utils.createDatabase(self.test_database_conn, False)
        database_utils.createViews(self.test_database_conn, self.verbose)
        cursor = self.test_database_conn.cursor()
        # Verify that the views were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view';")
        views = cursor.fetchall()
        expected_views = [
            ('ProbeClients',),
            ('ConnectedAP',),
            ('ProbeClientsConnected',),
            ('HandshakeAP',),
            ('HandshakeAPUnique',),
            ('IdentityAP',),
            ('CertificateAP',),
            ('SecurityAP',),
            ('CapabilitiesAP',),
            ('SummaryAP',)
        ]
        self.assertEqual(views, expected_views)

    def test_insertAP(self):
        essid = "Test_AP"
        manuf = "Test_Manufacturer"
        channel = "6"
        freqmhz = "2437"
        carrier = "test"
        encryption = "WPA2"
        packets_total = "10"
        lat = "37.7749"
        lon = "-122.4194"
        cloaked = 'False'
        mfpc = 'False'
        mfpr = 'False'
        # Insert new AP
        result = database_utils.insertAP(self.c, self.verbose, self.bssid,
                                         essid, manuf, channel, freqmhz,
                                         carrier, encryption, packets_total,
                                         lat, lon, cloaked, mfpc, mfpr, 0)

        self.assertEqual(result, 0)

        self.c.execute("SELECT ssid FROM AP WHERE bssid = ?", (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], essid)

    def test_insertClients(self):
        ssid = "Test_AP"
        manuf = "Test_Manufacturer"
        packets_total = "10"
        power = "-70"
        # Insert new client
        result = database_utils.insertClients(self.c, self.verbose, self.mac,
                                              ssid, manuf, packets_total,
                                              power, "Misc", 0)

        self.assertEqual(result, 0)

        self.c.execute("SELECT manuf, randomized FROM Client WHERE mac=?",
                       (self.mac,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], manuf)
        # 55:.. first octet 0x55, locally-administered bit clear -> not random
        self.assertEqual(rows[0][1], 'False')

    def test_insertWPS(self):
        # Define WPS parameters
        wlan_ssid = "Test_SSID"
        wps_version = "1.0"
        wps_device_name = "Test_Device"
        wps_model_name = "Test_Model"
        wps_model_number = "12345"
        wps_config_methods = "1234"
        wps_config_methods_keypad = True

        # Insert new WPS
        result = database_utils.insertWPS(self.c, self.verbose, self.bssid,
                                          wlan_ssid, wps_version,
                                          wps_device_name, wps_model_name,
                                          wps_model_number,
                                          wps_config_methods,
                                          wps_config_methods_keypad)
        self.assertEqual(result, 0)

        # WPS columns now live on the AP row (1:1 merge)
        self.c.execute("SELECT wlan_ssid FROM AP WHERE bssid = ?",
                       (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], wlan_ssid)

    def test_insertCertificate(self):
        # Define a parsed certificate (as built by _extract_cert_fields)
        cert = {
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

        # Insert new certificate (AP/server certificate)
        result = database_utils.insertCertificate(self.c, self.verbose,
                                                  self.bssid, self.mac,
                                                  'AP', 'test.cap', cert)
        self.assertEqual(result, 0)

        self.c.execute("SELECT subject_cn, issuer_cn, cert_type, "
                       "subject_alt_names, ext_key_usage, self_signed, "
                       "validity_days, public_key_exponent, "
                       "sha256_fingerprint "
                       "FROM Certificate WHERE bssid = ?", (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], cert['subject_cn'])
        self.assertEqual(rows[0][1], cert['issuer_cn'])
        self.assertEqual(rows[0][2], 'AP')
        self.assertEqual(rows[0][3], cert['subject_alt_names'])
        self.assertEqual(rows[0][4], cert['ext_key_usage'])
        self.assertEqual(rows[0][5], cert['self_signed'])
        self.assertEqual(rows[0][6], cert['validity_days'])
        self.assertEqual(rows[0][7], cert['public_key_exponent'])
        self.assertEqual(rows[0][8], cert['sha256_fingerprint'])

        # A client certificate (different fingerprint) is stored in the same
        # table for the same AP, tagged with its own cert_type
        client_cert = dict(cert)
        client_cert['sha256_fingerprint'] = '99ff88ee77dd'
        client_cert['subject_cn'] = 'user.test.local'
        result = database_utils.insertCertificate(self.c, self.verbose,
                                                  self.bssid, self.mac,
                                                  'Client', 'test.cap',
                                                  client_cert)
        self.assertEqual(result, 0)
        self.c.execute("SELECT cert_type FROM Certificate WHERE bssid = ? "
                       "ORDER BY cert_type", (self.bssid,))
        self.assertEqual([r[0] for r in self.c.fetchall()], ['AP', 'Client'])

        # Inserting the same certificate again must not duplicate it
        result = database_utils.insertCertificate(self.c, self.verbose,
                                                  self.bssid, self.mac,
                                                  'AP', 'test.cap', cert)
        self.assertEqual(result, 0)
        self.c.execute("SELECT COUNT(*) FROM Certificate WHERE bssid = ?",
                       (self.bssid,))
        self.assertEqual(self.c.fetchone()[0], 2)

    def test_insertSecurity(self):
        # Insert RSN/WPA security details for an AP (WPA3-Enterprise)
        result = database_utils.insertSecurity(
            self.c, self.verbose, self.bssid, 'WPA3',
            '802.1X-SuiteB-SHA384', 'GCMP-256', 'GCMP-256', 'True',
            'Required', '0x00c0', 'test.cap')
        self.assertEqual(result, 0)

        # Security columns now live on the AP row (1:1 merge)
        self.c.execute("SELECT wpa_version, akm_suites, pairwise_ciphers, "
                       "enterprise, pmf FROM AP WHERE bssid = ?",
                       (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 'WPA3')
        self.assertEqual(rows[0][1], '802.1X-SuiteB-SHA384')
        self.assertEqual(rows[0][2], 'GCMP-256')
        self.assertEqual(rows[0][3], 'True')
        self.assertEqual(rows[0][4], 'Required')

        # A second beacon for the same BSSID overwrites the AP columns
        result = database_utils.insertSecurity(
            self.c, self.verbose, self.bssid, 'WPA2', 'PSK', 'CCMP-128',
            'CCMP-128', 'False', 'Capable', '0x0080', 'test.cap')
        self.assertEqual(result, 0)
        self.c.execute("SELECT COUNT(*), MAX(wpa_version) FROM AP "
                       "WHERE bssid = ?", (self.bssid,))
        count, wpa_version = self.c.fetchone()
        self.assertEqual(count, 1)
        self.assertEqual(wpa_version, 'WPA2')

    def test_security_and_certificate_views(self):
        # The SecurityAP and CertificateAP views must join Security/Certificate
        # to AP on the BSSID and expose the expected columns.
        database_utils.insertSecurity(
            self.c, self.verbose, self.bssid, 'WPA3', 'SAE', 'CCMP-128',
            'CCMP-128', 'False', 'Required', '0x00c0', 'test.cap')
        self.c.execute("SELECT wpa_version, pmf FROM SecurityAP "
                       "WHERE bssid = ?", (self.bssid,))
        row = self.c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'WPA3')
        self.assertEqual(row[1], 'Required')

        cert = {
            'cert_index': 0, 'version': 'v3', 'serial_number': 'ab',
            'signature_algorithm': 'sha256WithRSAEncryption',
            'issuer': 'CN=CA', 'subject': 'CN=radius',
            'not_before': '', 'not_after': '', 'subject_cn': 'radius',
            'subject_o': '', 'subject_ou': '', 'issuer_cn': 'CA',
            'issuer_o': '', 'issuer_ou': '', 'public_key_algorithm': 'RSA',
            'public_key_size': 2048, 'public_key_curve': '',
            'public_key_exponent': '65537', 'subject_alt_names': '',
            'key_usage': '', 'ext_key_usage': '', 'is_ca': 'False',
            'path_length': None, 'self_signed': 'False',
            'authority_key_id': '', 'subject_key_id': '', 'crl_urls': '',
            'ocsp_urls': '', 'validity_days': 365,
            'sha1_fingerprint': 'aa', 'sha256_fingerprint': 'viewfp',
        }
        database_utils.insertCertificate(self.c, self.verbose, self.bssid,
                                         self.mac, 'AP', 'test.cap', cert)
        self.c.execute("SELECT cert_type, subject_cn FROM CertificateAP "
                       "WHERE bssid = ?", (self.bssid,))
        row = self.c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'AP')
        self.assertEqual(row[1], 'radius')

    def test_insertCapabilities(self):
        # Store 802.11r/k/v + MBSSID + CSA capabilities on the AP row.
        result = database_utils.insertCapabilities(
            self.c, self.verbose, self.bssid, 'True', '0xabcd', 'True',
            'True', 'True', 8, 'True', 36)
        self.assertEqual(result, 0)
        self.c.execute("SELECT ft_80211r, mobility_domain_id, rrm_80211k, "
                       "bss_transition_80211v, mbssid, max_bssid_indicator, "
                       "csa, csa_new_channel FROM AP WHERE bssid = ?",
                       (self.bssid,))
        row = self.c.fetchone()
        self.assertEqual(row, ('True', '0xabcd', 'True', 'True', 'True', 8,
                               'True', 36))

        # A later beacon without the elements must NOT clear sticky flags, and
        # must keep the detail fields it does not carry.
        result = database_utils.insertCapabilities(
            self.c, self.verbose, self.bssid, 'False', '', 'False', 'False',
            'False', None, 'False', None)
        self.assertEqual(result, 0)
        self.c.execute("SELECT ft_80211r, mobility_domain_id, rrm_80211k, "
                       "csa_new_channel FROM AP WHERE bssid = ?",
                       (self.bssid,))
        row = self.c.fetchone()
        self.assertEqual(row, ('True', '0xabcd', 'True', 36))

    def test_cloaked_sticky_on_merge(self):
        # A detected cloaked='True' must survive later merges (e.g. a beacon
        # enriching the AP via insertAPConstraint, which passes 'False').
        database_utils.insertAP(self.c, self.verbose, self.bssid, "", "manuf",
                                "6", "2437", "", "WPA2", "0", "0.0", "0.0",
                                'True', 'False', 'False', 0)
        database_utils.insertSecurity(
            self.c, self.verbose, self.bssid, 'WPA2', 'PSK', 'CCMP-128',
            'CCMP-128', 'False', 'Disabled', '0x0000', 'test.cap')
        self.c.execute("SELECT cloaked FROM AP WHERE bssid = ?", (self.bssid,))
        self.assertEqual(self.c.fetchone()[0], 'True')

    def test_insertHiddenSSID(self):
        # An AP with no SSID yet gets its name filled and flagged as revealed.
        database_utils.insertAPConstraint(self.c, self.verbose, self.bssid)
        result = database_utils.insertHiddenSSID(
            self.c, self.verbose, self.bssid, "RecoveredNet")
        self.assertEqual(result, 0)
        self.c.execute("SELECT ssid, ssid_revealed FROM AP WHERE bssid = ?",
                       (self.bssid,))
        self.assertEqual(self.c.fetchone(), ("RecoveredNet", 'True'))

        # A known SSID must never be overwritten by a reveal.
        result = database_utils.insertHiddenSSID(
            self.c, self.verbose, self.bssid, "DifferentName")
        self.assertEqual(result, 0)
        self.c.execute("SELECT ssid FROM AP WHERE bssid = ?", (self.bssid,))
        self.assertEqual(self.c.fetchone()[0], "RecoveredNet")

    def test_capabilities_view(self):
        # The CapabilitiesAP view exposes the capability columns from AP and
        # only lists APs that advertise at least one of them.
        database_utils.insertCapabilities(
            self.c, self.verbose, self.bssid, 'True', '0x1234', 'False',
            'False', 'False', None, 'False', None)
        self.c.execute("SELECT ssid, ft_80211r, mobility_domain_id "
                       "FROM CapabilitiesAP WHERE bssid = ?", (self.bssid,))
        row = self.c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[1], 'True')
        self.assertEqual(row[2], '0x1234')

        # An AP with no capabilities advertised must not appear in the view.
        other = "AA:BB:CC:DD:EE:FF"
        database_utils.insertAPConstraint(self.c, self.verbose, other)
        self.c.execute("SELECT COUNT(*) FROM CapabilitiesAP WHERE bssid = ?",
                       (other,))
        self.assertEqual(self.c.fetchone()[0], 0)

    def test_isRandomizedMAC(self):
        # bit 1 of the first octet set -> locally administered (randomized)
        self.assertEqual(database_utils.isRandomizedMAC("DA:BB:CC:DD:EE:FF"),
                         'True')
        # globally administered (OUI) MAC -> not randomized
        self.assertEqual(database_utils.isRandomizedMAC("00:11:22:33:44:55"),
                         'False')

    def test_insertEAPMD5(self):
        result = database_utils.insertEAPMD5(
            self.c, self.verbose, self.bssid, self.mac, "user", "42",
            "0102030405060708090a0b0c0d0e0f10",
            "aabbccddeeff00112233445566778899",
            "aabbccddeeff00112233445566778899:"
            "0102030405060708090a0b0c0d0e0f10:42", 'test.cap')
        self.assertEqual(result, 0)
        self.c.execute("SELECT identity, eap_id, hashcat FROM EAPMD5 "
                       "WHERE bssid = ? AND mac = ?", (self.bssid, self.mac))
        row = self.c.fetchone()
        self.assertEqual(row[0], "user")
        self.assertEqual(row[1], "42")
        self.assertTrue(row[2].endswith(":42"))

    def test_insertProbeFingerprint(self):
        # The fingerprint now lives on the Probe row for the probed (mac, ssid)
        result = database_utils.insertProbeFingerprint(
            self.c, self.verbose, self.mac, "TestProbe", "abc123",
            "0,1,50,3,45,221", 'test.cap')
        self.assertEqual(result, 0)
        self.c.execute("SELECT fingerprint, ie_order FROM Probe "
                       "WHERE mac = ? AND ssid = ?", (self.mac, "TestProbe"))
        row = self.c.fetchone()
        self.assertEqual(row[0], "abc123")
        self.assertEqual(row[1], "0,1,50,3,45,221")

        # A fingerprint for an SSID already present as a plain probe row
        # updates that row in place rather than creating a duplicate.
        database_utils.insertProbe(self.c, self.verbose, self.mac, "Probed", 0)
        database_utils.insertProbeFingerprint(
            self.c, self.verbose, self.mac, "Probed", "def456",
            "0,1,221", 'test.cap')
        self.c.execute("SELECT COUNT(*), MAX(fingerprint) FROM Probe "
                       "WHERE mac = ? AND ssid = ?", (self.mac, "Probed"))
        count, fingerprint = self.c.fetchone()
        self.assertEqual(count, 1)
        self.assertEqual(fingerprint, "def456")

    def test_insertConnected(self):
        # add needed data
        essid = "Test_AP"
        manuf = "Test_Manufacturer"
        channel = "6"
        freqmhz = "2437"
        carrier = "test"
        encryption = "WPA2"
        packets_total = "10"
        lat = "37.7749"
        lon = "-122.4194"
        cloaked = False
        mfpc = 'False'
        mfpr = 'False'
        # Insert new AP
        result = database_utils.insertAP(self.c, self.verbose, self.bssid,
                                         essid, manuf, channel, freqmhz,
                                         carrier, encryption, packets_total,
                                         lat, lon, cloaked, mfpc, mfpr, 0)

        self.assertEqual(result, 0)

        ssid = ""
        manuf = "Test_Manufacturer"
        packets_total = "10"
        power = "-70"
        # Insert new client
        result = database_utils.insertClients(self.c, self.verbose, self.mac,
                                              ssid, manuf, packets_total,
                                              power, "Misc", 0)

        self.assertEqual(result, 0)

        # Insert new connected device
        result = database_utils.insertConnected(self.c, self.verbose,
                                                self.bssid, self.mac)
        self.assertEqual(result, 0)

        self.c.execute("SELECT bssid FROM Connected WHERE mac=?", (self.mac,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], self.bssid)

    def test_inserFile(self):
        script_path = os.path.dirname(os.path.abspath(__file__))
        path = script_path+"/README.md"

        result = database_utils.insertFile(self.c, self.verbose, path)
        self.assertEqual(result, 0)

        self.c.execute("SELECT file FROM Files WHERE file=?", (path,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], path)

    def test_insertHandshake(self):
        script_path = os.path.dirname(os.path.abspath(__file__))
        path = script_path+"/README.md"

        result = database_utils.insertHandshake(self.c, self.verbose,
                                                self.bssid, self.mac, path)
        self.assertEqual(result, 0)

        self.c.execute("SELECT * FROM handshake WHERE bssid = ?",
                       (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][2], path)

    def test_insertIdentity(self):
        identity = "DOMAIN\\username"
        method = "EAP-PEAP"
        result = database_utils.insertIdentity(self.c, self.verbose,
                                               self.bssid, self.mac, identity,
                                               method)
        self.assertEqual(result, 0)
        self.c.execute("SELECT identity, realm FROM Identity WHERE mac=?",
                       (self.mac,))
        row = self.c.fetchone()
        self.assertEqual(row[0], identity)
        self.assertEqual(row[1], "")  # no '@' -> no realm

        # An anonymous outer identity carries the realm after '@'
        result = database_utils.insertIdentity(self.c, self.verbose,
                                               self.bssid, self.mac,
                                               "anonymous@example.com",
                                               "EAP-TTLS")
        self.assertEqual(result, 0)
        self.c.execute("SELECT realm FROM Identity WHERE mac=? AND "
                       "identity=?", (self.mac, "anonymous@example.com"))
        self.assertEqual(self.c.fetchone()[0], "example.com")

    def test_insertSeenClient(self):
        # add needed data
        ssid = ""
        manuf = "Test_Manufacturer"
        packets_total = "10"
        power = "-70"
        # Insert new client
        result = database_utils.insertClients(self.c, self.verbose, self.mac,
                                              ssid, manuf, packets_total,
                                              power, "Misc", 0)

        # Insert seenClient
        # station = "Test_Station"
        time = "2022-02-23 10:00:00"
        tool = "aircrack-ng"
        power = -50
        lat = "37.7749"
        lon = "-122.4194"
        alt = "10000"
        result = database_utils.insertSeenClient(self.c, self.verbose,
                                                 self.mac, time, tool, power,
                                                 lat, lon, alt)
        self.assertEqual(result, 0)
        self.c.execute("SELECT * FROM SeenClient WHERE mac=?", (self.mac,))
        row = self.c.fetchone()
        self.assertEqual(row[1], time)
        self.assertEqual(row[2], tool)
        self.assertEqual(row[3], power)

    def test_insertSeenAP(self):
        # add needed data
        essid = "Test_AP"
        manuf = "Test_Manufacturer"
        channel = "6"
        freqmhz = "2437"
        carrier = "test"
        encryption = "WPA2"
        packets_total = "10"
        lat = "37.7749"
        lon = "-122.4194"
        cloaked = False
        mfpc = 'False'
        mfpr = 'False'
        # Insert new AP
        result = database_utils.insertAP(self.c, self.verbose, self.bssid,
                                         essid, manuf, channel, freqmhz,
                                         carrier, encryption, packets_total,
                                         lat, lon, cloaked, mfpc, mfpr, 0)

        self.assertEqual(result, 0)

        # Insert SeenAP
        time = "2032-02-23 10:00:00"
        tool = "aircrack-ng"
        signal_rsi = "-70"
        lat = "37.7749"
        lon = "-122.4194"
        alt = "10000"
        bsstimestamp = "2032-02-23 10:00:00"
        result = database_utils.insertSeenAP(self.c, self.verbose, self.bssid,
                                             time, tool, signal_rsi, lat, lon,
                                             alt, bsstimestamp)
        self.assertEqual(result, 0)
        self.c.execute("SELECT * FROM SeenAP WHERE bssid = ?", (self.bssid,))
        row = self.c.fetchone()
        self.assertEqual(row[1], time)
        self.assertEqual(row[2], tool)

    def test_setHashcat(self):
        # add needed data
        essid = "Test_AP"
        manuf = "Test_Manufacturer"
        channel = "6"
        freqmhz = "2437"
        carrier = "test"
        encryption = "WPA2"
        packets_total = "10"
        lat = "37.7749"
        lon = "-122.4194"
        cloaked = False
        mfpc = 'False'
        mfpr = 'False'
        # Insert new AP
        result = database_utils.insertAP(self.c, self.verbose, self.bssid,
                                         essid, manuf, channel, freqmhz,
                                         carrier, encryption, packets_total,
                                         lat, lon, cloaked, mfpc, mfpr, 0)

        self.assertEqual(result, 0)

        ssid = ""
        manuf = "Test_Manufacturer"
        packets_total = "10"
        power = "-70"
        # Insert new client
        result = database_utils.insertClients(self.c, self.verbose, self.mac,
                                              ssid, manuf, packets_total,
                                              power, "Misc", 0)

        self.assertEqual(result, 0)

        # insert Handshake
        script_path = os.path.dirname(os.path.abspath(__file__))
        path = script_path+"/README.md"

        result = database_utils.insertHandshake(self.c, self.verbose,
                                                self.bssid, self.mac, path)
        self.assertEqual(result, 0)

        # Insert hashcat HASH
        script_path = os.path.dirname(os.path.abspath(__file__))
        path = script_path+"/README.md"
        test_hashcat = "aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77"
        result = database_utils.setHashcat(self.c, self.verbose, self.bssid,
                                           self.mac, path, test_hashcat)
        self.assertEqual(result, 0)
        self.c.execute("SELECT * FROM handshake WHERE bssid = ?",
                       (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(rows[0][2], path)

    def test_load_vendors(self):
        ouiAux = oui.load_vendors()
        vendor = oui.get_vendor(ouiAux, '00:00:00:00:00:01', self.verbose)
        self.assertEqual(vendor, 'XEROX CORPORATION')

    def test_get_vendor(self):
        ouiAux = {'000000': 'company1',
                  'FFFFFF': 'company2'}
        vendor = oui.get_vendor(ouiAux, '00:00:00:00:00:01', self.verbose)
        self.assertEqual(vendor, 'company1')

    def test_obfuscateDB(self):
        # add needed data
        essid = "Test_AP"
        manufAP = "Test_Manufacturer_AP"
        channel = "6"
        freqmhz = "2437"
        carrier = "test"
        encryption = "WPA2"
        packets_total = "10"
        lat = "37.7749"
        lon = "-122.4194"
        cloaked = False
        mfpc = 'False'
        mfpr = 'False'
        # Insert new AP
        result = database_utils.insertAP(self.c, self.verbose, self.bssid,
                                         essid, manufAP, channel, freqmhz,
                                         carrier, encryption, packets_total,
                                         lat, lon, cloaked, mfpc, mfpr, 0)

        self.assertEqual(result, 0)

        ssid = "null_ssid"
        manufClient = "Test_Manufacturer_Client"
        packets_total = "10"
        power = "-70"
        # Insert new client
        result = database_utils.insertClients(self.c, self.verbose, self.mac,
                                              ssid, manufClient, packets_total,
                                              power, "Misc", 0)

        self.assertEqual(result, 0)

        # insert Handshake
        script_path = os.path.dirname(os.path.abspath(__file__))
        path = script_path+"/README.md"

        result = database_utils.insertHandshake(self.c, self.verbose,
                                                self.bssid, self.mac, path)
        self.assertEqual(result, 0)

        # obfuscateDB
        result = database_utils.obfuscateDB(self.database, self.verbose)
        self.assertEqual(result, 0)

        # self.c.execute("SELECT * FROM handshake WHERE bssid = ?",
        #                (self.bssid,))
        self.c.execute("SELECT * FROM AP WHERE ssid=?", (essid,))
        rows = self.c.fetchall()
        # Same ESSID but different BSSID
        self.assertEqual(rows[0][1], essid)
        self.assertEqual(rows[0][3], manufAP)
        self.assertEqual(rows[0][4], int(channel))
        self.assertNotEqual(rows[0][0], self.bssid)

        self.c.execute("SELECT * FROM CLIENT WHERE ssid=?", (ssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], ssid)
        self.assertEqual(rows[0][2], manufClient)
        self.assertEqual(rows[0][3], packets_total)


class TestFunctionsRealData(unittest.TestCase):
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

        # Load real data
        nest_asyncio.apply()

        tshark = True
        hcxpcapngtool = True
        ouiMap = oui.load_vendors()
        captures = [
            "./test_data/test-01.cap",
            "./test_data/test-01.csv",
            "./test_data/test-01.kismet.csv",
            "./test_data/test-01.kismet.netxml",
            "./test_data/test-01.log.csv"
        ]
        fake_lat = ''
        fake_lon = ''
        force = False
        for capture in captures:
            wifi_db.process_capture(ouiMap, capture, self.database,
                                    self.verbose, fake_lat, fake_lon,
                                    hcxpcapngtool, tshark, force)

    def tearDown(self):
        self.database.close()
        if self.test_database_conn:
            self.test_database_conn.close()
        if os.path.exists(self.test_database_name):
            os.remove(self.test_database_name)

    def testRealAP(self):

        # Check AP
        query = "SELECT ssid FROM AP WHERE bssid = ?;"
        self.c.execute(query, ('B2:9B:00:EE:FB:EB',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'MiFibra-5-D6G3')

        query = "SELECT firstTimeSeen FROM AP WHERE bssid = ?;"
        self.c.execute(query, ('F0:9F:C2:11:0A:24',))
        row = self.c.fetchone()
        self.assertEqual(row[0], ' 2023-10-20 14:33:06')

    def testRealClient(self):
        # Client
        query = "SELECT manuf FROM Client WHERE mac = ? "
        self.c.execute(query, ('64:32:A8:AD:AB:53',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'Intel Corporate')

        query = "SELECT firstTimeSeen FROM Client WHERE mac = ?"
        self.c.execute(query, ('64:32:A8:AD:AB:53',))
        row = self.c.fetchone()
        self.assertEqual(row[0], ' 2023-10-20 14:33:06')

    def testRealConnected(self):
        # Connected
        query = "SELECT bssid FROM Connected WHERE mac = ?"
        self.c.execute(query, ('28:6C:07:6F:F9:43',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'F0:9F:C2:71:22:12')

        query = "SELECT bssid FROM Connected WHERE mac = ?"
        self.c.execute(query, ('64:32:A8:BA:6C:41',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'F0:9F:C2:71:22:1A')

    def testRealFiles(self):
        # Files
        query = "SELECT hashSHA FROM Files WHERE file = ?"
        self.c.execute(query, ('./test_data/test-01.cap',))
        row = self.c.fetchone()
        self.assertEqual(row[0],
                         '1c951d7a9387ad7a17a85f0bfbec4ee7' +
                         'bddf30244ae39aabd78654a104e4409c')

        query = "SELECT hashSHA FROM Files WHERE file = ?"
        self.c.execute(query, ('./test_data/test-01.kismet.netxml',))
        row = self.c.fetchone()
        self.assertEqual(row[0],
                         '7aaf4ba048b0fca4d1c481905f076be0e' +
                         'fd7913bef2d87bd1e0ef1537ff1bc0b')

    def testRealHandshake(self):
        # Handshake
        query = "SELECT hashSHA FROM Handshake WHERE bssid = ?"
        self.c.execute(query, ('F0:9F:C2:7A:33:28',))
        row = self.c.fetchone()
        self.assertEqual(row[0],
                         '1c951d7a9387ad7a17a85f0bfbe' +
                         'c4ee7bddf30244ae39aabd78654a104e4409c')
        query = "SELECT hashcat FROM Handshake WHERE mac = ?"
        self.c.execute(query, ('28:6C:07:6F:F9:44',))
        row = self.c.fetchone()
        # List of expected values, to avoid errors in some systems, idk why
        expected_values = ['WPA*02*45a64e58157df9397ffaca67b16fc898*' +
                           'f09fc2712212*286c076ff944*' +
                           '776966692d6d6f62696c65*' +
                           'babf7d3ce7f859d4b2a86b7fa704cea0177c9a42' +
                           '202ebc68a1ab3c779a97c37a*0103007502010a0' +
                           '00000000000000000011e04b195770b11f0378fc' +
                           '9977f3a4342475f0073d746781530f3a71dbb5e4' +
                           'b840000000000000000000000000000000000000' +
                           '0000000000000000000000000000000000000000' +
                           '0000000000000000000001630140100000fac020' +
                           '100000fac040100000fac020000*00',
                           'WPA*02*45a64e58157df9397ffaca67b16fc898*' +
                           'f09fc2712212*286c076ff944*' +
                           '776966692d6d6f62696c65*' +
                           'babf7d3ce7f859d4b2a86b7fa704cea0177c9a42' +
                           '202ebc68a1ab3c779a97c37a*0103007502010a0' +
                           '00000000000000000011e04b195770b11f0378fc' +
                           '9977f3a4342475f0073d746781530f3a71dbb5e4' +
                           'b840000000000000000000000000000000000000' +
                           '0000000000000000000000000000000000000000' +
                           '0000000000000000000001630140100000fac020' +
                           '100000fac040100000fac020000*80']
        self.assertIn(row[0], expected_values)

    def testRealIdentity(self):
        # Identity
        query = "SELECT identity FROM Identity WHERE mac = ?"
        self.c.execute(query, ('64:32:A8:AC:53:50',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'CONTOSOREG\\anonymous')

        query = "SELECT identity FROM Identity WHERE mac = ?"
        self.c.execute(query, ('64:32:A8:BA:6C:41',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'CONTOSO\\anonymous')

    def testRealProbe(self):
        # Probe. Filter by the expected SSID: the merged Probe table also holds
        # broadcast probe-request rows (ssid '') from the fingerprint parser,
        # so an unfiltered fetchone() is no longer order-deterministic.
        query = "SELECT ssid FROM Probe WHERE mac = ? AND ssid = ?"
        self.c.execute(query, ('64:32:A8:AC:53:50', 'wifi-regional'))
        row = self.c.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], 'wifi-regional')

        query = "SELECT ssid FROM Probe WHERE mac = ? AND ssid LIKE ?"
        self.c.execute(query, ('B4:99:BA:6F:F9:45', 'wifi-%',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'wifi-offices')

    def testRealSeenAP(self):
        # SeenAP
        query = "SELECT signal_rssi FROM seenAP WHERE time = ? AND bssid = ?"
        self.c.execute(query, ('2023-10-20 14:34:43', 'F0:9F:C2:AA:19:29',))
        row = self.c.fetchone()
        self.assertEqual(row[0], -29)

        query = "SELECT tool FROM seenAP WHERE time = ? AND bssid = ?"
        self.c.execute(query, ('2023-10-20 14:35:01', 'F0:9F:C2:71:22:10',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'aircrack-ng')

    def testRealSeenClient(self):
        # SeenClient
        query = "SELECT tool FROM seenClient WHERE time = ? AND mac = ?"
        self.c.execute(query, ('2023-10-20 14:33:06', '4E:E6:C2:58:FC:24',))
        row = self.c.fetchone()
        self.assertEqual(row[0], 'aircrack-ng')

        query = "SELECT signal_rssi FROM seenClient WHERE time = ? AND mac = ?"
        self.c.execute(query, ('2023-10-20 14:35:02', 'B4:99:BA:6F:F9:45',))
        row = self.c.fetchone()
        self.assertEqual(row[0], -49)

    def testRealWPS(self):
        # WPS attributes are merged 1:1 onto the AP row. Assert the merged WPS
        # columns exist and that any WPS data parsed from the real capture is
        # well-formed. The capture is not guaranteed to contain WPS-enabled
        # APs (the .cap parser also needs tshark), so the presence of WPS rows
        # is not required; only their correctness is checked.
        self.c.execute("PRAGMA table_info(AP)")
        columns = {row[1] for row in self.c.fetchall()}
        wps_columns = {
            'wps_version', 'wps_device_name', 'wps_model_name',
            'wps_model_number', 'wps_config_methods',
            'wps_config_methods_keypad',
        }
        self.assertTrue(wps_columns.issubset(columns))

        query = ("SELECT wps_version FROM AP "
                 "WHERE wps_version IS NOT NULL AND wps_version != ''")
        self.c.execute(query)
        for (wps_version,) in self.c.fetchall():
            self.assertIn(wps_version, ('1.0', '2.0'))


if __name__ == '__main__':
    unittest.main()
