import os
import unittest

from test_base import DBTestBase
from utils import database_utils
from utils import oui
from utils.decode import (decode_wps_config_methods,
                          decode_rsn_capabilities)


class TestDecode(unittest.TestCase):
    '''Bitmask -> human-readable decoders for the AP *_text columns.'''

    def test_wps_config_methods(self):
        # Captured examples: the raw config-methods hex bitmask and the flag
        # list it decodes to. Display-PIN/Push-Button subtypes (0x2000/0x0200)
        # replace their parent Display/PushButton bits.
        cases = {
            '0x0000': '',
            '0x0004': 'Label',
            '0x0086': 'Ethernet, Label, PushButton',
            '0x008c': 'Label, Display, PushButton',
            '0x2008': 'Virtual Display PIN',
            '0x200c': 'Label, Virtual Display PIN',
            '0x210c': 'Label, Keypad, Virtual Display PIN',
            '0x218c': 'Label, PushButton, Keypad, Virtual Display PIN',
        }
        for raw, expected in cases.items():
            self.assertEqual(decode_wps_config_methods(raw), expected, raw)

    def test_wps_config_methods_edge(self):
        # Empty/None/garbage decode to '' rather than raising.
        self.assertEqual(decode_wps_config_methods(''), '')
        self.assertEqual(decode_wps_config_methods(None), '')
        self.assertEqual(decode_wps_config_methods('nothex'), '')
        # A bare integer (already parsed) is accepted too.
        self.assertEqual(decode_wps_config_methods(0x0004), 'Label')

    def test_rsn_capabilities(self):
        self.assertEqual(decode_rsn_capabilities('0x0000'), '')
        self.assertEqual(decode_rsn_capabilities('0x0080'), 'MFPC')
        self.assertEqual(decode_rsn_capabilities('0x00c0'), 'MFPR, MFPC')
        self.assertEqual(decode_rsn_capabilities('0x0001'), 'Pre-Auth')
        # Replay-counter subfields (bits 2-3 / 4-5) decode to their counts.
        self.assertEqual(decode_rsn_capabilities('0x000c'),
                         'PTKSA Replay Counters: 16')
        self.assertEqual(decode_rsn_capabilities(''), '')
        self.assertEqual(decode_rsn_capabilities(None), '')


class TestFunctions(DBTestBase):
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
        ap = self.insert_test_ap()

        self.c.execute("SELECT ssid FROM AP WHERE bssid = ?", (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], ap['essid'])

    def test_insertClients(self):
        client = self.insert_test_client(ssid="Test_AP")

        self.c.execute("SELECT manuf, randomized FROM Client WHERE mac=?",
                       (self.mac,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], client['manuf'])
        # 55:.. first octet 0x55, locally-administered bit clear -> not random
        self.assertEqual(rows[0][1], 'False')

    def test_insertWPS(self):
        # Define WPS parameters
        wlan_ssid = "Test_SSID"
        wps_version = "1.0"
        wps_device_name = "Test_Device"
        wps_model_name = "Test_Model"
        wps_model_number = "12345"
        wps_config_methods = "0x008c"
        wps_config_methods_keypad = True

        # Insert new WPS
        result = database_utils.insertWPS(
            self.c, self.verbose, database_utils.WPSRow(
                bssid=self.bssid, wlan_ssid=wlan_ssid, wps_version=wps_version,
                wps_device_name=wps_device_name, wps_model_name=wps_model_name,
                wps_model_number=wps_model_number,
                wps_config_methods=wps_config_methods,
                wps_config_methods_keypad=wps_config_methods_keypad))
        self.assertEqual(result, 0)

        # WPS columns now live on the AP row (1:1 merge); the raw config-methods
        # bitmask is decoded into the sibling wps_config_methods_text column.
        self.c.execute("SELECT wlan_ssid, wps_config_methods, "
                       "wps_config_methods_text FROM AP WHERE bssid = ?",
                       (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], wlan_ssid)
        self.assertEqual(rows[0][1], "0x008c")
        self.assertEqual(rows[0][2], "Label, Display, PushButton")

    def test_isRandomizedMAC(self):
        # bit 1 of the first octet set -> locally administered (randomized)
        self.assertEqual(database_utils.isRandomizedMAC("DA:BB:CC:DD:EE:FF"),
                         'True')
        # globally administered (OUI) MAC -> not randomized
        self.assertEqual(database_utils.isRandomizedMAC("00:11:22:33:44:55"),
                         'False')

    def test_insertClients_randomized_flag(self):
        # 1.6: insertClients derives and stores the randomized flag. A
        # locally-administered MAC (first octet 0xDA, bit 1 set) -> 'True'.
        rand_mac = "DA:BB:CC:DD:EE:FF"
        result = database_utils.insertClients(
            self.c, self.verbose, database_utils.ClientRow(
                mac=rand_mac, ssid="", manuf="m", client_type="",
                packets_total="0", device="", firstTimeSeen=0))
        self.assertEqual(result, 0)
        self.c.execute("SELECT randomized FROM Client WHERE mac=?",
                       (rand_mac.upper(),))
        self.assertEqual(self.c.fetchone()[0], 'True')

    def test_firstTimeSeen_merge(self):
        # 1.6 fix: a real firstTimeSeen must replace the '0' placeholder left by
        # a foreign-key constraint insert, the earliest timestamp must win, and
        # a later timestamp (or a 0 placeholder) must never overwrite it.
        database_utils.insertAPConstraint(self.c, self.verbose, self.bssid)

        def stored_fts():
            self.c.execute("SELECT firstTimeSeen FROM AP WHERE bssid=?",
                           (self.bssid,))
            return self.c.fetchone()[0]

        # Real timestamp replaces the 0 placeholder.
        self.insert_test_ap(firstTimeSeen="2024-06-01 00:00:00")
        self.assertEqual(stored_fts(), "2024-06-01 00:00:00")
        # A later timestamp does not overwrite the earlier one.
        self.insert_test_ap(firstTimeSeen="2025-01-01 00:00:00")
        self.assertEqual(stored_fts(), "2024-06-01 00:00:00")
        # An earlier timestamp wins.
        self.insert_test_ap(firstTimeSeen="2020-01-01 00:00:00")
        self.assertEqual(stored_fts(), "2020-01-01 00:00:00")
        # A 0 placeholder never clobbers a real timestamp.
        self.insert_test_ap(firstTimeSeen=0)
        self.assertEqual(stored_fts(), "2020-01-01 00:00:00")

    def test_insertEAPMD5(self):
        result = database_utils.insertEAPMD5(
            self.c, self.verbose, database_utils.EAPMD5Row(
                bssid=self.bssid, mac=self.mac, identity="user", eap_id="42",
                challenge="0102030405060708090a0b0c0d0e0f10",
                response="aabbccddeeff00112233445566778899",
                hashcat="aabbccddeeff00112233445566778899:"
                "0102030405060708090a0b0c0d0e0f10:42", file='test.cap'))
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
        self.insert_test_ap()
        self.insert_test_client()

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
        path = self.insert_test_handshake()

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
        self.insert_test_client()

        # Insert seenClient
        # station = "Test_Station"
        time = "2022-02-23 10:00:00"
        tool = "aircrack-ng"
        power = -50
        lat = "37.7749"
        lon = "-122.4194"
        alt = "10000"
        result = database_utils.insertSeenClient(
            self.c, self.verbose, database_utils.SeenClientRow(
                mac=self.mac, time=time, tool=tool, signal_rssi=power,
                lat=lat, lon=lon, alt=alt))
        self.assertEqual(result, 0)
        self.c.execute("SELECT * FROM SeenClient WHERE mac=?", (self.mac,))
        row = self.c.fetchone()
        self.assertEqual(row[1], time)
        self.assertEqual(row[2], tool)
        self.assertEqual(row[3], power)

    def test_insertSeenAP(self):
        # add needed data
        self.insert_test_ap()

        # Insert SeenAP
        time = "2032-02-23 10:00:00"
        tool = "aircrack-ng"
        signal_rsi = "-70"
        lat = "37.7749"
        lon = "-122.4194"
        alt = "10000"
        bsstimestamp = "2032-02-23 10:00:00"
        result = database_utils.insertSeenAP(
            self.c, self.verbose, database_utils.SeenAPRow(
                bssid=self.bssid, time=time, tool=tool, signal_rsi=signal_rsi,
                lat=lat, lon=lon, alt=alt, bsstimestamp=bsstimestamp))
        self.assertEqual(result, 0)
        self.c.execute("SELECT * FROM SeenAP WHERE bssid = ?", (self.bssid,))
        row = self.c.fetchone()
        self.assertEqual(row[1], time)
        self.assertEqual(row[2], tool)

    def test_setHashcat(self):
        # add needed data
        self.insert_test_ap()
        self.insert_test_client()
        path = self.insert_test_handshake()

        # Insert hashcat HASH
        test_hashcat = "aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77"
        result = database_utils.setHashcat(self.c, self.verbose, self.bssid,
                                           self.mac, path, test_hashcat)
        self.assertEqual(result, 0)
        self.c.execute("SELECT file, hashcat FROM handshake WHERE bssid = ?",
                       (self.bssid,))
        rows = self.c.fetchall()
        self.assertEqual(rows[0][0], path)
        # The hashcat hash must actually be stored, not left empty.
        self.assertEqual(rows[0][1], test_hashcat)

    def test_setHashcat_without_prior_handshake(self):
        # Regression: hcxpcapngtool --all finds handshakes/PMKIDs that the
        # tshark parser skipped, so setHashcat is called for an AP/Client that
        # has no pre-existing Handshake/AP/Client row. It must create the
        # referenced rows itself, otherwise the INSERT fails with a FOREIGN
        # KEY constraint and the hashcat hash is silently dropped (empty).
        script_path = os.path.dirname(os.path.abspath(__file__))
        path = script_path + "/README.md"
        test_hashcat = ("WPA*02*727f2f35c4db2779fff8b30f4d349678*"
                        "f09fc2712212*286c076ff944*776966692d6d6f62696c65")

        result = database_utils.setHashcat(self.c, self.verbose, self.bssid,
                                           self.mac, path, test_hashcat)
        self.assertEqual(result, 0)
        self.c.execute("SELECT hashcat FROM handshake WHERE bssid = ? "
                       "AND mac = ?", (self.bssid, self.mac))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], test_hashcat)

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
        ap = self.insert_test_ap(manuf="Test_Manufacturer_AP")
        client = self.insert_test_client(ssid="null_ssid",
                                         manuf="Test_Manufacturer_Client")
        self.insert_test_handshake()

        # obfuscateDB
        result = database_utils.obfuscateDB(self.database, self.verbose)
        self.assertEqual(result, 0)

        # self.c.execute("SELECT * FROM handshake WHERE bssid = ?",
        #                (self.bssid,))
        self.c.execute("SELECT * FROM AP WHERE ssid=?", (ap['essid'],))
        rows = self.c.fetchall()
        # Same ESSID but different BSSID
        self.assertEqual(rows[0][1], ap['essid'])
        self.assertEqual(rows[0][3], ap['manuf'])
        self.assertEqual(rows[0][4], int(ap['channel']))
        self.assertNotEqual(rows[0][0], self.bssid)

        self.c.execute("SELECT * FROM CLIENT WHERE ssid=?", (client['ssid'],))
        rows = self.c.fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], client['ssid'])
        self.assertEqual(rows[0][2], client['manuf'])
        self.assertEqual(rows[0][3], client['client_type'])


if __name__ == '__main__':
    unittest.main()
