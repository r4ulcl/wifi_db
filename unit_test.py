import os
# import sqlite3
import unittest
# from database_utils import *
from utils import database_utils
from utils import oui
from utils import update
from utils import wifi_db_aircrack
import wifi_db
from unittest.mock import patch, MagicMock
import json
import nest_asyncio
import platform
import subprocess
import pytest

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
        self.test_database_conn = database_utils.connectDatabase(self.test_database_name, False)
        database_utils.createDatabase(self.test_database_conn, self.verbose)
        cursor = self.test_database_conn.cursor()
        # Verify that the tables were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        expected_tables = [('AP',), ('Client',), ('SeenClient',), ('Connected',), ('WPS',), ('SeenAp',), ('Probe',), ('Handshake',), ('Identity',), ('Files',)]  # Replace with actual expected tables
        self.assertEqual(tables, expected_tables)

    def test_createViews(self):
        self.test_database_conn = database_utils.connectDatabase(self.test_database_name, False)
        database_utils.createDatabase(self.test_database_conn, False)  # Create tables first
        database_utils.createViews(self.test_database_conn, self.verbose)
        cursor = self.test_database_conn.cursor()
        # Verify that the views were created
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view';")
        views = cursor.fetchall()
        expected_views = [('ProbeClients',), ('ConnectedAP',), ('ProbeClientsConnected',), ('HandshakeAP',), ('HandshakeAPUnique',), ('IdentityAP',), ('SummaryAP',)]  # Replace with actual expected views
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
        # TODO  Insert existing AP with new values
        # manuf = "Updated_Manufacturer"
        # result = insertAP(self.c, False, bssid, essid, manuf, channel,
        #                   freqmhz, carrier,
        # encryption, packets_total, lat, lon, cloaked)
        # self.assertEqual(result, 0)
        # self.c.execute("SELECT * FROM AP WHERE bssid=?", (bssid,))
        # rows = self.c.fetchall()
        # self.assertEqual(len(rows), 1)
        # self.assertEqual(rows[0][3], "Updated_Manufacturer")

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
        # TODO Insert existing client with new values
        # manuf = "Updated_Manufacturer"
        # result = insertClients(self.c, False, mac, ssid, manuf,
        #                        packets_total, power, "Misc")
        # self.assertEqual(result, 0)
        # self.c.execute("SELECT * FROM CLIENT WHERE mac=?", (mac,))
        # rows = self.c.fetchall()
        # self.assertEqual(len(rows), 1)
        # self.assertEqual(rows[0][2], "Updated_Manufacturer")

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

        # TODO Insert existing WPS with new values
        # wps_device_name = "Updated_Device"
        # result = insertWPS(self.c, self.verbose, bssid, wlan_ssid,
        # wps_version,
        # wps_device_name, wps_model_name, wps_model_number,
        # wps_config_methods, wps_config_methods_keypad)
        # self.assertEqual(result, 0)
        # self.c.execute("SELECT * FROM WPS WHERE wlan_ssid=?", (wlan_ssid,))
        # rows = self.c.fetchall()
        # self.assertEqual(len(rows), 1)
        # self.assertEqual(rows[0][3], "Updated_Device")

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

    def test_inserFile(self):
        script_path = os.path.dirname(os.path.abspath(__file__))
        path = script_path+"/README.md"

        result = database_utils.insertFile(self.c, self.verbose, path)
        self.assertEqual(result, 0)

    def test_insertHandshake(self):
        script_path = os.path.dirname(os.path.abspath(__file__))
        path = script_path+"/README.md"

        result = database_utils.insertHandshake(self.c, self.verbose,
                                                self.bssid, self.mac, path)
        self.assertEqual(result, 0)

        self.c.execute("SELECT * FROM handshake WHERE bssid=?", (self.bssid,))
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
        self.c.execute("SELECT identity FROM Identity WHERE mac=?",
                       (self.mac,))
        row = self.c.fetchone()
        self.assertEqual(row[0], identity)

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
        self.c.execute("SELECT * FROM SeenAP WHERE bssid=?", (self.bssid,))
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
        self.c.execute("SELECT * FROM handshake WHERE bssid=?", (self.bssid,))
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

        # self.c.execute("SELECT * FROM handshake WHERE bssid=?",
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
        captures = ["./test_data/test-01.cap", "./test_data/test-01.csv", "./test_data/test-01.kismet.csv", "./test_data/test-01.kismet.netxml", "./test_data/test-01.log.csv"]
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
        self.c.execute("SELECT ssid FROM AP where bssid = 'B2:9B:00:EE:FB:EB';")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'MiFibra-5-D6G3')

        self.c.execute("SELECT firstTimeSeen FROM AP where bssid = 'F0:9F:C2:11:0A:24';")
        row = self.c.fetchone()
        self.assertEqual(row[0], ' 2023-10-20 14:33:06')

    def testRealClient(self):
        # Client
        self.c.execute("SELECT manuf FROM Client WHERE mac = '64:32:A8:AD:AB:53' ")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'Intel Corporate')

        self.c.execute("SELECT firstTimeSeen FROM Client WHERE mac = '64:32:A8:AD:AB:53'")
        row = self.c.fetchone()
        self.assertEqual(row[0], ' 2023-10-20 14:33:06')

    def testRealConnected(self):
        # Connected
        self.c.execute("SELECT bssid FROM Connected WHERE mac = '28:6C:07:6F:F9:43'")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'F0:9F:C2:71:22:12')

        self.c.execute("SELECT bssid FROM Connected WHERE mac = '64:32:A8:BA:6C:41'")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'F0:9F:C2:71:22:1A')

    def testRealFiles(self):
        # Files
        self.c.execute("SELECT hashSHA FROM Files WHERE file = './test_data/test-01.cap'")
        row = self.c.fetchone()
        self.assertEqual(row[0], '1c951d7a9387ad7a17a85f0bfbec4ee7bddf30244ae39aabd78654a104e4409c')

        self.c.execute("SELECT hashSHA FROM Files WHERE file = './test_data/test-01.kismet.netxml'")
        row = self.c.fetchone()
        self.assertEqual(row[0], '7aaf4ba048b0fca4d1c481905f076be0efd7913bef2d87bd1e0ef1537ff1bc0b')

    def testRealHandshake(self):
        # Handshake
        self.c.execute("SELECT hashSHA FROM Handshake WHERE bssid = 'F0:9F:C2:7A:33:28'")
        row = self.c.fetchone()
        self.assertEqual(row[0], '1c951d7a9387ad7a17a85f0bfbec4ee7bddf30244ae39aabd78654a104e4409c')

        self.c.execute("SELECT hashcat FROM Handshake WHERE mac = '28:6C:07:6F:F9:44'")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'WPA*02*45a64e58157df9397ffaca67b16fc898*f09fc2712212*286c076ff944*776966692d6d6f62696c65*babf7d3ce7f859d4b2a86b7fa704cea0177c9a42202ebc68a1ab3c779a97c37a*0103007502010a000000000000000000011e04b195770b11f0378fc9977f3a4342475f0073d746781530f3a71dbb5e4b84000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000*00')

    def testRealIdentity(self):
        # Identity
        self.c.execute("SELECT identity FROM Identity WHERE mac = '64:32:A8:AC:53:50'")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'CONTOSOREG\\anonymous')

        self.c.execute("SELECT identity FROM Identity WHERE mac = '64:32:A8:BA:6C:41'")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'CONTOSO\\anonymous')

    def testRealProbe(self):
        # Probe
        self.c.execute("SELECT ssid FROM Probe WHERE mac = '64:32:A8:AC:53:50'")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'wifi-regional')

        self.c.execute("SELECT ssid FROM Probe WHERE mac = 'B4:99:BA:6F:F9:45' AND ssid LIKE 'wifi-%'")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'wifi-offices')

    def testRealSeenAP(self):
        # SeenAP
        self.c.execute("SELECT signal_rssi FROM seenAP WHERE time = '2023-10-20 14:34:43' AND bssid = 'F0:9F:C2:AA:19:29'")
        row = self.c.fetchone()
        self.assertEqual(row[0], -29)

        self.c.execute("SELECT tool FROM seenAP WHERE time = '2023-10-20 14:35:01' AND bssid = 'F0:9F:C2:71:22:10'")
        row = self.c.fetchone()
        self.assertEqual(row[0], 'aircrack-ng')

    def testRealSeenClient(self):
        # SeenClient
        self.c.execute("SELECT tool FROM seenClient WHERE time = '2023-10-20 14:33:06' AND mac = '4E:E6:C2:58:FC:24'")
        #row = self.c.fetchone()
        #self.assertEqual(row[0], 'aircrack-ng')

        self.c.execute("SELECT signal_rssi FROM seenClient WHERE time = '2023-10-20 14:35:02' AND mac = 'B4:99:BA:6F:F9:45'")
        row = self.c.fetchone()
        self.assertEqual(row[0], -49)

    #def testReal(self):
        # WPS TODO
        #self.c.execute("SELECT  FROM  WHERE  = ''")
        #row = self.c.fetchone()
        #self.assertEqual(row[0], 0)

        #self.c.execute("SELECT  FROM  WHERE  = ''")
        #row = self.c.fetchone()
        #self.assertEqual(row[0], 0)

        # self.c.execute("SELECT * FROM files")
        # row = self.c.fetchone()
        # self.assertEqual(row[0], 0)

    '''

        '''


if __name__ == '__main__':
    unittest.main()
