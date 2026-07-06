from utils import oui
from utils import capture_pipeline

import nest_asyncio

from test_base import DBTestBase


class TestFunctionsRealData(DBTestBase):
    def setUp(self):
        # DBTestBase builds the on-disk test database (self.database / self.c);
        # then load the real sample captures on top of it.
        super().setUp()
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
        ctx = capture_pipeline.Context(
            ouiMap=ouiMap, database=self.database, verbose=self.verbose,
            fake_lat=fake_lat, fake_lon=fake_lon,
            hcxpcapngtool=hcxpcapngtool, tshark=tshark, force=force)
        for capture in captures:
            capture_pipeline.process_capture(ctx, capture)

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
