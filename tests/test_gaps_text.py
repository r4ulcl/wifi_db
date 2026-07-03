'''Coverage for the text/XML parser edge branches: missing-file returns,
outer exception handlers, per-row parse errors, the netxml truncation repair,
GPS coordinates and unknown record types, plus the two decode() bitmask
branches the sample data never hits.'''
import os
import tempfile
import unittest

from utils import log_parsers, text_parsers, netxml_parser, decode

from test_base import mem_db


class CursorRaisingDB:
    '''A database whose cursor() raises, to trip the parsers' outer
    try/except (which starts with `cursor = database.cursor()`).'''
    def cursor(self):
        raise RuntimeError("db unavailable")

    def commit(self):
        pass


def _tmpfile(content, suffix):
    handle = tempfile.NamedTemporaryFile('w', suffix=suffix, delete=False,
                                         encoding='utf-8')
    handle.write(content)
    handle.close()
    return handle.name


# --------------------------------------------------------------------------
# decode
# --------------------------------------------------------------------------
class TestDecode(unittest.TestCase):
    def test_config_methods_pushbutton_subsumed(self):
        # 0x0080 (PushButton) + 0x0200 (Virtual Push Button): the base
        # PushButton name is suppressed in favour of the subtype.
        result = decode.decode_wps_config_methods(0x0280)
        self.assertIn('Virtual Push Button', result)
        self.assertNotIn('PushButton', result)

    def test_rsn_capabilities_gtksa_replay_counters(self):
        # bits 4-5 = 01 -> GTKSA replay counters = 2 (> 1), so it is listed.
        result = decode.decode_rsn_capabilities(0x0010)
        self.assertIn('GTKSA Replay Counters: 2', result)


# --------------------------------------------------------------------------
# log_parsers
# --------------------------------------------------------------------------
class TestLogParsers(unittest.TestCase):
    def test_kismet_insert_ap_row_error(self):
        # row[19] is not a parseable date: the exception is logged (verbose)
        # and the row skipped (returns 0). Both verbosities exercise the guard.
        row = ['x'] * 40
        row[19] = 'not-a-date'
        for verbose in (True, False):
            self.assertEqual(
                log_parsers._kismet_insert_ap(None, verbose, {}, row), 0)

    def test_parse_kismet_csv_missing_file(self):
        log_parsers.parse_kismet_csv({}, "/no/such/file.kismet.csv", None,
                                     False)

    def test_parse_kismet_csv_outer_error(self):
        path = _tmpfile("Network;a\n", ".kismet.csv")
        try:
            log_parsers.parse_kismet_csv({}, path, CursorRaisingDB(), False)
        finally:
            os.remove(path)

    def test_parse_log_csv_missing_file(self):
        log_parsers.parse_log_csv({}, "/no/such/file.log.csv", None, False,
                                  "", "")

    def test_parse_log_csv_unknown_kind(self):
        # A row whose kind column is neither Client nor AP is skipped.
        content = ("LocalTime,a,b,c,d,e,f,g,h,i,j\n"
                   "2023-10-20 14:33:06,,,,,,,,,,Other\n")
        path = _tmpfile(content, ".log.csv")
        database = mem_db()
        try:
            log_parsers.parse_log_csv({}, path, database, False, "", "")
        finally:
            database.close()
            os.remove(path)

    def test_parse_log_csv_outer_error(self):
        path = _tmpfile("LocalTime\n", ".log.csv")
        try:
            log_parsers.parse_log_csv({}, path, CursorRaisingDB(), False,
                                      "", "")
        finally:
            os.remove(path)


# --------------------------------------------------------------------------
# text_parsers
# --------------------------------------------------------------------------
class TestTextParsers(unittest.TestCase):
    def test_parse_csv_missing_file(self):
        text_parsers.parse_csv({}, "/no/such/file.csv", None, False)

    def test_parse_csv_outer_error(self):
        path = _tmpfile("BSSID,x\n", ".csv")
        try:
            text_parsers.parse_csv({}, path, CursorRaisingDB(), False)
        finally:
            os.remove(path)


# --------------------------------------------------------------------------
# netxml_parser
# --------------------------------------------------------------------------
_FULL_NETXML = '''<detection-run>
  <wireless-network type="infrastructure">
    <SSID first-time="Fri Oct 20 14:33:06 2023">
      <essid cloaked="false">TestNet</essid>
      <encryption>WPA2</encryption>
    </SSID>
    <BSSID>F0:9F:C2:00:00:01</BSSID>
    <manuf>TestManuf</manuf>
    <channel>6</channel>
    <freqmhz>2437 1803</freqmhz>
    <maxseenrate>54</maxseenrate>
    <carrier>IEEE 802.11bgn</carrier>
    <encoding>CCK</encoding>
    <packets><total>100</total></packets>
    <datasize>0</datasize>
    <gps-info><max-lat>40.1</max-lat><max-lon>-3.7</max-lon></gps-info>
    <wireless-client number="1" first-time="Fri Oct 20 14:33:09 2023">
      <client-mac>64:32:A8:00:00:01</client-mac>
      <packets><total>10</total></packets>
    </wireless-client>
  </wireless-network>
  <wireless-network type="probe">
    <BSSID>64:32:A8:00:00:02</BSSID>
    <manuf>TestManuf</manuf>
    <channel>44</channel>
    <packets><total>60</total></packets>
    <wireless-client number="1" first-time="Fri Oct 20 14:33:06 2023">
      <client-mac>64:32:A8:00:00:02</client-mac>
      <SSID first-time="Fri Oct 20 14:33:06 2023">
        <ssid>probed-net</ssid>
      </SSID>
    </wireless-client>
  </wireless-network>
  <wireless-network type="other">
    <BSSID>00:00:00:00:00:01</BSSID>
  </wireless-network>
</detection-run>
'''

# No closing </detection-run>: exercises the truncation-repair path.
_TRUNCATED_NETXML = ('<detection-run>\n'
                     '  <wireless-network type="other">\n'
                     '    <BSSID>00:00:00:00:00:02</BSSID>\n'
                     '  </wireless-network>\n'
                     '  <wireless-network type="infrastructure" '
                     'first-time="broken')


class TestNetxmlParser(unittest.TestCase):
    def test_full_netxml_probe_infra_and_unknown_verbose(self):
        path = _tmpfile(_FULL_NETXML, ".kismet.netxml")
        database = mem_db()
        try:
            netxml_parser.parse_netxml({}, path, database, True)
            row = database.cursor().execute(
                "SELECT lat_t FROM AP WHERE bssid = ?",
                ('F0:9F:C2:00:00:01',)).fetchone()
            self.assertEqual(row, (40.1,))
        finally:
            database.close()
            os.remove(path)

    def test_truncated_file_is_repaired(self):
        # The missing </detection-run> is repaired; the first complete network
        # is still parsed without raising. Both verbosities hit the repair.
        for verbose in (True, False):
            path = _tmpfile(_TRUNCATED_NETXML, ".kismet.netxml")
            database = mem_db()
            try:
                netxml_parser.parse_netxml({}, path, database, verbose)
            finally:
                database.close()
                os.remove(path)

    def test_parse_netxml_missing_file(self):
        # A working database but a non-existent file reaches the "missing"
        # branch (the cursor is opened before the file is checked).
        database = mem_db()
        try:
            netxml_parser.parse_netxml({}, "/no/such/file.kismet.netxml",
                                       database, False)
        finally:
            database.close()

    def test_parse_netxml_outer_error(self):
        path = _tmpfile(_FULL_NETXML, ".kismet.netxml")
        try:
            netxml_parser.parse_netxml({}, path, CursorRaisingDB(), False)
        finally:
            os.remove(path)


if __name__ == '__main__':
    unittest.main()
