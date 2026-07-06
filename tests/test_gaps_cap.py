'''Coverage for the .cap parser branches that the real test-01.cap capture
never exercises: verbose logging, the WPS / MFP / capability / hidden-SSID
frame types absent from the sample capture, EAP error handling and the
hcxpcapngtool 22000-hash extraction. Every parser is driven through
run_cap_parse with synthetic packets (see tests/fake_packets.py), so no tshark
or real capture is needed.'''
import os
import tempfile
import types
import unittest
from unittest import mock

from utils import cap_common, cap_runner, cap_parsers
from utils import beacon_parsers, security_parsers, eap_parsers

from fake_packets import Field, FakeLayer, FakePkt, capture_patch
from test_base import MemDBTempFile, colon_hex


class CapGapBase(MemDBTempFile):
    # Some inserts (handshake, hcxpcapngtool) hash the capture path, so
    # MemDBTempFile writes a real .cap file on disk at self.path.
    temp_suffix = '.cap'


# --------------------------------------------------------------------------
# cap_common: the defensive except-branches and the tshark unraisable hook.
# --------------------------------------------------------------------------
class TestCapCommonEdges(unittest.TestCase):
    def test_quiet_unraisablehook_swallows_tshark_crash(self):
        crash = cap_common.pyshark.capture.capture.TSharkCrashException("boom")
        with mock.patch.object(cap_common, '_default_unraisablehook') as dflt:
            cap_common._quiet_tshark_unraisablehook(
                types.SimpleNamespace(exc_value=crash))
            dflt.assert_not_called()

    def test_quiet_unraisablehook_defers_other_errors(self):
        with mock.patch.object(cap_common, '_default_unraisablehook') as dflt:
            unraisable = types.SimpleNamespace(exc_value=ValueError("real"))
            cap_common._quiet_tshark_unraisablehook(unraisable)
            dflt.assert_called_once_with(unraisable)

    def test_all_field_values_falls_back_to_str(self):
        class _BadField:
            # Iterating .all_fields blows up; the helper falls back to str().
            @property
            def all_fields(self):
                raise RuntimeError("no sub-fields")

            def __str__(self):
                return "raw-value"

        layer = FakeLayer(fields={'x': _BadField()})
        self.assertEqual(cap_common._all_field_values(layer, 'x'),
                         ["raw-value"])

    def test_field_value_swallows_get_default_value_error(self):
        class _BadField:
            all_fields = []

            def get_default_value(self):
                raise RuntimeError("boom")

        layer = FakeLayer(fields={'x': _BadField()})
        self.assertEqual(cap_common._field_value(layer, 'x'), '')

    def test_ssid_from_mgt_non_hex_colon_value(self):
        # A value containing ':' that is not valid hex must not raise; the raw
        # text is returned instead.
        layer = FakeLayer(attrs={'wlan_ssid': 'zz:zz'})
        self.assertEqual(cap_common._ssid_from_mgt(layer), 'zz:zz')

    def test_field_value_none_field(self):
        # get_field returning None (an absent field on a real pyshark layer)
        # normalises to ''.
        class _NoneFieldLayer:
            def get_field(self, _name):
                return None

        self.assertEqual(cap_common._field_value(_NoneFieldLayer(), 'x'), '')


# --------------------------------------------------------------------------
# cap_runner: a per-packet error logged in verbose mode.
# --------------------------------------------------------------------------
class TestCapRunnerVerboseError(CapGapBase):
    def test_per_pkt_exception_logged_and_counted(self):
        def boom(_cursor, _pkt):
            raise ValueError("bad packet")

        # verbose=True prints the error; verbose=False takes the other branch.
        for verbose in (True, False):
            with capture_patch([FakePkt({})]):
                errors = cap_runner.run_cap_parse(
                    self.database, self.path, verbose, "X", "flt", boom,
                    catch_pkt_errors=True)
            self.assertEqual(errors, 1)


# --------------------------------------------------------------------------
# cap_parsers
# --------------------------------------------------------------------------
def _eapol_pkt(ta, da, key_info, type_='3'):
    eapol = FakeLayer(attrs={'field_names': ['type', 'keydes'],
                             'type': type_,
                             'wlan_rsna_keydes_key_info': key_info})
    return FakePkt({'eapol': eapol, 'wlan': FakeLayer(attrs={'ta': ta,
                                                             'da': da})})


def _mfp_pkt(rsn_caps, ta='AA:BB:CC:00:00:01'):
    return FakePkt({'wlan': FakeLayer(attrs={'ta': ta}),
                    'wlan.mgt': FakeLayer(attrs={
                        'wlan_rsn_capabilities': rsn_caps})})


def _wps_pkt(sa='AA:BB:CC:DD:EE:FF'):
    ssid_hex = colon_hex(b'TestAP')
    mgt = FakeLayer(attrs={
        'wlan_ssid': ssid_hex, 'wps_ext_version2': '20',
        'wps_device_name': 'Router1', 'wps_model_name': 'ModelX',
        'wps_model_number': 'N100', 'wps_config_methods': '0x0088',
        'wps_config_methods_keypad': '1'})
    return FakePkt({'wlan': FakeLayer(attrs={'sa': sa}), 'wlan.mgt': mgt})


class TestParseCapDispatch(CapGapBase):
    def test_parse_cap_no_tools_is_noop(self):
        # tshark False and hcxpcapngtool False: neither branch runs.
        cap_parsers.parse_cap(self.path, self.database, False,
                              hcxpcapngtool=False, tshark=False)


def _both_verbose(parser, packets, database, capture):
    '''Run a parser through the synthetic packets at both verbosity levels so
    each `if verbose:` branch (and the verbose=False path realdata would take)
    is exercised. `seen` is per-call, so the second pass re-runs cleanly.'''
    for verbose in (True, False):
        with capture_patch(packets):
            parser(capture, database, verbose)


class TestParseHandshakes(CapGapBase):
    def test_valid_and_unmatched_handshakes(self):
        ap, client = 'AA:BB:CC:00:00:AA', 'AA:BB:CC:00:00:CC'
        packets = [
            # a non-EAPOL-Key frame (type != '3') is skipped.
            _eapol_pkt(ap, client, 'key_info', type_='1'),
            # message-1 (from AP): remembered, find('10a') == -1 branch.
            _eapol_pkt(ap, client, 'key_info_08a'),
            # message-2 (from client): matches -> "Valid handshake" + insert.
            _eapol_pkt(client, ap, 'key_info_10a'),
            # another '10a' frame that does not match the stored message-1.
            _eapol_pkt('AA:BB:CC:00:00:11', 'AA:BB:CC:00:00:22',
                       'key_info_10a'),
        ]
        _both_verbose(cap_parsers.parse_handshakes, packets,
                      self.database, self.path)
        row = self.cursor.execute(
            "SELECT bssid, mac FROM Handshake").fetchone()
        self.assertEqual(row, (ap, client))


class TestParseMFP(CapGapBase):
    def test_mfp_variants(self):
        packets = [
            _mfp_pkt(''),          # empty caps -> early return (line 78)
            _mfp_pkt('0x0001'),    # neither MFPC nor MFPR -> return (line 89)
            _mfp_pkt('0x00c0'),    # MFPC+MFPR set -> verbose + insertMFP
        ]
        _both_verbose(cap_parsers.parse_MFP, packets,
                      self.database, self.path)
        row = self.cursor.execute(
            "SELECT mfpc, mfpr FROM AP WHERE bssid = ?",
            ('AA:BB:CC:00:00:01',)).fetchone()
        self.assertEqual(row, ('True', 'True'))


class TestParseWPS(CapGapBase):
    def test_wps_beacon_merged_onto_ap(self):
        packets = [
            _wps_pkt(),
            # a frame with no wlan.sa yields an empty bssid: per_pkt skips it.
            FakePkt({'wlan': FakeLayer(attrs={}),
                     'wlan.mgt': FakeLayer(attrs={'wlan_ssid': ''})}),
        ]
        _both_verbose(cap_parsers.parse_WPS, packets,
                      self.database, self.path)
        row = self.cursor.execute(
            "SELECT wps_device_name, wps_version FROM AP WHERE bssid = ?",
            ('AA:BB:CC:DD:EE:FF',)).fetchone()
        self.assertEqual(row, ('Router1', '2.0'))

    def test_wps_fields_for_pkt_directly(self):
        bssid, fields = cap_parsers._wps_fields_for_pkt(_wps_pkt())
        self.assertEqual(bssid, 'AA:BB:CC:DD:EE:FF')
        self.assertEqual(fields['wlan_ssid'], 'TestAP')
        self.assertEqual(fields['wps_version'], '2.0')


# --------------------------------------------------------------------------
# beacon_parsers
# --------------------------------------------------------------------------
class TestBeaconParsers(CapGapBase):
    def test_capabilities_insert(self):
        # tag 54 = Mobility Domain -> 802.11r advertised, so the row is stored.
        # A frame without any capability tag returns early (no row).
        def cap_pkt(sa):
            return FakePkt(
                {'wlan': FakeLayer(attrs={'sa': sa}),
                 'wlan.mgt': FakeLayer(fields={'wlan_tag_number': Field(
                     None, all_values=['54'])})})

        no_cap = FakePkt(
            {'wlan': FakeLayer(attrs={'sa': 'AA:BB:CC:00:0F:02'}),
             'wlan.mgt': FakeLayer(fields={'wlan_tag_number': Field(
                 None, all_values=['0'])})})
        # A repeated BSSID is skipped by the per-AP `seen` guard.
        packets = [cap_pkt('AA:BB:CC:00:0F:01'), no_cap,
                   cap_pkt('AA:BB:CC:00:0F:01')]
        _both_verbose(beacon_parsers.parse_capabilities, packets,
                      self.database, self.path)
        row = self.cursor.execute(
            "SELECT ft_80211r FROM AP WHERE bssid = ?",
            ('AA:BB:CC:00:0F:01',)).fetchone()
        self.assertEqual(row, ('True',))

    def test_hidden_ssid_empty_and_revealed(self):
        empty = FakePkt({
            'wlan': FakeLayer(attrs={'bssid': 'AA:BB:CC:00:0E:01'}),
            'wlan.mgt': FakeLayer(attrs={'wlan_ssid': ''})})

        def revealed(bssid):
            return FakePkt({
                'wlan': FakeLayer(attrs={'bssid': bssid}),
                'wlan.mgt': FakeLayer(attrs={'wlan_ssid': 'RevealedNet'})})

        # The repeated BSSID is skipped by the per-AP `seen` guard.
        packets = [empty, revealed('AA:BB:CC:00:0E:02'),
                   revealed('AA:BB:CC:00:0E:02')]
        _both_verbose(beacon_parsers.parse_hidden_ssid, packets,
                      self.database, self.path)
        row = self.cursor.execute(
            "SELECT ssid FROM AP WHERE bssid = ?",
            ('AA:BB:CC:00:0E:02',)).fetchone()
        self.assertEqual(row, ('RevealedNet',))


# --------------------------------------------------------------------------
# security_parsers
# --------------------------------------------------------------------------
class TestSecurityParsers(CapGapBase):
    def test_security_with_and_without_akm_verbose(self):
        def akm_pkt(sa, rsn_caps):
            return FakePkt({
                'wlan': FakeLayer(attrs={'sa': sa}),
                'wlan.mgt': FakeLayer(
                    attrs={'wlan_rsn_capabilities': rsn_caps},
                    fields={'wlan_rsn_akms_type': Field(
                        None, all_values=['2'])})})

        valid = akm_pkt('AA:BB:CC:00:5E:01', '0x00c0')  # MFP set -> insertMFP
        # AKM present but no MFP bits -> the insertMFP branch is skipped.
        no_mfp = akm_pkt('AA:BB:CC:00:5E:04', '0x0000')
        # A repeated BSSID is skipped by the per-AP `seen` guard.
        dup = akm_pkt('AA:BB:CC:00:5E:01', '0x00c0')
        # No AKM element -> _security_row returns None -> per_pkt returns 0.
        no_akm = FakePkt({
            'wlan': FakeLayer(attrs={'sa': 'AA:BB:CC:00:5E:02'}),
            'wlan.mgt': FakeLayer(attrs={})})
        _both_verbose(security_parsers.parse_security,
                      [valid, dup, no_mfp, no_akm],
                      self.database, self.path)
        row = self.cursor.execute(
            "SELECT wpa_version FROM AP WHERE bssid = ?",
            ('AA:BB:CC:00:5E:01',)).fetchone()
        self.assertEqual(row, ('WPA2',))

    def test_security_row_none_without_akm(self):
        self.assertIsNone(
            security_parsers._security_row(FakeLayer(attrs={})))

    def test_insert_one_security_none_without_akm(self):
        self.assertIsNone(security_parsers._insert_one_security(
            self.cursor, False, 'f', 'AA:BB:CC:00:5E:03', FakeLayer(attrs={})))


# --------------------------------------------------------------------------
# eap_parsers
# --------------------------------------------------------------------------
class TestEapParsers(CapGapBase):
    def test_identity_missing_identity_field_verbose(self):
        # EAP-Response Identity (code 2, type 1) whose eap.identity field is
        # absent: the AttributeError is caught, logged and counted.
        pkt = FakePkt({'eap': FakeLayer(attrs={'code': '2', 'type': '1'}),
                       'wlan': FakeLayer(attrs={'da': 'AA:BB:CC:00:1D:01',
                                               'sa': 'AA:BB:CC:00:1D:02'})})
        # An EAP-Request Identity (code 1) refreshes addresses without reading
        # the identity field (the code != '2' branch).
        request = FakePkt({
            'eap': FakeLayer(attrs={'code': '1', 'type': '1'}),
            'wlan': FakeLayer(attrs={'da': 'AA:BB:CC:00:1D:01',
                                    'sa': 'AA:BB:CC:00:1D:02'})})
        with capture_patch([request, pkt]):
            errors = eap_parsers.parse_identities(
                self.path, self.database, True)
        self.assertEqual(errors, 1)
        # verbose=False takes the other branch of the same error path.
        with capture_patch([request, pkt]):
            eap_parsers.parse_identities(self.path, self.database, False)

    def test_eap_md5_pair_verbose(self):
        request = FakePkt({
            'eap': FakeLayer(attrs={'code': '1', 'id': '7',
                                   'md5_value': 'aa:bb'}),
            'wlan': FakeLayer(attrs={'sa': 'AA:BB:CC:00:4D:0A',
                                    'da': 'AA:BB:CC:00:4D:0C'})})
        response = FakePkt({
            'eap': FakeLayer(attrs={'code': '2', 'id': '7',
                                   'md5_value': 'cc:dd'}),
            'wlan': FakeLayer(attrs={'sa': 'AA:BB:CC:00:4D:0C',
                                    'da': 'AA:BB:CC:00:4D:0A'})})
        _both_verbose(eap_parsers.parse_eap_md5, [request, response],
                      self.database, self.path)
        row = self.cursor.execute(
            "SELECT challenge, response FROM EAPMD5").fetchone()
        self.assertEqual(row, ('aabb', 'ccdd'))

    def test_probe_fingerprint_verbose(self):
        mgt = FakeLayer(attrs={'wlan_ssid': ''},
                        fields={'wlan_tag_number': Field(
                            None, all_values=['0', '1', '48'])})
        pkt = FakePkt({'wlan': FakeLayer(attrs={'sa': 'AA:BB:CC:00:9B:01'}),
                       'wlan.mgt': mgt})
        _both_verbose(eap_parsers.parse_probe_fingerprint, [pkt],
                      self.database, self.path)
        row = self.cursor.execute(
            "SELECT ie_order FROM Probe WHERE mac = ?",
            ('AA:BB:CC:00:9B:01',)).fetchone()
        self.assertEqual(row, ('0,1,48',))


class TestExecHcxpcapngtool(CapGapBase):
    '''exec_hcxpcapngtool with subprocess.Popen faked so no external binary is
    needed. Runs in a temporary cwd because the tool writes/reads/removes
    ./test.22000.'''

    def _run_in_tmpdir(self, popen_factory, verbose=False):
        with tempfile.TemporaryDirectory() as workdir:
            prev = os.getcwd()
            os.chdir(workdir)
            try:
                with mock.patch.object(eap_parsers.subprocess, 'Popen',
                                       popen_factory):
                    eap_parsers.exec_hcxpcapngtool(
                        self.path, self.database, verbose)
            finally:
                os.chdir(prev)

    def test_no_output_file_returns_early(self):
        class _Popen:  # never creates test.22000
            def __init__(self, *a, **k):
                pass

            def wait(self):
                return 0

        self._run_in_tmpdir(_Popen)
        count = self.cursor.execute(
            "SELECT COUNT(*) FROM Handshake").fetchone()[0]
        self.assertEqual(count, 0)

    def test_hash_line_inserted_verbose(self):
        line = ('WPA*02*ffffffffffffffffffffffffffffffff*'
                'aabbccddeeff*112233445566*657373*'
                'deadbeef*0103*00\n')

        class _Popen:
            def __init__(self, *a, **k):
                with open('test.22000', 'w', encoding='utf-8') as handle:
                    handle.write(line)

            def wait(self):
                return 0

        # Both verbosities: the verbose branch prints the parsed hash line.
        for verbose in (True, False):
            self._run_in_tmpdir(_Popen, verbose=verbose)
        row = self.cursor.execute(
            "SELECT bssid, mac FROM Handshake").fetchone()
        self.assertEqual(row, ('AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66'))

    def test_popen_failure_is_caught(self):
        def _boom(*a, **k):
            raise OSError("cannot exec")

        # Must not raise; the error is caught and reported.
        self._run_in_tmpdir(_boom)


if __name__ == '__main__':
    unittest.main()
