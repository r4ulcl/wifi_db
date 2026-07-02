'''Tests for utils/eap_parsers.py driven by fake pyshark packets.

The per-packet callbacks are pure state machines once the packet fields are
supplied, so plain stand-in objects exercise the EAP identity, EAP-MD5 and
probe-fingerprint logic without tshark. Database inserts are mocked.'''
import unittest
from unittest import mock

from utils import eap_parsers


class _Eap:
    def __init__(self, code=None, type=None, identity=None,
                 md5_value=None, eap_id=None):
        if code is not None:
            self.code = code
        if type is not None:
            self.type = type
        if identity is not None:
            self.identity = identity
        if md5_value is not None:
            self.md5_value = md5_value
        if eap_id is not None:
            self.id = eap_id


class _Wlan:
    def __init__(self, da=None, sa=None):
        self.da = da
        self.sa = sa


class _Pkt:
    def __init__(self, eap, wlan=None):
        self.eap = eap
        if wlan is not None:
            self.wlan = wlan


class TestIdentityForPkt(unittest.TestCase):
    def _call(self, pkt, state=("", "", "", "")):
        cursor = mock.Mock()
        with mock.patch("utils.eap_parsers.database_utils.insertIdentity") \
                as insert:
            errors, new_state = eap_parsers._identity_for_pkt(
                cursor, False, pkt, state)
        return errors, new_state, insert

    def test_success_and_failure_frames_skipped(self):
        # EAP Success (3) / Failure (4) carry no Type field: skip, no error.
        for code in ("3", "4"):
            errors, state, insert = self._call(_Pkt(_Eap(code=code)))
            self.assertEqual(errors, 0)
            insert.assert_not_called()

    def test_identity_response_records_identity(self):
        pkt = _Pkt(_Eap(code="2", type="1", identity="alice"),
                   _Wlan(da="AP", sa="CLIENT"))
        errors, state, insert = self._call(pkt)
        self.assertEqual(errors, 0)
        self.assertEqual(state, ("AP", "CLIENT", "alice", ""))
        insert.assert_not_called()

    def test_identity_response_missing_field(self):
        # code 2 identity request whose .identity raises is counted once.
        eap = _Eap(code="2", type="1")
        pkt = _Pkt(eap, _Wlan(da="AP", sa="CLIENT"))
        errors, state, insert = self._call(pkt)
        self.assertEqual(errors, 1)

    def test_method_packet_inserts(self):
        # A non-identity EAP type stores the method against the last identity.
        pkt = _Pkt(_Eap(code="1", type="13"))  # 13 = EAP-TLS
        errors, state, insert = self._call(
            pkt, state=("AP", "CLIENT", "alice", ""))
        self.assertEqual(errors, 0)
        self.assertEqual(state[3], "EAP-TLS")
        insert.assert_called_once()

    def test_unknown_method_type(self):
        pkt = _Pkt(_Eap(code="1", type="250"))
        errors, state, insert = self._call(pkt)
        self.assertIn("OTHER (UNKNOWN EAP METHOD)", state[3])
        self.assertIn("250", state[3])


class TestEapMd5(unittest.TestCase):
    def test_packet_parsing(self):
        pkt = _Pkt(_Eap(code="1", eap_id="5", md5_value="aa:bb:cc"),
                   _Wlan(da="AP", sa="CLIENT"))
        parsed = eap_parsers._eap_md5_packet(pkt)
        self.assertEqual(parsed, ("1", "5", "CLIENT", "AP", "aabbcc"))

    def test_packet_parsing_empty_value(self):
        pkt = _Pkt(_Eap(code="1", eap_id="5", md5_value=""),
                   _Wlan(da="AP", sa="CLIENT"))
        self.assertIsNone(eap_parsers._eap_md5_packet(pkt))

    def test_packet_parsing_missing_field(self):
        # No md5_value attribute at all -> None (the except branch).
        pkt = _Pkt(_Eap(code="1"), _Wlan(da="AP", sa="CLIENT"))
        self.assertIsNone(eap_parsers._eap_md5_packet(pkt))

    def test_hashcat_line_hex_id(self):
        # eap_id is decimal from pyshark; the hashcat line hex-encodes it.
        line = eap_parsers._eap_md5_hashcat("5", "challenge", "response")
        self.assertEqual(line, "response:challenge:05")

    def test_hashcat_line_non_numeric_id(self):
        line = eap_parsers._eap_md5_hashcat("zz", "chal", "resp")
        self.assertEqual(line, "resp:chal:zz")

    def _for_pkt(self, pkt, challenges):
        cursor = mock.Mock()
        with mock.patch(
                "utils.eap_parsers.database_utils.insertEAPMD5",
                return_value=0) as insert:
            errors = eap_parsers._eap_md5_for_pkt(
                cursor, False, pkt, challenges, "file.cap")
        return errors, insert

    def test_request_then_response_pairs_up(self):
        challenges = {}
        request = _Pkt(_Eap(code="1", eap_id="7", md5_value="ab:cd"),
                       _Wlan(da="CLIENT", sa="AP"))
        errors, insert = self._for_pkt(request, challenges)
        self.assertEqual(errors, 0)
        insert.assert_not_called()
        self.assertEqual(challenges[("AP", "CLIENT", "7")], "abcd")

        response = _Pkt(_Eap(code="2", eap_id="7", md5_value="ef:01"),
                        _Wlan(da="AP", sa="CLIENT"))
        errors, insert = self._for_pkt(response, challenges)
        self.assertEqual(errors, 0)
        insert.assert_called_once()

    def test_response_without_challenge_ignored(self):
        response = _Pkt(_Eap(code="2", eap_id="9", md5_value="ef:01"),
                        _Wlan(da="AP", sa="CLIENT"))
        errors, insert = self._for_pkt(response, {})
        self.assertEqual(errors, 0)
        insert.assert_not_called()

    def test_other_codes_ignored(self):
        pkt = _Pkt(_Eap(code="4", eap_id="1", md5_value="aa"),
                   _Wlan(da="AP", sa="CLIENT"))
        errors, insert = self._for_pkt(pkt, {})
        self.assertEqual(errors, 0)
        insert.assert_not_called()

    def test_unparseable_packet_ignored(self):
        pkt = _Pkt(_Eap(code="1"), _Wlan(da="AP", sa="CLIENT"))
        errors, insert = self._for_pkt(pkt, {})
        self.assertEqual(errors, 0)


class _MgtLayer:
    def __init__(self, tags, ssid_hex=None):
        self._tags = tags
        self._ssid_hex = ssid_hex

    def get_field(self, name):
        class _F:
            def __init__(self, values):
                self.all_fields = [type("SF", (), {
                    "get_default_value": (lambda self, v=v: v)})()
                    for v in values]
        if name == "wlan_tag_number":
            return _F(self._tags)
        raise KeyError(name)

    @property
    def wlan_ssid(self):
        if self._ssid_hex is None:
            raise AttributeError("wlan_ssid")
        return self._ssid_hex


class _ProbePkt:
    def __init__(self, sa=None, mgt=None):
        if sa is not None:
            self.wlan = _Wlan(sa=sa)
        self._mgt = mgt

    def __getitem__(self, key):
        if key == "wlan.mgt" and self._mgt is not None:
            return self._mgt
        raise KeyError(key)


class TestProbeFingerprint(unittest.TestCase):
    def _call(self, pkt, seen):
        cursor = mock.Mock()
        with mock.patch(
                "utils.eap_parsers.database_utils.insertProbeFingerprint",
                return_value=0) as insert:
            errors = eap_parsers._probe_fingerprint_for_pkt(
                cursor, False, pkt, seen, "file.cap")
        return errors, insert

    def test_missing_mac(self):
        errors, insert = self._call(_ProbePkt(), set())
        self.assertEqual(errors, 0)
        insert.assert_not_called()

    def test_missing_mgt(self):
        errors, insert = self._call(_ProbePkt(sa="AA"), set())
        self.assertEqual(errors, 0)
        insert.assert_not_called()

    def test_no_tags(self):
        mgt = _MgtLayer(tags=[])
        errors, insert = self._call(_ProbePkt(sa="AA", mgt=mgt), set())
        self.assertEqual(errors, 0)
        insert.assert_not_called()

    def test_fingerprint_inserted_and_deduped(self):
        ssid_hex = ":".join("%02x" % b for b in b"Net")
        mgt = _MgtLayer(tags=["0", "1", "48"], ssid_hex=ssid_hex)
        seen = set()
        errors, insert = self._call(
            _ProbePkt(sa="aa:bb:cc:dd:ee:ff", mgt=mgt), seen)
        self.assertEqual(errors, 0)
        insert.assert_called_once()
        # Same MAC/SSID/fingerprint again is skipped.
        errors, insert = self._call(
            _ProbePkt(sa="aa:bb:cc:dd:ee:ff", mgt=mgt), seen)
        insert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
