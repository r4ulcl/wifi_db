'''Tests for the EAP identity and EAP-MD5 logic in utils/eap_parsers.py,
driven by fake pyshark packets.

The per-packet callbacks are pure state machines once the packet fields are
supplied, so plain stand-in objects exercise them without tshark. Database
inserts are mocked. The probe-fingerprint parser lives in the same module but
is tested separately in test_probe_fingerprint.py to keep each file small.'''
import unittest
from unittest import mock

from utils import eap_parsers


class _Eap:
    '''Stand-in pyshark eap layer. Only the fields passed in are set, so a
    packet missing a field raises AttributeError just like the real one.'''
    # Constructor kwarg -> attribute name (pyshark exposes .type and .id).
    _ALIASES = {"etype": "type", "eap_id": "id"}

    def __init__(self, **fields):
        for name, value in fields.items():
            setattr(self, self._ALIASES.get(name, name), value)


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
        pkt = _Pkt(_Eap(code="2", etype="1", identity="alice"),
                   _Wlan(da="AP", sa="CLIENT"))
        errors, state, insert = self._call(pkt)
        self.assertEqual(errors, 0)
        self.assertEqual(state, ("AP", "CLIENT", "alice", ""))
        insert.assert_not_called()

    def test_identity_response_missing_field(self):
        # code 2 identity request whose .identity raises is counted once.
        eap = _Eap(code="2", etype="1")
        pkt = _Pkt(eap, _Wlan(da="AP", sa="CLIENT"))
        errors, state, insert = self._call(pkt)
        self.assertEqual(errors, 1)

    def test_method_packet_inserts(self):
        # A non-identity EAP type stores the method against the last identity.
        pkt = _Pkt(_Eap(code="1", etype="13"))  # 13 = EAP-TLS
        errors, state, insert = self._call(
            pkt, state=("AP", "CLIENT", "alice", ""))
        self.assertEqual(errors, 0)
        self.assertEqual(state[3], "EAP-TLS")
        insert.assert_called_once()

    def test_unknown_method_type(self):
        pkt = _Pkt(_Eap(code="1", etype="250"))
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


if __name__ == "__main__":
    unittest.main()
