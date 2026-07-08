'''Tests for the probe-request fingerprint parser in utils/eap_parsers.py,
driven by fake pyshark packets (the EAP identity/MD5 tests for the same
module live in test_eap_parsers.py).

_probe_fingerprint_for_pkt is pure once the packet fields are supplied, so
stand-in layer/packet objects exercise it without tshark; the database insert
is mocked.'''
import unittest
from types import SimpleNamespace
from unittest import mock

from utils import eap_parsers


class _MgtLayer:
    '''Stand-in wlan.mgt layer exposing the IE tag numbers and (optionally)
    the SSID element the fingerprint parser reads.'''
    def __init__(self, tags, ssid_hex=None):
        self._tags = tags
        self._ssid_hex = ssid_hex

    def get_field(self, name):
        if name == "wlan_tag_number":
            return _FakeField(self._tags)
        raise KeyError(name)

    @property
    def wlan_ssid(self):
        if self._ssid_hex is None:
            raise AttributeError("wlan_ssid")
        return self._ssid_hex


class _FakeField:
    '''pyshark field stand-in: .all_fields yields one sub-field per value.'''
    def __init__(self, values):
        self.all_fields = [SimpleNamespace(get_default_value=lambda v=v: v)
                           for v in values]


class _ProbePkt:
    '''Probe-request packet: pkt.wlan.sa and pkt['wlan.mgt'], either of which
    may be absent to trigger the parser's guard clauses.'''
    def __init__(self, sa=None, mgt=None):
        if sa is not None:
            self.wlan = SimpleNamespace(sa=sa)
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
