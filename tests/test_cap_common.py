'''Tests for the pure pyshark-field helpers in utils/cap_common.py.

These take plain layer/packet stand-ins (no tshark), so they exercise the
field extraction, SSID decoding and suite-name mapping used by every .cap
parser without opening a capture.'''
import unittest

from utils import cap_common


class _Field:
    '''Minimal stand-in for a pyshark field object.'''
    def __init__(self, value, all_values=None):
        self._value = value
        if all_values is None:
            self.all_fields = [self]
        else:
            self.all_fields = [_Field(v) for v in all_values]

    def get_default_value(self):
        return self._value

    def __str__(self):
        return str(self._value)


class _Layer:
    '''Stand-in pyshark layer: get_field(name) returns a preset _Field.'''
    def __init__(self, fields):
        self._fields = fields

    def get_field(self, name):
        field = self._fields.get(name)
        if field is None:
            raise KeyError(name)
        return field


class TestScalarHelpers(unittest.TestCase):
    def test_safe(self):
        self.assertEqual(cap_common._safe(lambda: 1 / 0, "fallback"),
                         "fallback")
        self.assertEqual(cap_common._safe(lambda: "ok"), "ok")

    def test_to_int(self):
        self.assertEqual(cap_common._to_int("10"), 10)
        self.assertEqual(cap_common._to_int("ff", 16), 255)
        self.assertEqual(cap_common._to_int(7), 7)
        self.assertIsNone(cap_common._to_int("nope"))
        self.assertIsNone(cap_common._to_int(None))

    def test_dedupe_preserves_order(self):
        self.assertEqual(cap_common._dedupe(["a", "b", "a", "c", "b"]),
                         ["a", "b", "c"])

    def test_suite_name(self):
        mapping = {"2": "WPA2"}
        self.assertEqual(cap_common._suite_name("2", mapping), "WPA2")
        self.assertEqual(cap_common._suite_name(2, mapping), "WPA2")
        # Unknown selector falls back to its own string form.
        self.assertEqual(cap_common._suite_name("99", mapping), "99")
        self.assertEqual(cap_common._suite_name(None, mapping), "None")

    def test_field_is_set(self):
        for truthy in ("1", "true", "TRUE", "yes", " Yes "):
            self.assertTrue(cap_common._field_is_set(truthy))
        for falsy in ("0", "false", "no", ""):
            self.assertFalse(cap_common._field_is_set(falsy))


class TestFieldExtraction(unittest.TestCase):
    def test_field_value_present_missing_and_error(self):
        layer = _Layer({"present": _Field("v"), "empty": _Field(None)})
        self.assertEqual(cap_common._field_value(layer, "present"), "v")
        # Field whose value is None normalises to ''.
        self.assertEqual(cap_common._field_value(layer, "empty"), "")
        # get_field raising (unknown name) also yields ''.
        self.assertEqual(cap_common._field_value(layer, "missing"), "")

    def test_first_field_value(self):
        layer = _Layer({"a": _Field(None), "b": _Field("second")})
        self.assertEqual(
            cap_common._first_field_value(layer, ["a", "b"]), "second")
        self.assertEqual(
            cap_common._first_field_value(layer, ["missing"]), "")

    def test_all_field_values(self):
        layer = _Layer({"tags": _Field(None, all_values=["1", "", "2", None])})
        # Empty and None entries are dropped.
        self.assertEqual(
            cap_common._all_field_values(layer, "tags"), ["1", "2"])
        self.assertEqual(cap_common._all_field_values(layer, "missing"), [])

    def test_mgt_tag_numbers(self):
        layer = _Layer({"wlan_tag_number":
                        _Field(None, all_values=["0", "1", "bad", "48"])})
        self.assertEqual(cap_common._mgt_tag_numbers(layer), {0, 1, 48})


class TestSsidDecoding(unittest.TestCase):
    def test_plaintext(self):
        layer = _Layer({"wlan_ssid": _Field("MyNetwork")})
        self.assertEqual(cap_common._ssid_from_mgt(layer), "MyNetwork")

    def test_hidden(self):
        layer = _Layer({"wlan_ssid": _Field("")})
        self.assertEqual(cap_common._ssid_from_mgt(layer), "")

    def test_hex_encoded(self):
        raw = ":".join("%02x" % b for b in b"HexSSID")
        layer = _Layer({"wlan_ssid": _Field(raw)})
        self.assertEqual(cap_common._ssid_from_mgt(layer), "HexSSID")

    def test_hex_nul_padding_stripped(self):
        raw = ":".join("%02x" % b for b in b"AP\x00\x00")
        layer = _Layer({"wlan_ssid": _Field(raw)})
        self.assertEqual(cap_common._ssid_from_mgt(layer), "AP")


class _Pkt:
    def __init__(self, sa=None, mgt=None):
        if sa is not None:
            self.wlan = type("W", (), {"sa": sa})()
        self._mgt = mgt

    def __getitem__(self, key):
        if key == "wlan.mgt" and self._mgt is not None:
            return self._mgt
        raise KeyError(key)


class TestPacketHelpers(unittest.TestCase):
    def test_pkt_bssid_mgt(self):
        mgt = _Layer({})
        bssid, layer = cap_common._pkt_bssid_mgt(_Pkt(sa="AA", mgt=mgt))
        self.assertEqual(bssid, "AA")
        self.assertIs(layer, mgt)
        # No wlan layer at all -> (None, None), never raises.
        self.assertEqual(cap_common._pkt_bssid_mgt(_Pkt()), (None, None))

    def test_seen_or_invalid(self):
        seen = {"AA:BB:CC:DD:EE:FF"}
        mgt = _Layer({})
        self.assertTrue(cap_common._seen_or_invalid(None, mgt, seen))
        self.assertTrue(cap_common._seen_or_invalid("AA", None, seen))
        self.assertTrue(cap_common._seen_or_invalid(
            "aa:bb:cc:dd:ee:ff", mgt, seen))
        self.assertFalse(cap_common._seen_or_invalid(
            "11:22:33:44:55:66", mgt, seen))


if __name__ == "__main__":
    unittest.main()
