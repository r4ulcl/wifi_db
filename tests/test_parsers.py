'''Unit tests for the pure parser-logic added in 1.6: RSN/WPA classification,
suite-selector naming, X.509 cert attribution by EAP direction, the EAP-MD5
hashcat line format, the sticky WPS field merge and the constant lookup tables.

These functions are the deterministic core of the .cap parsers and need neither
pyshark packet objects nor a database, so they are tested directly.'''
import unittest

from utils.cap_common import _suite_name, _dedupe, _to_int
from utils.security_parsers import _classify_wpa, _akm_ints
from utils.cert_parsers import _cert_attribution
from utils.cap_parsers import _merge_wps_fields
from utils.eap_parsers import _eap_md5_hashcat
from utils.wifi_constants import (RSN_AKM_SUITES, RSN_CIPHERS,
                                  RSN_ENTERPRISE_AKMS, EAP_METHOD_TYPES)


class TestWpaClassification(unittest.TestCase):
    def test_classify_wpa(self):
        self.assertEqual(_classify_wpa({2}), 'WPA2')          # PSK
        self.assertEqual(_classify_wpa({1}), 'WPA2')          # 802.1X
        self.assertEqual(_classify_wpa({8}), 'WPA3')          # SAE
        self.assertEqual(_classify_wpa({9}), 'WPA3')          # FT-SAE
        self.assertEqual(_classify_wpa({18}), 'OWE')          # OWE
        # A transition network advertising both SAE and PSK is WPA2/WPA3.
        self.assertEqual(_classify_wpa({8, 2}), 'WPA2/WPA3')
        self.assertEqual(_classify_wpa({9, 4}), 'WPA2/WPA3')
        # SAE takes precedence over OWE when both are present.
        self.assertEqual(_classify_wpa({8, 18}), 'WPA3')

    def test_akm_ints(self):
        self.assertEqual(_akm_ints(['1', '2', '8']), {1, 2, 8})
        self.assertEqual(_akm_ints([]), set())
        # Unparseable selectors are dropped, not counted.
        self.assertEqual(_akm_ints(['x', '2']), {2})


class TestSuiteNaming(unittest.TestCase):
    def test_suite_name(self):
        self.assertEqual(_suite_name('8', RSN_AKM_SUITES), 'SAE')
        self.assertEqual(_suite_name('2', RSN_AKM_SUITES), 'PSK')
        self.assertEqual(_suite_name('4', RSN_CIPHERS), 'CCMP-128')
        # An unknown selector falls back to its own number.
        self.assertEqual(_suite_name('99', RSN_AKM_SUITES), '99')

    def test_dedupe_preserves_order(self):
        self.assertEqual(_dedupe(['PSK', 'PSK', 'SAE', 'PSK']), ['PSK', 'SAE'])


class TestCertAttribution(unittest.TestCase):
    def test_direction(self):
        # eap.code 2 (EAP-Response) = client cert: bssid=dst, mac=src.
        self.assertEqual(
            _cert_attribution(['HEX', 'SA', 'DA', '2']),
            ('HEX', 'DA', 'SA', 'Client'))
        # eap.code 1 (EAP-Request) = AP/server cert: bssid=src, mac=dst.
        self.assertEqual(
            _cert_attribution(['HEX', 'SA', 'DA', '1']),
            ('HEX', 'SA', 'DA', 'AP'))
        # Any other code is Unknown but still src/dst ordered.
        self.assertEqual(
            _cert_attribution(['HEX', 'SA', 'DA', '9']),
            ('HEX', 'SA', 'DA', 'Unknown'))

    def test_missing_columns(self):
        # A line with only the certificate column must not raise.
        self.assertEqual(_cert_attribution(['HEX']),
                         ('HEX', '', '', 'Unknown'))


class TestEapMd5Hashcat(unittest.TestCase):
    def test_format(self):
        # response:challenge:eap_id, with the EAP id hex-encoded (42 -> 2a).
        self.assertEqual(
            _eap_md5_hashcat('42', '0102030405060708090a0b0c0d0e0f10',
                             'aabbccddeeff00112233445566778899'),
            'aabbccddeeff00112233445566778899:'
            '0102030405060708090a0b0c0d0e0f10:2a')

    def test_non_numeric_id_passthrough(self):
        # A non-decimal eap_id is left as-is rather than crashing.
        self.assertEqual(_eap_md5_hashcat('zz', 'cccc', 'rrrr'),
                         'rrrr:cccc:zz')

    def test_to_int(self):
        self.assertEqual(_to_int('42'), 42)
        self.assertEqual(_to_int('0x1f', 16), 31)
        self.assertIsNone(_to_int('nope'))


class TestWpsMerge(unittest.TestCase):
    def _fields(self, **kw):
        base = {
            'wlan_ssid': '', 'wps_version': '1.0', 'wps_device_name': '',
            'wps_model_name': '', 'wps_model_number': '',
            'wps_config_methods': '', 'wps_config_methods_keypad': '',
        }
        base.update(kw)
        return base

    def test_first_frame_copied(self):
        fields = self._fields(wps_device_name='Router')
        merged = _merge_wps_fields(None, fields)
        self.assertEqual(merged['wps_device_name'], 'Router')
        # Must be a copy, not the same dict, so later merges don't alias it.
        self.assertIsNot(merged, fields)

    def test_sticky_non_empty(self):
        # A Probe Response fills device/model; a later reduced Beacon (empty
        # details) must not blank them, but does fill a still-missing field.
        acc = _merge_wps_fields(None, self._fields(wps_device_name='Router',
                                                   wps_model_name='X1'))
        _merge_wps_fields(acc, self._fields(wps_device_name='',
                                            wps_model_number='N9'))
        self.assertEqual(acc['wps_device_name'], 'Router')
        self.assertEqual(acc['wps_model_name'], 'X1')
        self.assertEqual(acc['wps_model_number'], 'N9')

    def test_version_climbs_to_2_and_sticks(self):
        acc = _merge_wps_fields(None, self._fields(wps_version='1.0'))
        _merge_wps_fields(acc, self._fields(wps_version='2.0'))
        self.assertEqual(acc['wps_version'], '2.0')
        # A later 1.0 frame must not downgrade a 2.0 detection.
        _merge_wps_fields(acc, self._fields(wps_version='1.0'))
        self.assertEqual(acc['wps_version'], '2.0')


class TestConstantTables(unittest.TestCase):
    def test_eap_method_types(self):
        self.assertEqual(EAP_METHOD_TYPES['13'], 'EAP-TLS')
        self.assertEqual(EAP_METHOD_TYPES['25'], 'EAP-PEAP')
        self.assertEqual(EAP_METHOD_TYPES['4'], 'EAP-MD5')

    def test_enterprise_akms(self):
        # 802.1X-family selectors are enterprise; PSK/SAE/OWE are not.
        self.assertIn(1, RSN_ENTERPRISE_AKMS)
        self.assertIn(5, RSN_ENTERPRISE_AKMS)
        self.assertNotIn(2, RSN_ENTERPRISE_AKMS)
        self.assertNotIn(8, RSN_ENTERPRISE_AKMS)
        self.assertNotIn(18, RSN_ENTERPRISE_AKMS)


if __name__ == '__main__':
    unittest.main()
