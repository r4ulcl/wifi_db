'''Tests for the small runtime helpers: the shared pyshark capture driver
(utils/cap_runner.py), the OUI vendor-list download logic (utils/oui.py) and
the asyncio child-watcher shim (utils/asyncio_shim.py).

pyshark's FileCapture and the vendor download are mocked, so no tshark
process or network access is involved.'''
import asyncio
import unittest
from unittest import mock

import requests

from utils import asyncio_shim
from utils import cap_runner
from utils import oui


class TestRunCapParse(unittest.TestCase):
    def setUp(self):
        self.database = mock.Mock()

    def _run(self, per_pkt, packets, **kwargs):
        with mock.patch.object(cap_runner.pyshark, "FileCapture",
                               return_value=packets):
            return cap_runner.run_cap_parse(
                self.database, "x.cap", True, "label",
                "wlan", per_pkt, **kwargs)

    def test_clean_run_with_finalize(self):
        errors = self._run(lambda cursor, pkt: 0, ["pkt1", "pkt2"],
                           finalize=lambda cursor: 0)
        self.assertEqual(errors, 0)
        self.database.commit.assert_called_once()

    def test_per_packet_errors_are_counted(self):
        # With catch_pkt_errors each failing packet is skipped and counted.
        def per_pkt(cursor, pkt):
            raise ValueError("bad packet")
        self.assertEqual(self._run(per_pkt, ["pkt1", "pkt2"]), 2)
        self.database.commit.assert_called_once()

    def test_per_packet_error_fatal_without_catch(self):
        # Without catch_pkt_errors the first failure aborts the whole parse.
        def per_pkt(cursor, pkt):
            raise ValueError("bad packet")
        errors = self._run(per_pkt, ["pkt1", "pkt2"],
                           catch_pkt_errors=False)
        self.assertEqual(errors, 1)
        self.database.commit.assert_not_called()

    def test_tshark_crash(self):
        crash = cap_runner.pyshark.capture.capture.TSharkCrashException(
            "cut short")
        with mock.patch.object(cap_runner.pyshark, "FileCapture",
                               side_effect=crash):
            errors = cap_runner.run_cap_parse(
                self.database, "x.cap", False, "label",
                "wlan", lambda cursor, pkt: 0)
        self.assertEqual(errors, 1)


class TestOui(unittest.TestCase):
    def test_redownload_success(self):
        # Force the "no cached file" branch; the downloaded bytes land in the
        # temp file and copyfile is patched so the repo CSV stays untouched.
        response = mock.Mock(content=b"Mac Prefix,Vendor\n00:00:01,Test\n")
        with mock.patch("utils.oui.os.path.exists", return_value=False), \
                mock.patch("requests.get", return_value=response), \
                mock.patch("utils.oui.copyfile") as copy:
            vendors = oui.load_vendors()
        copy.assert_called_once()
        self.assertTrue(vendors)

    def test_redownload_network_error(self):
        # Download failure is swallowed and the shipped CSV is used instead.
        with mock.patch("utils.oui.os.path.exists", return_value=False), \
                mock.patch("requests.get",
                           side_effect=requests.exceptions.RequestException(
                               "offline")), \
                mock.patch("utils.oui.copyfile") as copy:
            vendors = oui.load_vendors()
        copy.assert_not_called()
        self.assertTrue(vendors)

    def test_get_vendor_prefix_walk(self):
        # The lookup shortens the MAC until a prefix matches; verbose prints
        # each attempt.
        vendors = {"001122": "TestVendor"}
        self.assertEqual(
            oui.get_vendor(vendors, "00:11:22:33:44:55", True),
            "TestVendor")
        self.assertEqual(oui.get_vendor({}, "00:11:22:33:44:55", True),
                         "Unknown")


class TestAsyncioShim(unittest.TestCase):
    # The child-watcher names install() checks for and shims when absent
    # (removed in Python 3.14; still present, deprecated, on 3.12).
    _NAMES = ("get_child_watcher", "set_child_watcher",
              "AbstractChildWatcher", "SafeChildWatcher",
              "ThreadedChildWatcher", "FastChildWatcher",
              "PidfdChildWatcher", "MultiLoopChildWatcher")

    def test_null_child_watcher_api(self):
        watcher = asyncio_shim._NullChildWatcher()
        watcher.attach_loop(None)
        watcher.add_child_handler(123, lambda: None)
        self.assertTrue(watcher.remove_child_handler(123))
        self.assertTrue(watcher.is_active())
        with watcher as entered:
            self.assertIs(entered, watcher)
        watcher.close()

    def test_install_fills_missing_names(self):
        # Simulate Python 3.14 by removing the attributes, then check
        # install() puts working shims in place. Originals are restored.
        saved = {name: getattr(asyncio, name) for name in self._NAMES
                 if hasattr(asyncio, name)}
        try:
            for name in saved:
                delattr(asyncio, name)
            asyncio_shim.install()
            for name in self._NAMES:
                self.assertTrue(hasattr(asyncio, name), name)
            self.assertIs(asyncio.get_child_watcher(),
                          asyncio_shim._NULL_CHILD_WATCHER)
            self.assertIsNone(asyncio.set_child_watcher(None))
        finally:
            for name, value in saved.items():
                setattr(asyncio, name, value)

    def test_install_idempotent(self):
        # With every name present install() must change nothing.
        before = {name: getattr(asyncio, name) for name in self._NAMES
                  if hasattr(asyncio, name)}
        asyncio_shim.install()
        for name, value in before.items():
            self.assertIs(getattr(asyncio, name), value, name)


if __name__ == "__main__":
    unittest.main()
