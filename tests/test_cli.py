'''Tests for the wifi_db.py CLI plumbing: argument parsing, tool detection
and main() itself.

The capture pipeline main() drives (file discovery, dispatch, parsing) lives
in utils/capture_pipeline.py and is tested in test_capture_pipeline.py.
Network-touching pieces (update check, vendor download) are patched out here.'''
import os
import tempfile
import unittest
from unittest import mock

import wifi_db

from test_base import run_main


class TestSmallHelpers(unittest.TestCase):
    def test_banner_and_version(self):
        # Pure prints; just make sure they run.
        wifi_db.banner()
        wifi_db.printVersion()

    def test_replace_multiple_slashes(self):
        self.assertEqual(wifi_db.replace_multiple_slashes("/a//b///c"),
                         "/a/b/c")
        self.assertEqual(wifi_db.replace_multiple_slashes("a/b"), "a/b")

    def test_build_arg_parser(self):
        parser = wifi_db.build_arg_parser()
        args = parser.parse_args(["-v", "--debug", "-o", "-f",
                                  "-t", "1.0", "-n", "2.0",
                                  "--source", "kismet",
                                  "-d", "x.db", "cap1", "cap2"])
        self.assertTrue(args.verbose)
        self.assertTrue(args.debug)
        self.assertTrue(args.obfuscated)
        self.assertTrue(args.force)
        self.assertEqual(args.lat, "1.0")
        self.assertEqual(args.lon, "2.0")
        self.assertEqual(args.source, "kismet")
        self.assertEqual(args.database, "x.db")
        self.assertEqual(args.capture, ["cap1", "cap2"])


class TestToolDetection(unittest.TestCase):
    def test_tool_available(self):
        with mock.patch("wifi_db.subprocess.call", return_value=0):
            self.assertTrue(wifi_db._tool_available("sometool"))

    def test_tool_available_windows(self):
        # On Windows the lookup command is "where" instead of "which".
        with mock.patch("wifi_db.platform.system",
                        return_value="Windows"), \
                mock.patch("wifi_db.subprocess.call", return_value=0) as call:
            self.assertTrue(wifi_db._tool_available("sometool"))
        call.assert_called_once_with(["where", "sometool"])

    def test_tool_lookup_fails(self):
        with mock.patch("wifi_db.subprocess.call", side_effect=OSError):
            self.assertFalse(wifi_db._tool_available("sometool"))

    def test_detect_tools(self):
        with mock.patch("wifi_db._tool_available",
                        side_effect=[True, False]):
            self.assertEqual(wifi_db.detect_tools(), (True, False))


class TestMain(unittest.TestCase):
    '''main() end to end with a real temporary database and an (empty)
    capture folder; the update check and vendor download are patched out
    (see test_base.run_main).'''

    def test_version_exits(self):
        with self.assertRaises(SystemExit):
            run_main(["--version"])

    def test_missing_capture_exits(self):
        with self.assertRaises(SystemExit):
            run_main([])

    def test_full_run(self):
        with tempfile.TemporaryDirectory() as workdir:
            db_path = os.path.join(workdir, "out.db")
            captures = os.path.join(workdir, "captures")
            os.mkdir(captures)
            # Trailing slash and doubled slash both get normalised.
            run_main(["--debug", "-o", "-d", db_path, captures + "//"])
            self.assertTrue(os.path.exists(db_path))


if __name__ == "__main__":
    unittest.main()
