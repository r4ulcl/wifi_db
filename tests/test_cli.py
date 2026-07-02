'''Tests for the wifi_db.py CLI plumbing: argument parsing, tool detection,
capture-file discovery/dispatch and main() itself.

The capture parsers themselves are exercised by test_parsers/test_realdata;
here they are patched out so the tests only drive the wiring around them.
Network-touching pieces (update check, vendor download) are patched too.'''
import os
import tempfile
import unittest
from unittest import mock

from utils import database_utils
import wifi_db


def _make_ctx(database=None, verbose=False, force=False):
    '''A Context with harmless defaults for tests that never parse.'''
    return wifi_db.Context(ouiMap={}, database=database, verbose=verbose,
                           fake_lat="", fake_lon="", hcxpcapngtool=False,
                           tshark=False, force=force)


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


class TestCaptureDiscovery(unittest.TestCase):
    def test_collect_capture_files(self):
        with tempfile.TemporaryDirectory() as folder:
            names = ["a.cap", "b.csv", "c.kismet.csv", "d.kismet.netxml",
                     "e.log.csv", "readme.txt"]
            for name in names:
                open(os.path.join(folder, name), "w").close()
            files = wifi_db.collect_capture_files(folder)
        self.assertNotIn("readme.txt", files)
        self.assertEqual(sorted(files), sorted(names[:-1]))
        # Reverse-sorted so the .cap files end up processed last.
        self.assertEqual(files[-1], "a.cap")

    def test_process_folder_absolute(self):
        ctx = _make_ctx(verbose=True)
        with tempfile.TemporaryDirectory() as folder:
            open(os.path.join(folder, "one.csv"), "w").close()
            open(os.path.join(folder, "two.csv"), "w").close()
            with mock.patch("wifi_db.process_capture") as process:
                wifi_db.process_folder(ctx, folder)
        self.assertEqual(process.call_count, 2)

    def test_process_folder_relative(self):
        ctx = _make_ctx()
        with tempfile.TemporaryDirectory() as folder:
            open(os.path.join(folder, "one.csv"), "w").close()
            parent, name = os.path.split(folder)
            with mock.patch("wifi_db.os.getcwd", return_value=parent), \
                    mock.patch("wifi_db.process_capture") as process:
                wifi_db.process_folder(ctx, name)
        process.assert_called_once_with(
            ctx, os.path.join(parent, name, "one.csv"))


class TestHandleCapture(unittest.TestCase):
    def test_aircrack_folder(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch("wifi_db.process_folder") as process:
            wifi_db.handle_capture(_make_ctx(), folder, "aircrack-ng")
        process.assert_called_once()

    def test_aircrack_file(self):
        with mock.patch("wifi_db.process_capture") as process:
            wifi_db.handle_capture(_make_ctx(), "some.csv", "aircrack-ng")
        process.assert_called_once()

    def test_kismet_and_wigle_are_stubs(self):
        # Both sources are TODO: they must not touch the parse pipeline.
        with mock.patch("wifi_db.process_capture") as process, \
                mock.patch("wifi_db.process_folder") as folder:
            wifi_db.handle_capture(_make_ctx(), "x", "kismet")
            wifi_db.handle_capture(_make_ctx(), "x", "wigle")
        process.assert_not_called()
        folder.assert_not_called()


class TestIngestAndProcess(unittest.TestCase):
    '''ingest_capture/process_capture against a real (temporary) database,
    with run_parser patched out so no capture file is actually parsed.'''

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        db_path = os.path.join(self.tmpdir.name, "test.db")
        self.database = database_utils.connectDatabase(db_path, False)
        database_utils.createDatabase(self.database, False)
        self.ctx = _make_ctx(database=self.database)

    def tearDown(self):
        self.database.close()
        self.tmpdir.cleanup()

    def _capture_file(self, name):
        '''Create a real capture file: ingest_capture MD5-hashes its path.'''
        path = os.path.join(self.tmpdir.name, name)
        with open(path, "w") as handle:
            handle.write("data\n")
        return path

    def test_run_parser_unknown_name(self):
        # Unknown parser names dispatch to nothing (and must not raise).
        wifi_db.run_parser(self.ctx, "no-such-parser", "x.csv")

    def test_ingest_capture_marks_processed(self):
        capture = self._capture_file("a.csv")
        with mock.patch("wifi_db.run_parser") as parser:
            wifi_db.ingest_capture(self.ctx, "csv", capture, announce=True)
        parser.assert_called_once()
        cursor = self.database.cursor()
        self.assertEqual(database_utils.checkFileProcessed(
            cursor, False, capture), 1)

    def test_ingest_capture_skips_processed(self):
        capture = self._capture_file("a.csv")
        with mock.patch("wifi_db.run_parser"):
            wifi_db.ingest_capture(self.ctx, "csv", capture)
        with mock.patch("wifi_db.run_parser") as parser:
            wifi_db.ingest_capture(self.ctx, "csv", capture)
        parser.assert_not_called()

    def test_ingest_capture_force_reprocesses(self):
        capture = self._capture_file("a.csv")
        with mock.patch("wifi_db.run_parser"):
            wifi_db.ingest_capture(self.ctx, "csv", capture)
        self.ctx.force = True
        with mock.patch("wifi_db.run_parser") as parser:
            wifi_db.ingest_capture(self.ctx, "csv", capture)
        parser.assert_called_once()

    def test_process_capture_known_extension(self):
        with mock.patch("wifi_db.ingest_capture") as ingest:
            wifi_db.process_capture(self.ctx, "sample.kismet.netxml")
        ingest.assert_called_once_with(self.ctx, "netxml",
                                       "sample.kismet.netxml")

    def test_process_capture_skips_processed(self):
        capture = self._capture_file("b.csv")
        with mock.patch("wifi_db.run_parser"):
            wifi_db.ingest_capture(self.ctx, "csv", capture)
        with mock.patch("wifi_db.ingest_capture") as ingest:
            wifi_db.process_capture(self.ctx, capture)
        ingest.assert_not_called()

    def test_process_capture_fallback_formats(self):
        # No recognised extension: every fallback suffix is attempted (and a
        # trailing "." is stripped first).
        with mock.patch("wifi_db.ingest_capture") as ingest:
            wifi_db.process_capture(self.ctx, "noext.")
        suffixes = [call.args[2] for call in ingest.call_args_list]
        self.assertEqual(len(suffixes), len(wifi_db.FALLBACK_FORMATS))
        for suffix, _name in wifi_db.FALLBACK_FORMATS:
            self.assertIn("noext" + suffix, suffixes)


class TestMain(unittest.TestCase):
    '''main() end to end with a real temporary database and an (empty)
    capture folder; the update check and vendor download are patched out.'''

    def _run_main(self, argv):
        with mock.patch("wifi_db.sys.argv", ["wifi_db.py"] + argv), \
                mock.patch("wifi_db.update.check_for_update"), \
                mock.patch("wifi_db.oui.load_vendors", return_value={}), \
                mock.patch("wifi_db.detect_tools",
                           return_value=(False, False)):
            wifi_db.main()

    def test_version_exits(self):
        with self.assertRaises(SystemExit):
            self._run_main(["--version"])

    def test_missing_capture_exits(self):
        with self.assertRaises(SystemExit):
            self._run_main([])

    def test_full_run(self):
        with tempfile.TemporaryDirectory() as workdir:
            db_path = os.path.join(workdir, "out.db")
            captures = os.path.join(workdir, "captures")
            os.mkdir(captures)
            # Trailing slash and doubled slash both get normalised.
            self._run_main(["--debug", "-o", "-d", db_path,
                            captures + "//"])
            self.assertTrue(os.path.exists(db_path))


if __name__ == "__main__":
    unittest.main()
