'''Tests for the capture ingestion pipeline in utils/capture_pipeline.py:
file discovery, folder walking, source handling and the
insert/parse/mark-processed dispatch.

The capture parsers themselves are exercised by test_parsers/test_realdata;
here they are patched out so the tests only drive the wiring around them.'''
import os
import tempfile
import unittest
from unittest import mock

from utils import capture_pipeline
from utils import database_utils


def _make_ctx(database=None, verbose=False, force=False):
    '''A Context with harmless defaults for tests that never parse.'''
    return capture_pipeline.Context(
        ouiMap={}, database=database, verbose=verbose, fake_lat="",
        fake_lon="", hcxpcapngtool=False, tshark=False, force=force)


class TestCaptureDiscovery(unittest.TestCase):
    def test_collect_capture_files(self):
        with tempfile.TemporaryDirectory() as folder:
            names = ["a.cap", "b.csv", "c.kismet.csv", "d.kismet.netxml",
                     "e.log.csv", "readme.txt"]
            for name in names:
                open(os.path.join(folder, name), "w").close()
            files = capture_pipeline.collect_capture_files(folder)
        self.assertNotIn("readme.txt", files)
        self.assertEqual(sorted(files), sorted(names[:-1]))
        # Reverse-sorted so the .cap files end up processed last.
        self.assertEqual(files[-1], "a.cap")

    def test_process_folder_absolute(self):
        ctx = _make_ctx(verbose=True)
        with tempfile.TemporaryDirectory() as folder:
            open(os.path.join(folder, "one.csv"), "w").close()
            open(os.path.join(folder, "two.csv"), "w").close()
            with mock.patch(
                    "utils.capture_pipeline.process_capture") as process:
                capture_pipeline.process_folder(ctx, folder)
        self.assertEqual(process.call_count, 2)

    def test_process_folder_relative(self):
        ctx = _make_ctx()
        with tempfile.TemporaryDirectory() as folder:
            open(os.path.join(folder, "one.csv"), "w").close()
            parent, name = os.path.split(folder)
            with mock.patch("utils.capture_pipeline.os.getcwd",
                            return_value=parent), \
                    mock.patch(
                        "utils.capture_pipeline.process_capture") as process:
                capture_pipeline.process_folder(ctx, name)
        process.assert_called_once_with(
            ctx, os.path.join(parent, name, "one.csv"))


class TestHandleCapture(unittest.TestCase):
    def test_aircrack_folder(self):
        with tempfile.TemporaryDirectory() as folder, \
                mock.patch("utils.capture_pipeline.process_folder") as process:
            capture_pipeline.handle_capture(_make_ctx(), folder, "aircrack-ng")
        process.assert_called_once()

    def test_aircrack_file(self):
        with mock.patch(
                "utils.capture_pipeline.process_capture") as process:
            capture_pipeline.handle_capture(
                _make_ctx(), "some.csv", "aircrack-ng")
        process.assert_called_once()

    def test_kismet_and_wigle_are_stubs(self):
        # Both sources are TODO: they must not touch the parse pipeline.
        with mock.patch("utils.capture_pipeline.process_capture") as process, \
                mock.patch("utils.capture_pipeline.process_folder") as folder:
            capture_pipeline.handle_capture(_make_ctx(), "x", "kismet")
            capture_pipeline.handle_capture(_make_ctx(), "x", "wigle")
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
        capture_pipeline.run_parser(self.ctx, "no-such-parser", "x.csv")

    def test_ingest_capture_marks_processed(self):
        capture = self._capture_file("a.csv")
        with mock.patch("utils.capture_pipeline.run_parser") as parser:
            capture_pipeline.ingest_capture(
                self.ctx, "csv", capture, announce=True)
        parser.assert_called_once()
        cursor = self.database.cursor()
        self.assertEqual(database_utils.checkFileProcessed(
            cursor, False, capture), 1)

    def test_ingest_capture_skips_processed(self):
        capture = self._capture_file("a.csv")
        with mock.patch("utils.capture_pipeline.run_parser"):
            capture_pipeline.ingest_capture(self.ctx, "csv", capture)
        with mock.patch("utils.capture_pipeline.run_parser") as parser:
            capture_pipeline.ingest_capture(self.ctx, "csv", capture)
        parser.assert_not_called()

    def test_ingest_capture_force_reprocesses(self):
        capture = self._capture_file("a.csv")
        with mock.patch("utils.capture_pipeline.run_parser"):
            capture_pipeline.ingest_capture(self.ctx, "csv", capture)
        self.ctx.force = True
        with mock.patch("utils.capture_pipeline.run_parser") as parser:
            capture_pipeline.ingest_capture(self.ctx, "csv", capture)
        parser.assert_called_once()

    def test_process_capture_known_extension(self):
        with mock.patch("utils.capture_pipeline.ingest_capture") as ingest:
            capture_pipeline.process_capture(self.ctx, "sample.kismet.netxml")
        ingest.assert_called_once_with(self.ctx, "netxml",
                                       "sample.kismet.netxml")

    def test_process_capture_skips_processed(self):
        capture = self._capture_file("b.csv")
        with mock.patch("utils.capture_pipeline.run_parser"):
            capture_pipeline.ingest_capture(self.ctx, "csv", capture)
        with mock.patch("utils.capture_pipeline.ingest_capture") as ingest:
            capture_pipeline.process_capture(self.ctx, capture)
        ingest.assert_not_called()

    def test_process_capture_fallback_formats(self):
        # No recognised extension: every fallback suffix is attempted (and a
        # trailing "." is stripped first).
        with mock.patch("utils.capture_pipeline.ingest_capture") as ingest:
            capture_pipeline.process_capture(self.ctx, "noext.")
        suffixes = [call.args[2] for call in ingest.call_args_list]
        self.assertEqual(len(suffixes), len(capture_pipeline.FALLBACK_FORMATS))
        for suffix, _name in capture_pipeline.FALLBACK_FORMATS:
            self.assertIn("noext" + suffix, suffixes)


if __name__ == "__main__":
    unittest.main()
