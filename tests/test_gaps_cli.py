'''Coverage for the remaining wifi_db.main() branch combinations (verbose on,
debug off, a capture path without a trailing slash, obfuscation off) and the
capture_pipeline fallback path when the given name has no trailing dot.'''
import os
import tempfile
import unittest
from unittest import mock

from utils import capture_pipeline

from test_base import run_main


class TestMainBranches(unittest.TestCase):
    def test_verbose_no_debug_no_obfuscate_no_trailing_slash(self):
        with tempfile.TemporaryDirectory() as workdir:
            db_path = os.path.join(workdir, "out.db")
            captures = os.path.join(workdir, "captures")
            os.mkdir(captures)
            # -v (verbose) without --debug, without -o, and a capture path that
            # does not end in '/': the complementary branch of every guard the
            # existing --debug/-o/trailing-slash test takes.
            run_main(["-v", "-d", db_path, captures])
            self.assertTrue(os.path.exists(db_path))


class TestCapturePipelineFallback(unittest.TestCase):
    def test_process_capture_fallback_without_trailing_dot(self):
        ctx = capture_pipeline.Context(
            ouiMap={}, database=mock.Mock(), verbose=False, fake_lat="",
            fake_lon="", hcxpcapngtool=False, tshark=False, force=False)
        ctx.database.cursor.return_value = mock.Mock()
        with mock.patch("utils.capture_pipeline.ingest_capture") as ingest, \
                mock.patch("utils.capture_pipeline.database_utils."
                           "checkFileProcessed", return_value=0):
            # "noext" has no recognised extension and no trailing '.', so the
            # dot-stripping branch is skipped and every fallback suffix tried.
            capture_pipeline.process_capture(ctx, "noext")
        suffixes = [call.args[2] for call in ingest.call_args_list]
        for suffix, _name in capture_pipeline.FALLBACK_FORMATS:
            self.assertIn("noext" + suffix, suffixes)


if __name__ == '__main__':
    unittest.main()
