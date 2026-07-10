'''Tests for utils/update.py (the GitHub self-update check).

Everything external is mocked: subprocess (git/pip), requests (GitHub API)
and input() (the update prompt), so the suite never touches the network or
mutates the checkout.'''
import subprocess
import unittest
from unittest import mock

import requests

from utils import update


class TestIsGitInstalled(unittest.TestCase):
    def test_git_present(self):
        with mock.patch("utils.update.subprocess.run") as run:
            run.return_value = mock.Mock(returncode=0)
            self.assertTrue(update.is_git_installed())

    def test_git_missing(self):
        with mock.patch("utils.update.subprocess.run",
                        side_effect=FileNotFoundError):
            self.assertFalse(update.is_git_installed())

    def test_git_broken(self):
        error = subprocess.CalledProcessError(1, "git")
        with mock.patch("utils.update.subprocess.run", side_effect=error):
            self.assertFalse(update.is_git_installed())


class TestGetLatestGithubRelease(unittest.TestCase):
    URL = "https://api.github.com/repos/r4ulcl/wifi_db"

    def test_ok(self):
        response = mock.Mock(status_code=200)
        response.json.return_value = {"tag_name": "v1.9"}
        with mock.patch("utils.update.requests.get", return_value=response):
            self.assertEqual(update.get_latest_github_release(self.URL),
                             "v1.9")

    def test_http_error_status(self):
        response = mock.Mock(status_code=404)
        with mock.patch("utils.update.requests.get", return_value=response):
            self.assertIsNone(update.get_latest_github_release(self.URL))

    def test_network_error(self):
        with mock.patch("utils.update.requests.get",
                        side_effect=requests.RequestException("offline")):
            self.assertIsNone(update.get_latest_github_release(self.URL))

    def test_malformed_json(self):
        # 200 whose JSON lacks "tag_name": the KeyError is swallowed too.
        response = mock.Mock(status_code=200)
        response.json.return_value = {}
        with mock.patch("utils.update.requests.get", return_value=response):
            self.assertIsNone(update.get_latest_github_release(self.URL))


class TestIsGitRepo(unittest.TestCase):
    def test_both_answers(self):
        for exists in (True, False):
            with mock.patch("utils.update.os.path.exists",
                            return_value=exists):
                self.assertEqual(update.is_git_repo(), exists)


class TestParseVersions(unittest.TestCase):
    def test_numeric_compare(self):
        # 1.10.0 must beat 1.6.0: tuples of ints, not a string compare.
        parsed = update._parse_versions("v1.6.0", "v1.10.0")
        self.assertEqual(parsed, ((1, 10, 0), (1, 6, 0), "1.10.0"))
        self.assertGreater(parsed[0], parsed[1])

    def test_unparseable(self):
        self.assertIsNone(update._parse_versions("nonsense", "v1.2"))
        self.assertIsNone(update._parse_versions("v1.2", "nonsense"))

    def test_padding_equal_precision(self):
        # The "1.6.0" build and the "v1.6" release tag are the same version:
        # the shorter tuple is zero-padded so they compare equal instead of
        # (1, 6) < (1, 6, 0) making the build look newer than the release.
        parsed = update._parse_versions("1.6.0", "v1.6")
        self.assertEqual(parsed, ((1, 6, 0), (1, 6, 0), "1.6"))
        self.assertEqual(parsed[0], parsed[1])


class TestPromptAndUpdate(unittest.TestCase):
    def test_decline(self):
        # "n" answers the prompt: no subprocess runs and no exit.
        with mock.patch("builtins.input", return_value="n"), \
                mock.patch("utils.update.subprocess.Popen") as popen:
            update._prompt_and_update("/repo", "1.9")
        popen.assert_not_called()

    def test_accept(self):
        # Empty answer defaults to yes: git pull (checkout + pull, via run)
        # then pip install (via Popen), then exit.
        with mock.patch("builtins.input", return_value=""), \
                mock.patch("utils.update.subprocess.run") as run, \
                mock.patch("utils.update.subprocess.Popen") as popen:
            popen.return_value = mock.Mock(wait=mock.Mock(return_value=0))
            with self.assertRaises(SystemExit):
                update._prompt_and_update("/repo/utils", "1.9")
        self.assertEqual(run.call_count, 2)
        self.assertEqual(popen.call_count, 1)


class TestGitPull(unittest.TestCase):
    def test_discards_csv_then_pulls_with_autostash(self):
        with mock.patch("utils.update.subprocess.run") as run:
            update._git_pull("/repo/utils")
        self.assertEqual(run.call_count, 2)
        checkout_cmd = run.call_args_list[0].args[0]
        pull_cmd = run.call_args_list[1].args[0]
        # First: discard the throwaway, always-dirty local OUI database so it
        # cannot block the pull.
        self.assertIn("checkout", checkout_cmd)
        self.assertTrue(
            any("mac-vendors-export.csv" in part for part in checkout_cmd))
        # Then: pull with autostash so any other stray local edit is shelved
        # across the pull instead of aborting it.
        self.assertIn("pull", pull_cmd)
        self.assertIn("rebase.autostash=true", pull_cmd)
        self.assertIn("merge.autostash=true", pull_cmd)


class TestCheckForUpdate(unittest.TestCase):
    '''Each early-return path of check_for_update, plus the three version
    comparison outcomes. The helpers it calls are patched per test.'''

    def _run(self, version, installed=True, repo=True, tag="v1.6.0"):
        with mock.patch("utils.update.is_docker", return_value=False), \
                mock.patch("utils.update.is_git_installed",
                           return_value=installed), \
                mock.patch("utils.update.is_git_repo", return_value=repo), \
                mock.patch("utils.update.get_latest_github_release",
                           return_value=tag), \
                mock.patch("utils.update._prompt_and_update") as prompt:
            update.check_for_update(version)
        return prompt

    def test_no_git(self):
        prompt = self._run("v1.0", installed=False)
        prompt.assert_not_called()

    def test_not_a_repo(self):
        prompt = self._run("v1.0", repo=False)
        prompt.assert_not_called()

    def test_no_release_info(self):
        prompt = self._run("v1.0", tag=None)
        prompt.assert_not_called()

    def test_unparseable_versions(self):
        prompt = self._run("nonsense", tag="alsononsense")
        prompt.assert_not_called()

    def test_newer_available(self):
        prompt = self._run("v1.0", tag="v1.6.0")
        prompt.assert_called_once()

    def test_dev_version(self):
        prompt = self._run("v9.9", tag="v1.6.0")
        prompt.assert_not_called()

    def test_up_to_date(self):
        prompt = self._run("v1.6.0", tag="v1.6.0")
        prompt.assert_not_called()

    def test_up_to_date_mixed_precision(self):
        # Regression: a "1.6.0" build against the "v1.6" release tag is up to
        # date, not a "future/dev version" and not an available update.
        prompt = self._run("1.6.0", tag="v1.6")
        prompt.assert_not_called()


class TestIsDocker(unittest.TestCase):
    '''is_docker() honours the WIFI_DB_DOCKER env var and the /.dockerenv
    marker, and is False when neither is present.'''

    def test_env_var(self):
        with mock.patch.dict("utils.update.os.environ",
                             {"WIFI_DB_DOCKER": "1"}):
            self.assertTrue(update.is_docker())

    def test_dockerenv_marker(self):
        with mock.patch.dict("utils.update.os.environ", {}, clear=True), \
                mock.patch("utils.update.os.path.exists", return_value=True):
            self.assertTrue(update.is_docker())

    def test_not_docker(self):
        with mock.patch.dict("utils.update.os.environ", {}, clear=True), \
                mock.patch("utils.update.os.path.exists", return_value=False):
            self.assertFalse(update.is_docker())


class TestCheckDockerUpdate(unittest.TestCase):
    '''In Docker, check_for_update skips the git paths and, when a newer
    release exists, prints the docker pull instructions instead of prompting to
    git pull.'''

    def _run(self, version, tag="v1.6.0"):
        with mock.patch("utils.update.is_docker", return_value=True), \
                mock.patch("utils.update.get_latest_github_release",
                           return_value=tag), \
                mock.patch("utils.update._prompt_and_update") as prompt, \
                mock.patch("builtins.print") as printed:
            update.check_for_update(version)
        return prompt, printed

    def test_newer_available_says_docker_pull(self):
        prompt, printed = self._run("v1.0", tag="v1.6.0")
        prompt.assert_not_called()
        output = " ".join(str(c.args[0]) for c in printed.call_args_list
                          if c.args)
        self.assertIn("docker pull r4ulcl/wifi_db:latest", output)

    def test_up_to_date(self):
        prompt, printed = self._run("v1.6.0", tag="v1.6.0")
        prompt.assert_not_called()
        output = " ".join(str(c.args[0]) for c in printed.call_args_list
                          if c.args)
        self.assertIn("latest version", output)


if __name__ == "__main__":
    unittest.main()
