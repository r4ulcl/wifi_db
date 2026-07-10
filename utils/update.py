''' Check for and apply updates of wifi_db from GitHub '''
import os
import sys
import re
import subprocess  # nosec B404 - only used with fixed, absolute-path commands
import requests


def is_git_installed():
    try:
        # Fixed command with an absolute path and no shell or user input.
        subprocess.run(["/usr/bin/git", "--version"], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=True)  # nosec B603
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        return False


def get_latest_github_release(repo_url):
    try:
        # (connect, read) timeouts: a short connect timeout makes the check
        # bail out quickly when there is no internet access, while still
        # allowing a slightly longer read for slow connections.
        response = requests.get(f"{repo_url}/releases/latest",
                                timeout=(2, 5))
        if response.status_code == 200:
            latest_release_tag = response.json()["tag_name"]
            return latest_release_tag
        return None
    except (requests.RequestException, KeyError, ValueError) as e:
        # Network error, or a 200 response whose JSON is malformed or missing
        # the "tag_name" field: treat all of them as "no update info".
        print(e)
        return None


def is_docker():
    '''True when running inside the wifi_db Docker image.

    The Dockerfile sets WIFI_DB_DOCKER=1; fall back to the /.dockerenv marker
    Docker creates in every container, in case the image was built without the
    env var.'''
    if os.environ.get("WIFI_DB_DOCKER"):
        return True
    return os.path.exists("/.dockerenv")


# Check if the user downloaded the repo using git or the ZIP.
def is_git_repo():
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)
    # script_dir is utils
    path_git = script_dir + "/../.git"
    # check if folder .git exists, if yes git pull
    # if not download zip and replace all
    git_path_exists = os.path.exists(path_git)
    return git_path_exists


def _parse_versions(version, latest_release_tag):
    '''Return (latest_tuple, current_tuple, latest_number) for the two version
    strings, or None when either has no parseable d.d(.d) number. The tuples are
    compared as ints so 1.10.0 > 1.6.0 (not a string compare).'''
    latest_match = re.search(r'(\d+(\.\d+)+)', latest_release_tag)
    current_match = re.search(r'(\d+(\.\d+)+)', version)
    if not latest_match or not current_match:
        return None
    latest_number = latest_match.group(1)
    current_number = current_match.group(1)
    latest_tuple = tuple(int(part) for part in latest_number.split('.'))
    current_tuple = tuple(int(part) for part in current_number.split('.'))
    # Pad with trailing zeros so 1.6 and 1.6.0 compare equal.
    max_len = max(len(latest_tuple), len(current_tuple))
    latest_tuple += (0,) * (max_len - len(latest_tuple))
    current_tuple += (0,) * (max_len - len(current_tuple))
    return latest_tuple, current_tuple, latest_number


def _git_pull(script_dir):
    '''Pull the latest code, tolerating the always-dirty bundled OUI database.

    oui.load_vendors() overwrites the tracked mac-vendors-export.csv at
    runtime, so it is almost always modified and would block the pull. Discard
    that throwaway copy first, then pull with autostash for any other edits.'''
    csv_path = os.path.join(script_dir, "mac-vendors-export.csv")
    # nosec B603: fixed command, absolute paths, no shell or user input.
    subprocess.run(["/usr/bin/git", "checkout", "--", csv_path],  # nosec B603
                   cwd=script_dir, check=False)
    subprocess.run(["/usr/bin/git",  # nosec B603
                    "-c", "rebase.autostash=true",
                    "-c", "merge.autostash=true",
                    "pull"], cwd=script_dir, check=False)


def _prompt_and_update(script_dir, latest_release_tag_number):
    '''Ask the user and, on yes, git pull + pip install requirements, then exit.'''
    user_choice = input("A new version is available (v" +
                        latest_release_tag_number +
                        "). Do you want to update (Y/n)?: "
                        ).strip().lower() or "y"
    if user_choice not in ("", "y", "Y"):
        print("You chose not to update. Running the current version.")
        return
    print("Updating...")
    _git_pull(script_dir)
    # Install required packages using pip (requirements.txt is at repo root).
    repo_root = os.path.dirname(script_dir)
    install_process = subprocess.Popen(  # nosec B603
        ["/usr/bin/python3", "-m", "pip", "install", "-r",
         "requirements.txt"], cwd=repo_root)
    install_process.wait()  # Wait for the installation
    print("Update complete. Please run again the script.")
    sys.exit()


def _latest_release_status(version, repo_url):
    '''Compare the running version to the latest GitHub release.

    Returns (status, latest_number) where status is one of "update", "future"
    or "latest". Returns (None, None) after printing the reason when the latest
    release or either version number cannot be determined.'''
    latest_release_tag = get_latest_github_release(repo_url)
    if not latest_release_tag:
        print("Unable to check for updates.")
        return None, None

    parsed = _parse_versions(version, latest_release_tag)
    if parsed is None:
        print("Unable to parse version numbers.")
        return None, None
    latest_version, current_version, latest_number = parsed

    if latest_version > current_version:
        return "update", latest_number
    if latest_version < current_version:
        return "future", latest_number
    return "latest", latest_number


def _check_docker_update(version, repo_url):
    '''Version check for the Docker image. There is no git repo inside the
    container, so an old version is fixed by pulling a fresh image rather than
    git pull.'''
    status, latest_number = _latest_release_status(version, repo_url)
    if status == "update":
        print("A new version is available (v" + latest_number +
              "). You are running wifi_db in Docker; update the image with:")
        print("    docker pull r4ulcl/wifi_db:latest\n")
    elif status == "future":
        print("You are using a future/dev version ;) ("+version+").\n")
    elif status == "latest":
        print("You are using the latest version ("+version+").\n")


def check_for_update(version):
    repo_url = "https://api.github.com/repos/r4ulcl/wifi_db"
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if is_docker():
        _check_docker_update(version, repo_url)
        return

    if not is_git_installed():
        print("Git is not installed on your system. Please install Git.")
        return

    if not is_git_repo():
        print("The program is not in a Git folder. \
               Update manually from GitHub.")
        return

    status, latest_number = _latest_release_status(version, repo_url)
    if status == "update":
        _prompt_and_update(script_dir, latest_number)
    elif status == "future":
        print("You are using a future/dev version ;) ("+version+").\n")
    elif status == "latest":
        print("You are using the latest version ("+version+").\n")


if __name__ == "__main__":
    VERSION = 'v1.2'

    check_for_update(VERSION)
