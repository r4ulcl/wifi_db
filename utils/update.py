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
    return latest_tuple, current_tuple, latest_number


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
    # Fixed command, absolute path, no shell or user input.
    update_process = subprocess.Popen(["/usr/bin/git", "pull"],
                                      cwd=script_dir)  # nosec B603
    # Wait for the Git pull operation to complete
    update_process.wait()
    # Install required packages using pip
    install_process = subprocess.Popen(  # nosec B603
        ["/usr/bin/python3", "-m", "pip", "install", "-r",
         "requirements.txt"])
    install_process.wait()  # Wait for the installation
    print("Update complete. Please run again the script.")
    sys.exit()


def check_for_update(version):
    repo_url = "https://api.github.com/repos/r4ulcl/wifi_db"
    script_dir = os.path.dirname(os.path.abspath(__file__))

    if not is_git_installed():
        print("Git is not installed on your system. Please install Git.")
        return

    if not is_git_repo():
        print("The program is not in a Git folder. \
               Update manually from GitHub.")
        return

    latest_release_tag = get_latest_github_release(repo_url)
    if not latest_release_tag:
        print("Unable to check for updates.")
        return

    parsed = _parse_versions(version, latest_release_tag)
    if parsed is None:
        print("Unable to parse version numbers.")
        return
    latest_version, current_version, latest_release_tag_number = parsed

    if latest_version > current_version:
        _prompt_and_update(script_dir, latest_release_tag_number)
    elif latest_version < current_version:
        print("You are using a future/dev version ;) ("+version+").\n")
    else:
        print("You are using the latest version ("+version+").\n")


if __name__ == "__main__":
    VERSION = 'v1.2'

    check_for_update(VERSION)
