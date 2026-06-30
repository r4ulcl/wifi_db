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


def check_for_update(version):
    repo_url = "https://api.github.com/repos/r4ulcl/wifi_db"
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)

    if not is_git_installed():
        print("Git is not installed on your system. Please install Git.")
        return
        # sys.exit(1)

    if not is_git_repo():
        print("The program is not in a Git folder. \
               Update manually from GitHub.")
        return

    latest_release_tag = get_latest_github_release(repo_url)

    if latest_release_tag:
        # Get only the number part, without v and -dev
        latest_match = re.search(r'(\d+(\.\d+)+)', latest_release_tag)
        current_match = re.search(r'(\d+(\.\d+)+)', version)
        if not latest_match or not current_match:
            print("Unable to parse version numbers.")
            return
        latest_release_tag_number = latest_match.group(1)
        current_number = current_match.group(1)
        # print(latest_release_tag_number)
        # print(current_number)

        # Compare as tuples of ints so 1.10.0 > 1.6.0 (not string compare)
        def _version_tuple(version):
            return tuple(int(part) for part in version.split('.'))

        latest_version = _version_tuple(latest_release_tag_number)
        current_version = _version_tuple(current_number)

        if latest_version > current_version:
            user_choice = input("A new version is available (v" +
                                latest_release_tag_number +
                                "). Do you want to update (Y/n)?: "
                                ).strip().lower() or "y"
            if user_choice in ("", "y", "Y"):
                print("Updating...")
                # Fixed command, absolute path, no shell or user input.
                update_process = subprocess.Popen(["/usr/bin/git", "pull"],
                                                  cwd=script_dir)  # nosec B603
                # Wait for the Git pull operation to complete
                update_process.wait()
                # Install dependencies
                requirements_file = "requirements.txt"
                # Install required packages using pip
                install_process = subprocess.Popen(  # nosec B603
                    ["/usr/bin/python3", "-m", "pip", "install", "-r",
                     requirements_file])
                install_process.wait()  # Wait for the installation

                print("Update complete. Please run again the script.")
                sys.exit()
            else:
                print("You chose not to update. Running the current version.")
        elif latest_version < current_version:
            print("You are using a future/dev version ;) ("+version+").\n")
        else:
            print("You are using the latest version ("+version+").\n")
    else:
        print("Unable to check for updates.")


if __name__ == "__main__":
    VERSION = 'v1.2'

    check_for_update(VERSION)
