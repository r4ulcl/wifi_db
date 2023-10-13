import os
import sys
import subprocess
import requests
import re


def is_git_installed():
    try:
        subprocess.run(["/usr/bin/git", "--version"], stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, check=True)
        return True
    except FileNotFoundError:
        return False
    except subprocess.CalledProcessError:
        return False


def get_latest_github_release(repo_url):
    try:
        response = requests.get(f"{repo_url}/releases/latest")
        if response.status_code == 200:
            latest_release_tag = response.json()["tag_name"]
            return latest_release_tag
        else:
            return None
    except Exception as e:
        print(e)
        return None


def check_for_update(VERSION):
    repo_url = "https://api.github.com/repos/r4ulcl/wifi_db"
    script_path = os.path.abspath(__file__)
    script_dir = os.path.dirname(script_path)

    if not is_git_installed():
        print("Git is not installed on your system. Please install Git.")
        sys.exit(1)

    latest_release_tag = get_latest_github_release(repo_url)

    if latest_release_tag:
        # Get only the number part, without v and -dev
        latest_release_tag_number = re.search(r'(\d+(\.\d+)+)',
                                              latest_release_tag).group(1)
        current_number = re.search(r'(\d+(\.\d+)+)', VERSION).group(1)
        # print(latest_release_tag_number)
        # print(current_number)
        if latest_release_tag_number > current_number:
            user_choice = input("A new version is available (v" +
                                latest_release_tag_number +
                                "). Do you want to update (Y/n)?: "
                                ).strip().lower() or "y"
            if user_choice in ("", "y", "Y"):
                print("Updating...")
                update_process = subprocess.Popen(["/usr/bin/git", "pull"],
                                                  cwd=script_dir)
                # Wait for the Git pull operation to complete
                update_process.wait()
                print("Update complete. Please run again the script.")
                sys.exit()
            else:
                print("You chose not to update. Running the current version.")
        elif latest_release_tag_number < current_number:
            print("You are using a future version ;) ("+VERSION+").\n")
        else:
            print("You are using the latest version ("+VERSION+").\n")
    else:
        print("Unable to check for updates.")


if __name__ == "__main__":
    VERSION = 'v1.2'

    check_for_update(VERSION)
