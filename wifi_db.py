#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-

import argparse
import os
from os import path
import platform
import subprocess  # nosec B404 - only used with fixed, non-shell commands
import sys
import re
import nest_asyncio
from utils import wifi_db_aircrack
from utils import update
from utils import database_utils
from utils import oui


# import nest_asyncio ; nest_asyncio.apply() ->
# Fix RuntimeError: This event loop is already running

VERSION = '1.6.0'


def banner():
    print(r'''
           _   __  _             _  _
__      __(_) / _|(_)         __| || |__
\ \ /\ / /| || |_ | |        / _` || '_ \
 \ V  V / | ||  _|| |       | (_| || |_) |
  \_/\_/  |_||_|  |_| _____  \__,_||_.__/
                     |_____|
                               by r4ulcl
''')


def printVersion():
    print("wifi_db version:", VERSION)


def replace_multiple_slashes(string):
    return re.sub('/+', '/', string)


def build_arg_parser():
    '''Build and return the argparse parser for the CLI.'''
    parser = argparse.ArgumentParser()
    parser.add_argument("-V", "--version", help="write the wifi_db version",
                        action="store_true")
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("--debug", help="increase output verbosity to debug",
                        action="store_true")

    parser.add_argument("-o", "--obfuscated", help="""Obfuscate MAC and BSSID
                         with AA:BB:CC:XX:XX:XX-defghi
                         (WARNING: replace all database)""",
                        action="store_true")

    parser.add_argument("-f", "--force", help="""Force insert file even if the
                         file is already processed.""",
                        action="store_true")

    parser.add_argument("-t", "--lat", default='',
                        help="insert a fake lat in the new elements")
    parser.add_argument("-n", "--lon", default='',
                        help="insert a fake lon in the new elements")

    parser.add_argument('--source',
                        default='aircrack-ng',
                        nargs='?',
                        choices=['aircrack-ng', 'kismet', 'wigle'],
                        help='source from capture data (default: %(default)s)')

    parser.add_argument("-d", "--database", type=str, default='db.SQLITE',
                        help="output database, if exist append to the given"
                        " database (default name: %(default)s)")

    parser.add_argument("capture", type=str, nargs='*',
                        help="capture folder or file with extensions .csv, "
                        ".kismet.csv, .kismet.netxml, or .log.csv. If no "
                        "extension is provided, all types will be added. "
                        "This option supports the use of "
                        "wildcards (*) to select multiple files or folders.")
    return parser


def _tool_available(tool):
    '''Return True if `tool` is found on PATH via which/where.'''
    try:
        cmd = "where" if platform.system() == "Windows" else "which"
        # Fixed command (which/where) with a fixed argument, no shell.
        subprocess.call([cmd, tool])  # nosec B603
        return True
    except OSError as E:
        print("False", E)
        return False


def detect_tools():
    '''Detect the optional external tools used to enrich captures.'''
    hcxpcapngtool = _tool_available("hcxpcapngtool")
    tshark = _tool_available("tshark")
    return hcxpcapngtool, tshark


def _is_capture_file(file):
    '''Return True if `file` has one of the recognised capture extensions.'''
    return (('.cap' in file) or ('.csv' in file)
            or ('.kismet.csv' in file)
            or ('kismet.netxml' in file)
            or ('.log.csv' in file))


def collect_capture_files(dir_capture):
    '''Return the recognised capture files in `dir_capture`, sorted reverse so
    the .cap files are processed last (by name and extension).'''
    files = [file for file in os.listdir(dir_capture)
             if _is_capture_file(file)]
    # Sorted reverse to cap last by name and extension
    files.sort(key=os.path.splitext, reverse=True)
    return files


def process_folder(ouiMap, capture, database, verbose, fake_lat, fake_lon,
                   hcxpcapngtool, tshark, force):
    '''Parse every recognised capture file inside a folder.'''
    print("Parsing folder:", capture)
    dirpath = os.getcwd()
    if os.path.isabs(capture):
        dir_capture = capture
    else:
        dir_capture = dirpath + "/" + capture
    if verbose:
        print(dir_capture)
        print("current directory is : " + dirpath)

    files = collect_capture_files(dir_capture)
    print(files)

    counter = 0
    # for each file with correct format of folder ...
    for f in files:
        counter += 1
        print("File: " + str(counter) + " of " + str(len(files)))
        capture_aux = dir_capture + "/" + f
        print("\n" + capture_aux)
        process_capture(ouiMap, capture_aux, database,
                        verbose, fake_lat, fake_lon,
                        hcxpcapngtool, tshark, force)


def handle_capture(ouiMap, capture, source, database, verbose, fake_lat,
                   fake_lon, hcxpcapngtool, tshark, force):
    '''Process a single capture path according to the selected source.'''
    if source == "aircrack-ng":
        # If it is a folder...
        if path.isdir(capture):
            process_folder(ouiMap, capture, database, verbose,
                           fake_lat, fake_lon, hcxpcapngtool, tshark, force)
        else:  # it is a file
            print("Parsing file:", capture)
            process_capture(ouiMap, capture, database,
                            verbose, fake_lat, fake_lon,
                            hcxpcapngtool, tshark, force)
    elif source == "kismet":
        print("Parsing Kismet capture")
        # TO DO
    else:
        print("Parsing Wigle capture")
        # TO DO


def main():
    '''Function main. Parse argument and exec the functions '''
    nest_asyncio.apply()

    # Check for update
    update.check_for_update(VERSION)

    # args
    parser = build_arg_parser()
    args = parser.parse_args()

    if args.version:
        printVersion()
        sys.exit()

    if not args.capture:
        print("wifi_db.py: error: the following arguments"
              + " are required: capture")
        sys.exit()

    # vars
    # version = args.version
    verbose = args.verbose
    debug = args.debug
    obfuscated = args.obfuscated
    force = args.force

    hcxpcapngtool, tshark = detect_tools()

    name = args.database
    captures = args.capture
    source = args.source

    fake_lat = args.lat
    fake_lon = args.lon

    print(captures)

    if verbose:
        print("verbosity turned on")

    if debug:
        verbose = True
        print("debug turned on")

    database = database_utils.connectDatabase(name, verbose)
    database_utils.createDatabase(database, verbose)
    database_utils.createViews(database, verbose)

    ouiMap = oui.load_vendors()

    for capture in captures:
        # Remove the trailing forward slash, if it exists
        if capture.endswith('/'):
            capture = capture[:-1]
        capture = replace_multiple_slashes(capture)

        handle_capture(ouiMap, capture, source, database, verbose,
                       fake_lat, fake_lon, hcxpcapngtool, tshark, force)

    # Cleat whitelist MACs
    script_path = os.path.dirname(os.path.abspath(__file__))
    database_utils.clearWhitelist(
        database, verbose, script_path + '/whitelist.txt')

    # if obfuscated
    if obfuscated:
        print("-o is enable, so obfuscate. This may take a while")
        database_utils.obfuscateDB(database, verbose)

    print("\nThe output database is in the file:", name)
    print("Use 'sqlitebrowser " + name
          + "' or other SQLITE program to view the data")


# (extension substring, parser name). Order matters: most specific first.
CAPTURE_FORMATS = [
    (".cap", "cap"),
    (".kismet.netxml", "netxml"),
    (".kismet.csv", "kismet_csv"),
    (".log.csv", "log_csv"),
    (".csv", "csv"),
]

# Order tried when the given path has no recognised extension (a suffix is
# appended to the path for each one).
FALLBACK_FORMATS = [
    (".kismet.netxml", "netxml"),
    (".kismet.csv", "kismet_csv"),
    (".csv", "csv"),
    (".log.csv", "log_csv"),
    (".cap", "cap"),
]


def run_parser(name, ouiMap, capture, database, verbose, fake_lat, fake_lon,
               hcxpcapngtool, tshark):
    '''Dispatch to the parser identified by `name`.'''
    if name == "cap":
        wifi_db_aircrack.parse_cap(capture, database, verbose,
                                   hcxpcapngtool, tshark)
    elif name == "netxml":
        wifi_db_aircrack.parse_netxml(ouiMap, capture, database, verbose)
    elif name == "kismet_csv":
        wifi_db_aircrack.parse_kismet_csv(ouiMap, capture, database, verbose)
    elif name == "log_csv":
        wifi_db_aircrack.parse_log_csv(ouiMap, capture, database, verbose,
                                       fake_lat, fake_lon)
    elif name == "csv":
        wifi_db_aircrack.parse_csv(ouiMap, capture, database, verbose)


def ingest_capture(name, ouiMap, capture, database, verbose, fake_lat,
                   fake_lon, hcxpcapngtool, tshark, force, announce=False):
    '''Insert, parse and mark a single capture file as processed (skipping it
    if it was already processed and --force was not given).'''
    cursor = database.cursor()
    if announce:
        print("Parsing file:", capture)
    if (database_utils.checkFileProcessed(cursor, verbose, capture) == 1
            and not force):
        print("File", "already processed\n")
        return
    database_utils.insertFile(cursor, verbose, capture)
    run_parser(name, ouiMap, capture, database, verbose, fake_lat, fake_lon,
               hcxpcapngtool, tshark)
    database_utils.setFileProcessed(cursor, verbose, capture)


def process_capture(ouiMap, capture, database,
                    verbose, fake_lat, fake_lon,
                    hcxpcapngtool, tshark, force):
    cursor = database.cursor()

    if (database_utils.checkFileProcessed(cursor, verbose, capture) == 1
            and not force):
        print("File", "already processed\n")
        return

    for ext, name in CAPTURE_FORMATS:
        if ext in capture:
            ingest_capture(name, ouiMap, capture, database, verbose,
                           fake_lat, fake_lon, hcxpcapngtool, tshark, force)
            return

    # No recognised extension: try every known format by appending its suffix.
    print("Not format found!")
    if capture.endswith('.'):
        capture = capture[:-1]
    for suffix, name in FALLBACK_FORMATS:
        ingest_capture(name, ouiMap, capture + suffix, database, verbose,
                       fake_lat, fake_lon, hcxpcapngtool, tshark, force,
                       announce=True)


if __name__ == "__main__":
    banner()
    main()
