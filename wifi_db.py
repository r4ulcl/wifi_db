#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-

import argparse
import os
import platform
import subprocess  # nosec B404 - only used with fixed, non-shell commands
import sys
import re
import nest_asyncio
from utils import update
from utils import database_utils
from utils import oui
# The capture ingestion pipeline lives in utils/capture_pipeline.py; main()
# builds a Context and hands each capture path to handle_capture.
from utils.capture_pipeline import Context, handle_capture


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

    ctx = Context(ouiMap=ouiMap, database=database, verbose=verbose,
                  fake_lat=fake_lat, fake_lon=fake_lon,
                  hcxpcapngtool=hcxpcapngtool, tshark=tshark, force=force)

    for capture in captures:
        # Remove the trailing forward slash, if it exists
        if capture.endswith('/'):
            capture = capture[:-1]
        capture = replace_multiple_slashes(capture)

        handle_capture(ctx, capture, source)

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


if __name__ == "__main__":
    banner()
    main()
