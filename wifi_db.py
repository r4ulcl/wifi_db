#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-

import argparse
from utils import wifi_db_aircrack
from utils import update
from utils import database_utils
from utils import oui
import os
from os import path
import platform
import subprocess
import nest_asyncio
import re


# import nest_asyncio ; nest_asyncio.apply() ->
# Fix RuntimeError: This event loop is already running”

VERSION = '1.4.1'


def banner():
    print('''
           _   __  _             _  _
__      __(_) / _|(_)         __| || |__
\ \ /\ / /| || |_ | |        / _` || '_ \\
 \ V  V / | ||  _|| |       | (_| || |_) |
  \_/\_/  |_||_|  |_| _____  \__,_||_.__/
                     |_____|
                               by r4ulcl
''')


def printVersion():
    print("wifi_db version:", VERSION)


def replace_multiple_slashes(string):
    return re.sub('/+', '/', string)


def main():
    nest_asyncio.apply()

    # Check for update
    update.check_for_update(VERSION)

    '''Function main. Parse argument and exec the functions '''
    # args
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
    args = parser.parse_args()

    if args.version:
        printVersion()
        exit()

    if not args.capture:
        print("wifi_db.py: error: the following arguments"
              + " are required: capture")
        exit()

    # vars
    # version = args.version
    verbose = args.verbose
    debug = args.debug
    obfuscated = args.obfuscated
    force = args.force

    try:
        cmd = "where" if platform.system() == "Windows" else "which"
        subprocess.call([cmd, "hcxpcapngtool"])
        hcxpcapngtool = True
    except Exception as E:
        hcxpcapngtool = False
        print("False", E)

    try:
        cmd = "where" if platform.system() == "Windows" else "which"
        subprocess.call([cmd, "tshark"])
        tshark = True
    except Exception as E:
        tshark = False
        print("False", E)

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

        if source == "aircrack-ng":
            print("Parsing file:", capture)
            # Remove format if any

            # If it is a folder...
            if path.isdir(capture):
                files = []
                dirpath = os.getcwd()
                if os.path.isabs(capture):
                    dir_capture = capture
                else:
                    dir_capture = dirpath + "/" + capture
                if verbose:
                    print(dir_capture)
                    print("current directory is : " + dirpath)

                for file in os.listdir(dir_capture):
                    if (('.cap' in file) or ('.csv' in file)
                       or ('.kismet.csv' in file)
                       or ('kismet.netxml' in file)
                       or ('.log.csv' in file)):
                        files.append(file)
                # Sorted reverse to cap last by name and extension
                files.sort(key=os.path.splitext, reverse=True)
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

            else:  # it is a file
                process_capture(ouiMap, capture, database,
                                verbose, fake_lat, fake_lon,
                                hcxpcapngtool, tshark, force)

        elif source == "kismet":
            print("Parsing Kismet capture")
            # TO DO
        else:
            print("Parsing Wigle capture")
            # TO DO

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


def process_capture(ouiMap, capture, database,
                    verbose, fake_lat, fake_lon,
                    hcxpcapngtool, tshark, force):
    cursor = database.cursor()

    if database_utils.checkFileProcessed(cursor,
                                         verbose, capture) == 1 and not force:
        print("File", "already processed\n")
    else:
        if ".cap" in capture:
            database_utils.insertFile(cursor, verbose, capture)
            wifi_db_aircrack.parse_cap(capture, database, verbose,
                                       hcxpcapngtool, tshark)
            database_utils.setFileProcessed(cursor, verbose, capture)
        elif ".kismet.netxml" in capture:
            database_utils.insertFile(cursor, verbose, capture)
            wifi_db_aircrack.parse_netxml(ouiMap, capture,
                                          database, verbose)
            database_utils.setFileProcessed(cursor, verbose, capture)
        elif ".kismet.csv" in capture:
            database_utils.insertFile(cursor, verbose, capture)
            wifi_db_aircrack.parse_kismet_csv(ouiMap, capture,
                                              database, verbose)
            database_utils.setFileProcessed(cursor, verbose, capture)
        elif ".log.csv" in capture:
            database_utils.insertFile(cursor, verbose, capture)
            wifi_db_aircrack.parse_log_csv(ouiMap, capture,
                                           database, verbose, fake_lat,
                                           fake_lon)
            database_utils.setFileProcessed(cursor, verbose, capture)
        elif ".csv" in capture:
            database_utils.insertFile(cursor, verbose, capture)
            wifi_db_aircrack.parse_csv(ouiMap, capture,
                                       database, verbose)
            database_utils.setFileProcessed(cursor, verbose, capture)
        else:
            print("Not format found!")
            # Remove dot at end if not format found
            if capture.endswith('.'):
                capture = capture[:-1]

            captureFormat = capture + ".kismet.netxml"
            print("Parsing file:", captureFormat)
            if (
                database_utils.checkFileProcessed(
                    cursor, verbose, captureFormat
                ) == 1 and not force
            ):
                print("File", "already processed\n")
            else:
                database_utils.insertFile(cursor, verbose, captureFormat)
                wifi_db_aircrack.parse_netxml(ouiMap, captureFormat,
                                              database, verbose)
                database_utils.setFileProcessed(cursor, verbose, captureFormat)

            captureFormat = capture + ".kismet.csv"
            print("Parsing file:", captureFormat)
            if (
                database_utils.checkFileProcessed(
                    cursor, verbose, captureFormat
                ) == 1 and not force
            ):
                print("File", "already processed\n")
            else:
                database_utils.insertFile(cursor, verbose, captureFormat)
                wifi_db_aircrack.parse_kismet_csv(ouiMap, captureFormat,
                                                  database, verbose)
                database_utils.setFileProcessed(cursor, verbose, captureFormat)

            captureFormat = capture + ".csv"
            print("Parsing file:", captureFormat)
            if (
                database_utils.checkFileProcessed(
                    cursor, verbose, captureFormat
                ) == 1 and not force
            ):
                print("File", "already processed\n")
            else:
                database_utils.insertFile(cursor, verbose, captureFormat)
                wifi_db_aircrack.parse_csv(ouiMap, captureFormat,
                                           database, verbose)
                database_utils.setFileProcessed(cursor, verbose, captureFormat)

            captureFormat = capture + ".log.csv"
            print("Parsing file:", captureFormat)
            if (
                database_utils.checkFileProcessed(
                    cursor, verbose, captureFormat
                ) == 1 and not force
            ):
                print("File", "already processed\n")
            else:
                database_utils.insertFile(cursor, verbose, captureFormat)
                wifi_db_aircrack.parse_log_csv(ouiMap, captureFormat,
                                               database, verbose, fake_lat,
                                               fake_lon)
                database_utils.setFileProcessed(cursor, verbose, captureFormat)

            captureFormat = capture + ".cap"
            print("Parsing file:", captureFormat)
            if (
                database_utils.checkFileProcessed(
                    cursor, verbose, captureFormat
                ) == 1 and not force
            ):
                print("File", "already processed\n")
            else:
                database_utils.insertFile(cursor, verbose, captureFormat)
                wifi_db_aircrack.parse_cap(captureFormat, database, verbose,
                                           hcxpcapngtool, tshark)
                database_utils.setFileProcessed(cursor, verbose, captureFormat)


if __name__ == "__main__":
    banner()
    main()
