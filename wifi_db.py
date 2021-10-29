#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-

import argparse
import wifi_db_aircrack
import database_utils
import os
import oui
from os import path


def main():
    '''Function main. Parse argument and exec the functions '''
    # args
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("--debug", help="increase output verbosity to debug",
                        action="store_true")

    parser.add_argument("-t", "--lat", default='',
                        help="insert a fake lat in all database")
    parser.add_argument("-n", "--lon", default='',
                        help="insert a fake lat in all database")

    parser.add_argument('--source',
                        default='aircrack-ng',
                        nargs='?',
                        choices=['aircrack-ng', 'kismet', 'wigle'],
                        help='source from capture data (default: %(default)s)')

    parser.add_argument("-d", "--database", type=str, default='db.SQLITE',
                        help="output database, if exist append to the given"
                        " database (default name: %(default)s)")

    parser.add_argument("capture", type=str,
                        help="capture file (.csv, .kismet.csv, "
                        ".kismet.netxml, .log.csv), \
                        if no extension add all")
    args = parser.parse_args()

    # vars
    verbose = args.verbose
    debug = args.debug

    name = args.database
    capture = args.capture
    source = args.source

    fake_lat = args.lat
    fake_lon = args.lon

    print(capture)

    if verbose:
        print("verbosity turned on")

    if debug:
        print("debug turned on")

    database = database_utils.connect_database(name, verbose)
    database_utils.create_database(database, verbose)
    database_utils.create_views(database, verbose)

    ouiMap = oui.load_vendors()

    if source == "aircrack-ng":
        print("Parsing aircrack-ng capture")
        if path.isdir(capture):
            files = []
            dirpath = os.getcwd()
            if os.path.isabs(capture):
                dir_capture = capture
            else:
                dir_capture = dirpath+"/"+capture
            if verbose:
                print(dir_capture)
                print("current directory is : " + dirpath)

            for r, d, f in os.walk(dir_capture):
                for file in f:
                    if 'kismet.netxml' in file:
                        files.append(os.path.join(r, file))

            for f in files:
                base = os.path.basename(f)
                name = os.path.splitext(os.path.splitext(base)[0])[0]
                capture_aux = dir_capture+"/"+name
                print("\n" + capture_aux)
                wifi_db_aircrack.parse_netxml(ouiMap, capture_aux,
                                              database, verbose)
                wifi_db_aircrack.parse_kismet_csv(ouiMap, capture_aux,
                                                  database, verbose)
                wifi_db_aircrack.parse_csv(ouiMap, capture_aux,
                                           database, verbose)
                wifi_db_aircrack.parse_log_csv(ouiMap, capture_aux,
                                               database, verbose)
        else:  # file
            wifi_db_aircrack.parse_netxml(ouiMap, capture,
                                          database, verbose)
            wifi_db_aircrack.parse_kismet_csv(ouiMap, capture,
                                              database, verbose)
            wifi_db_aircrack.parse_csv(ouiMap, capture,
                                       database, verbose)
            wifi_db_aircrack.parse_log_csv(ouiMap, capture,
                                           database, verbose)

        # Cleat whitelist MACs
        script_path = os.path.dirname(os.path.abspath(__file__))
        database_utils.clear_whitelist(
            database, script_path+'/whitelist.txt')

        if fake_lat != "":
            print(fake_lat)
            database_utils.fake_lat(database, fake_lat)
        if fake_lon != "":
            print(fake_lon)
            database_utils.fake_lon(database, fake_lon)
    elif source == "kismet":
        print("Parsing Kismet capture")
        # TO DO
    else:
        print("Parsing Wigle capture")
        # TO DO


if __name__ == "__main__":
    main()
