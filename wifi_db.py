#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-

import argparse
import wifi_db_aircrack
import os

def main():
    '''Function main. Parse argument and exec the functions '''

    #args
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-f", "--folder", help="insert a folder",
                        action="store_true")

    parser.add_argument('--source',
                        default='aircrack-ng',
                        nargs='?',
                        choices=['aircrack-ng', 'kismet', 'wigle'],
                        help='source from capture data (default: %(default)s)')

    parser.add_argument("database", type=str,
                        help="output database, if exist append to the given database")
    parser.add_argument("capture", type=str,
                        help="capture file (.csv,.kismet.csv, .kismet.netxml, .log.csv), \
                        if no extension add all")
    args = parser.parse_args()

    #vars
    verbose = args.verbose
    folder = args.folder

    name = args.database
    capture = args.capture
    source = args.source

    if verbose:
        print("verbosity turned on")


    database = wifi_db_aircrack.connect_database(name, verbose)
    wifi_db_aircrack.create_database(database, verbose)
    wifi_db_aircrack.create_views(database, verbose)

    if source == "aircrack-ng":
        print("Parsing aircrack-ng capture")
        if folder:
            files = []
            dirpath = os.getcwd()
            if verbose:
                print(dirpath+"/"+capture)
                print("current directory is : " + dirpath)
            for r, d, f in os.walk(dirpath+"/"+capture):
                for file in f:
                    if 'kismet.netxml' in file:
                        files.append(os.path.join(r, file))

            for f in files:
                base = os.path.basename(f)
                name = os.path.splitext(os.path.splitext(base)[0])[0]
                capture_aux = dirpath+"/"+capture+"/"+name
                print(capture_aux)
                wifi_db_aircrack.parse_netxml(capture_aux, database, verbose)
                wifi_db_aircrack.parse_kismet_csv(capture_aux, database, verbose)
                wifi_db_aircrack.parse_csv(capture_aux, database, verbose)
                wifi_db_aircrack.parse_log_csv(capture_aux, database, verbose)
        else:
            wifi_db_aircrack.parse_netxml(capture, database, verbose)
            wifi_db_aircrack.parse_kismet_csv(capture, database, verbose)
            wifi_db_aircrack.parse_csv(capture, database, verbose)
            wifi_db_aircrack.parse_log_csv(capture, database, verbose)
    elif source == "kismet":
        print("Parsing Kismet capture")
        # TO DO
    else:
        print("Parsing Wigle capture")
        # TO DO

if __name__ == "__main__":
    main()
