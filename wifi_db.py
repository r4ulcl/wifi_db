#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-

import argparse
import wifi_db_aircrack
import os
import oui

def main():
    '''Function main. Parse argument and exec the functions '''

    #args
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-f", "--folder", help="insert a folder",
                        action="store_true")
    
    parser.add_argument("-t", "--lat", default='', help="insert a fake lat in all database")
    parser.add_argument("-n", "--lon", default='', help="insert a fake lat in all database")

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
    
    fake_lat = args.lat
    fake_lon = args.lon

    if verbose:
        print("verbosity turned on")


    database = wifi_db_aircrack.connect_database(name, verbose)
    wifi_db_aircrack.create_database(database, verbose)
    wifi_db_aircrack.create_views(database, verbose)

    ouiMap = oui.load_vendors()
    
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
                wifi_db_aircrack.parse_netxml(ouiMap, capture_aux, database, verbose)
                wifi_db_aircrack.parse_kismet_csv(ouiMap, capture_aux, database, verbose)
                wifi_db_aircrack.parse_csv(ouiMap, capture_aux, database, verbose)
                wifi_db_aircrack.parse_log_csv(ouiMap, capture_aux, database, verbose)
        else:
            wifi_db_aircrack.parse_netxml(ouiMap, capture, database, verbose)
            wifi_db_aircrack.parse_kismet_csv(ouiMap, capture, database, verbose)
            wifi_db_aircrack.parse_csv(ouiMap, capture, database, verbose)
            wifi_db_aircrack.parse_log_csv(ouiMap, capture, database, verbose)

        if fake_lat != "":
            print(fake_lat) 
            wifi_db_aircrack.fake_lat(database, fake_lat)
        if fake_lon != "": 
            print(fake_lon) 
            wifi_db_aircrack.fake_lon(database, fake_lon)
    elif source == "kismet":
        print("Parsing Kismet capture")
        # TO DO
    else:
        print("Parsing Wigle capture")
        # TO DO
        
if __name__ == "__main__":
    main()
