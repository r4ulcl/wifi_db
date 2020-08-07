#!/bin/python3
''' # Delete an AP or client from database  '''
# -*- coding: utf-8 -*-
import csv
import xml.etree.ElementTree as ET
import sqlite3
import os
import re
import argparse
import oui
import ftfy

def connect_database(name, verbose):
    '''Function to connect to the database'''
    database = sqlite3.connect(name)
    database.text_factory = str
    if verbose:
        print("DB connected OK")
    return database

def delete_ap(database, bssid, verbose):
    print(bssid)
# DELETE from seenap where bssid="80:35:C1:3E:CD:8C";
# DELETE from connected where bssid="80:35:C1:3E:CD:8C";
# DELETE from ap where bssid="80:35:C1:3E:CD:8C";

    try:
        cursor = database.cursor()

        sql = "DELETE from seenap where bssid=\""+bssid+"\""
        print(sql)
        cursor.execute(sql)

        sql = "DELETE from connected where bssid=\""+bssid+"\""
        print(sql)
        cursor.execute(sql)

        sql = "DELETE from ap where bssid=\""+bssid+"\""
        print(sql)
        cursor.execute(sql)

        database.commit()
    except sqlite3.IntegrityError as error:
        print(error)


## !!!! ADD DELETE CLIENT to delete my AP, my phone, computer and tablet
# FILE WITH MACS whitelist!!!!! not added in DB, or added and deleted
def main():
    '''Function main. Parse argument and exec the functions '''
    #args
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")

    parser.add_argument("database", type=str,
                        help="output database, if exist append to the given database")

    parser.add_argument("bssid", type=str,
                        help="BSSID to delete")

    args = parser.parse_args()

    #vars
    verbose = args.verbose
    name = args.database
    bssid = args.bssid

    if verbose:
        print("verbosity turned on")


    database = connect_database(name, verbose)

    delete_ap(database, bssid, verbose)


if __name__ == "__main__":
    main()


