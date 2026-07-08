#!/bin/python3
''' # Delete an AP or client from database  '''
# -*- coding: utf-8 -*-
import sqlite3
import argparse


def connectDatabase(name, verbose):
    '''Function to connect to the database'''
    database = sqlite3.connect(name)
    database.text_factory = str
    # Enable foreign keys so ON DELETE CASCADE removes the related rows
    database.execute("PRAGMA foreign_keys = 1")
    if verbose:
        print("DB connected OK")
    return database


def delete_ap(database, bssid, verbose):
    print(bssid)

    # Fully static DELETE statements (no runtime string building, no
    # interpolated identifiers). With foreign keys enabled, deleting from AP
    # cascades to the rest, but they are deleted explicitly too so it also
    # works if cascade is unavailable. bssid is always a bound parameter.
    delete_statements = [
        "DELETE FROM Handshake WHERE bssid = ?",
        "DELETE FROM Identity WHERE bssid = ?",
        "DELETE FROM Certificate WHERE bssid = ?",
        "DELETE FROM EAPMD5 WHERE bssid = ?",
        "DELETE FROM SeenAp WHERE bssid = ?",
        "DELETE FROM Connected WHERE bssid = ?",
        "DELETE FROM AP WHERE bssid = ?",
    ]

    try:
        cursor = database.cursor()
        bssid = bssid.upper()

        for sql in delete_statements:
            if verbose:
                print(sql, bssid)
            cursor.execute(sql, (bssid,))

        database.commit()
    except sqlite3.Error as error:
        print(error)


# !!!! ADD DELETE CLIENT to delete my AP, my phone, computer and tablet
# FILE WITH MACS whitelist!!!!! not added in DB, or added and deleted
def main():
    '''Function main. Parse argument and exec the functions '''
    # args
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")

    parser.add_argument("database", type=str,
                        help="output database, if exist "
                             "append to the given database")

    parser.add_argument("bssid", type=str,
                        help="BSSID to delete")

    args = parser.parse_args()

    # vars
    verbose = args.verbose
    name = args.database
    bssid = args.bssid

    if verbose:
        print("verbosity turned on")

    database = connectDatabase(name, verbose)

    delete_ap(database, bssid, verbose)


if __name__ == "__main__":
    main()
