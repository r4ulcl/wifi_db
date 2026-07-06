#!/bin/python3
''' Database maintenance helpers kept apart from the parser insert helpers:
address obfuscation (for safely sharing a DB) and whitelist clearing. '''
# -*- coding: utf-8 -*-
import sqlite3
import secrets
import string


# obfuscated the database AA:BB:CC:XX:XX:XX-DEFG,
# needs database and not cursos to commit
def _obfuscateColumn(database, verbose, label, select_sql, update_sql,
                     uppercase):
    '''Replace every address in one table column with AA:BB:CC:XX:XX:XX-<rand>.

    `select_sql`/`update_sql` are fixed literals supplied by the caller (no
    identifier interpolation, so the statements stay injection-safe). The 8
    random lowercase letters keep the obfuscated values unique.'''
    try:
        if verbose:
            print("obfuscated " + label)
        cursor = database.cursor()
        cursor.execute(select_sql)
        for row in cursor.fetchall():
            aux = ''.join(secrets.choice(string.ascii_lowercase)
                          for _ in range(8))
            new = row[0][0:9] + 'XX:XX:XX' + '-' + aux
            old = row[0]
            if uppercase:
                new, old = new.upper(), old.upper()
            cursor.execute(update_sql, (new, old))
        database.commit()
        return int(0)
    except sqlite3.IntegrityError as error:
        print("obfuscateDB" + str(error))
        return int(1)


def obfuscateDB(database, verbose):
    '''Obfuscate AP BSSIDs and Client MACs so the DB can be shared safely.'''
    _obfuscateColumn(database, verbose, "APs",
                     "SELECT bssid from AP; ",
                     "UPDATE AP set bssid = (?) where bssid = ?", False)
    return _obfuscateColumn(database, verbose, "clients",
                            "SELECT mac from Client; ",
                            "UPDATE Client set mac = (?) where mac = ?", True)

# exists = '11:22:33:44:55:77' in whitelist


def clearWhitelist(database, verbose, whitelist):
    with open(whitelist, encoding='utf-8') as f:
        whitelist = f.read().splitlines()
    cursor = database.cursor()
    for mac in whitelist:
        mac = mac.upper()
        if verbose:
            print("clearWhitelist", mac)
        try:
            cursor.execute(
                "DELETE from Handshake where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Identity where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from SeenAP where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from SeenClient where mac = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Probe where mac = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Connected where bssid = (?)  OR mac = (?) ",
                (mac.upper(), mac.upper(),))
            cursor.execute(
                "DELETE from AP where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Client where mac = (?) ", (mac.upper(),))

            database.commit()

        except sqlite3.IntegrityError as error:
            print("clearWhitelist" + str(error))
    print("CLEARED WHITELIST MACS")
