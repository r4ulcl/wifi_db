#!/bin/python3
''' Utils to SQLite DB '''
# -*- coding: utf-8 -*-
import sqlite3
import os
import random
import string
import datetime
import hashlib


def connectDatabase(name, verbose):
    '''Function to connect to the database'''
    try:
        database = sqlite3.connect(name)
        database.text_factory = str
        database.execute("PRAGMA foreign_keys = 1")
        if verbose:
            print("DB connected OK")
        return database
    except Exception as error:
        print("FATAL ERROR createDatabase: " + str(error))
        exit()


def createDatabase(database, verbose):
    '''Function to create the tables in the database'''
    script_path = os.path.dirname(os.path.abspath(__file__))
    path = script_path + '/wifi_db_database.sql'
    db_file = open(path, 'r')
    views = db_file.read()
    try:
        cursor = database.cursor()
        for statement in views.split(';'):
            if statement:
                cursor.execute(statement + ';')
        database.commit()
        if verbose:
            print("Database created")
    except sqlite3.IntegrityError as error:
        print("createDatabase" + str(error))
    db_file.close()


def createViews(database, verbose):
    '''Function to create the Views in the database'''
    script_path = os.path.dirname(os.path.abspath(__file__))
    path = script_path + '/view.sql'
    views_file = open(path, 'r')
    views = views_file.read()
    try:
        cursor = database.cursor()
        # cursor.executemany(views)
        for statement in views.split(';'):
            if statement:
                cursor.execute(statement + ';')
        database.commit()
        if verbose:
            print("Views created")
    except sqlite3.IntegrityError as error:
        print("createViews" + str(error))
    views_file.close()


def insertAP(cursor, verbose, bssid, essid, manuf, channel, freqmhz, carrier,
             encryption, packets_total, lat, lon, cloaked, mfpc, mfpr,
             firstTimeSeen):
    ''''''
    try:
        cursor.execute('''INSERT INTO AP VALUES
                          (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                       (bssid.upper(), essid, cloaked, manuf, channel, freqmhz,
                        carrier, encryption, packets_total, lat, lon, mfpc,
                        mfpr, firstTimeSeen))

        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        try:
            if verbose:
                print("insertAP " + str(error))

            # If firstTimeSeen is before current firstTimeSeen update
            # Update `firstTimeSeen` column
            if firstTimeSeen != 0:
                sql = """UPDATE AP SET firstTimeSeen = CASE WHEN
                         firstTimeSeen = '' OR firstTimeSeen = '0' OR
                         firstTimeSeen IS NULL OR firstTimeSeen > (?) AND
                         (?) <> 0 AND firstTimeSeen <> 0 THEN (?) ELSE
                         firstTimeSeen END WHERE bssid = (?)"""
                if verbose:
                    print(sql, (firstTimeSeen, bssid))
                cursor.execute(sql, (firstTimeSeen, firstTimeSeen,
                                     firstTimeSeen, bssid.upper()))

            # Write if empty
            sql = """UPDATE AP SET ssid = CASE WHEN ssid = '' OR
                     ssid IS NULL THEN (?) ELSE ssid END WHERE bssid = (?)"""
            if verbose:
                print(sql, (essid, bssid.upper()))
            cursor.execute(sql, (essid, bssid.upper()))

            # Update `manuf` column
            sql = """UPDATE AP SET manuf = CASE WHEN manuf = '' OR manuf IS
                    NULL THEN (?) ELSE manuf END WHERE bssid = (?)"""
            if verbose:
                print(sql, (manuf, bssid.upper()))
            cursor.execute(sql, (manuf, bssid.upper()))

            # Update `channel` column
            sql = """UPDATE AP SET channel = CASE WHEN channel = '' OR channel
                    IS NULL OR channel = 0 THEN (?) ELSE channel END
                    WHERE bssid = (?)"""
            if verbose:
                print(sql, (channel, bssid))
            cursor.execute(sql, (channel, bssid.upper()))

            # Update `frequency` column
            sql = """UPDATE AP SET frequency = CASE WHEN frequency = '' OR
                     frequency IS NULL OR frequency < 2000 THEN (?) ELSE
                     frequency END WHERE bssid = (?)"""
            if verbose:
                print(sql, (freqmhz, bssid))
            cursor.execute(sql, (freqmhz, bssid.upper()))

            # Update `carrier` column
            sql = """UPDATE AP SET carrier = CASE WHEN carrier = '' OR
                     carrier IS NULL
                     THEN (?) ELSE carrier END WHERE bssid = (?)"""
            if verbose:
                print(sql, (carrier, bssid))
            cursor.execute(sql, (carrier, bssid.upper()))

            # Update `encryption` column
            sql = """UPDATE AP SET encryption = CASE WHEN encryption = '' OR
                    encryption IS NULL THEN (?) ELSE encryption END
                    WHERE bssid = (?)"""
            if verbose:
                print(sql, (encryption, bssid))
            cursor.execute(sql, (encryption, bssid.upper()))

            # Update `packetsTotal` column
            sql = """UPDATE AP SET packetsTotal = packetsTotal + (?)
                    WHERE bssid = (?)"""
            if verbose:
                print(sql, (packets_total, bssid.upper()))
            cursor.execute(sql, (packets_total, bssid.upper()))

            # Update `lat_t` and `lon_t` columns
            sql = """UPDATE AP SET lat_t = CASE WHEN lat_t = 0.0 THEN (?)
                    ELSE lat_t END, lon_t = CASE WHEN lon_t = 0.0 THEN (?)
                    ELSE lon_t END WHERE bssid = (?)"""
            if verbose:
                print(sql, (lat, lon, bssid.upper()))
            cursor.execute(sql, (lat, lon, bssid.upper()))

            # Update `cloaked` column
            sql = """UPDATE AP SET cloaked = CASE WHEN cloaked = 'False'
                    THEN (?) ELSE cloaked END WHERE bssid = (?)"""
            if verbose:
                print(sql, (cloaked, bssid.upper()))
            cursor.execute(sql, (cloaked, bssid.upper()))

            # UPDATE `mfpc` columns
            sql = """UPDATE AP SET mfpc = CASE WHEN mfpc = 'False' THEN (?)
                    ELSE mfpc END WHERE bssid = (?)"""
            if verbose:
                print(sql, (mfpc, bssid.upper()))
            cursor.execute(sql, (mfpc, bssid.upper()))

            # UPDATE `mfpr` columns
            sql = """UPDATE AP SET mfpr = CASE WHEN mfpr = 'False' THEN (?)
                    ELSE mfpr END WHERE bssid = (?)"""
            if verbose:
                print(sql, (mfpr, bssid.upper()))
            cursor.execute(sql, (mfpr, bssid.upper()))

            return int(0)
        except sqlite3.IntegrityError as error:

            if verbose:
                print("insertAP2 " + str(error))
            return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertAP Error " + str(error))
            return int(1)


def insertClients(cursor, verbose, mac, ssid, manuf,
                  type, packets_total, device, firstTimeSeen):
    '''Function to insert clients in the database'''
    try:
        cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?,?)''',
                       (mac.upper(), ssid, manuf, type, packets_total, device,
                        firstTimeSeen))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertClients " + str(error))
        try:

            # If firstTimeSeen is before current firstTimeSeen update
            # Update `firstTimeSeen` column
            if firstTimeSeen != 0:
                sql = """UPDATE client SET firstTimeSeen = CASE WHEN
                         (firstTimeSeen = '' OR firstTimeSeen = '0' OR
                         firstTimeSeen IS NULL OR firstTimeSeen > (?)) AND
                         (?) <> 0 AND firstTimeSeen <> 0 THEN (?) ELSE
                         firstTimeSeen END WHERE mac = (?)"""
                if verbose:
                    print(sql, (firstTimeSeen, mac))
                cursor.execute(sql, (firstTimeSeen, firstTimeSeen,
                                     firstTimeSeen, mac.upper()))

            # Update `packetsTotal` column
            sql = """UPDATE client SET packetsTotal = packetsTotal + (?)
                     WHERE mac = (?)"""
            if verbose:
                print(sql, (packets_total, mac.upper()))
            cursor.execute(sql, (packets_total, mac.upper()))

            # Write if empty
            # Update `ssid` column
            sql = """UPDATE client SET ssid = CASE WHEN ssid = '' OR ssid IS
                     NULL THEN (?) ELSE ssid END WHERE mac = (?)"""
            if verbose:
                print(sql, (ssid, mac.upper()))
            cursor.execute(sql, (ssid, mac.upper()))

            # Update `manuf` column
            sql = """UPDATE client SET manuf = CASE WHEN manuf = '' OR manuf IS
                     NULL THEN (?) ELSE manuf END WHERE mac = (?)"""
            if verbose:
                print(sql, (manuf, mac.upper()))
            cursor.execute(sql, (manuf, mac.upper()))

            # Update `type` column
            sql = """UPDATE client SET type = CASE WHEN type = '' OR type IS
                     NULL THEN (?) ELSE type END WHERE mac = (?)"""
            if verbose:
                print(sql, (type, mac.upper()))
            cursor.execute(sql, (type, mac.upper()))

            # Update `manuf` column
            sql = """UPDATE client SET device = CASE WHEN device = '' OR
                     device IS NULL THEN (?) ELSE device END WHERE mac = (?)"""
            if verbose:
                print(sql, (device, mac.upper()))
            cursor.execute(sql, (device, mac.upper()))

            return int(0)
        except sqlite3.IntegrityError as error:
            if verbose:
                print("insertClients2 " + str(error))
            return int(1)
        # print('Record already exists')
    except sqlite3.Error as error:
        if verbose:
            print("insertClients0 Error " + str(error))
        return int(1)


def insertProbe(cursor, verbose, bssid, essid, time):
    ''''''
    try:
        cursor.execute('''INSERT INTO Probe VALUES(?,?,?)''',
                       (bssid.upper(), essid, time))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertProbe" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertProbe Error " + str(error))
        return int(1)


def insertWPS(cursor, verbose, bssid, wlan_ssid, wps_version, wps_device_name,
              wps_model_name, wps_model_number, wps_config_methods,
              wps_config_methods_keypad):
    ''''''
    try:
        # Insert AP CONSTRAINT
        essid = ""
        manuf = ""
        channel = ""
        freqmhz = ""
        carrier = ""
        encryption = ""
        packets_total = ""
        lat = "0.0"
        lon = "0.0"
        cloaked = 'False'
        mfpc = 'False'
        mfpr = 'False'
        insertAP(cursor, verbose, bssid, essid, manuf, channel, freqmhz,
                 carrier, encryption, packets_total, lat, lon, cloaked, mfpc,
                 mfpr, 0)

        cursor.execute('''INSERT INTO WPS VALUES(?,?,?,?,?,?,?,?)''',
                       (bssid.upper(), wlan_ssid, wps_version, wps_device_name,
                        wps_model_name, wps_model_number, wps_config_methods,
                        wps_config_methods_keypad))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertWPS " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertWPS Error " + str(error))
        return int(1)


def insertConnected(cursor, verbose, bssid, mac):
    ''''''
    try:
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO connected VALUES(?,?)''',
            (bssid.upper(), mac.upper()))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertConnected" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertConnected Error " + str(error))
        return int(1)


def insertMFP(cursor, verbose, bssid, mfpc, mfpr, file):
    ''''''
    try:
        # Insert AP or update
        essid = ""
        manuf = ""
        channel = ""
        freqmhz = ""
        carrier = ""
        encryption = ""
        packets_total = ""
        lat = "0.0"
        lon = "0.0"
        cloaked = 'False'
        insertAP(cursor, verbose, bssid, essid, manuf, channel, freqmhz,
                 carrier, encryption, packets_total, lat, lon, cloaked, mfpc,
                 mfpr, 0)

        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertMFP" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertMFP Error " + str(error))

        return int(1)


def insertHandshake(cursor, verbose, bssid, mac, file):
    ''''''
    try:
        error = 0
        # Insert file
        error += insertFile(cursor, verbose, file)

        # Get file hash MD5
        with open(file, 'rb') as file_handle:
            hash = getHash(file_handle.read())

        # insertHandshake Client and AP CONSTRAINT
        ssid = ""
        manuf = ""
        type = ""
        packets_total = "0"
        device = ""
        error += insertClients(cursor, verbose, mac, ssid, manuf,
                               type, packets_total, device, 0)
        essid = ""
        manuf = ""
        channel = ""
        freqmhz = ""
        carrier = ""
        encryption = ""
        packets_total = ""
        lat = "0.0"
        lon = "0.0"
        cloaked = 'False'
        mfpc = 'False'
        mfpr = 'False'
        error += insertAP(cursor, verbose, bssid, essid, manuf, channel,
                          freqmhz, carrier, encryption, packets_total, lat,
                          lon, cloaked, mfpc, mfpr, 0)

        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO handshake VALUES(?,?,?,?,?)''',
            (bssid.upper(), mac.upper(), file, hash, ""))
        return int(error)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertHandshake" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertHandshake Error " + str(error))
        return int(1)


def insertIdentity(cursor, verbose, bssid, mac, identity, method):
    ''''''
    error = 0
    try:
        # Insert Identity Client and AP CONSTRAINT
        ssid = ""
        manuf = ""
        # type = ""
        packets_total = "0"
        device = ""
        error += insertClients(cursor, verbose, mac, ssid, manuf,
                               "", packets_total, device, 0)

        essid = ""
        manuf = ""
        channel = ""
        freqmhz = ""
        carrier = ""
        encryption = ""
        packets_total = ""
        lat = "0.0"
        lon = "0.0"
        cloaked = 'False'
        mfpc = 'False'
        mfpr = 'False'
        error += insertAP(cursor, verbose, bssid, essid, manuf, channel,
                          freqmhz, carrier, encryption, packets_total, lat,
                          lon, cloaked, mfpc, mfpr, 0)

        if verbose:
            print('output ' + bssid.upper(), mac.upper(), identity, method)
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO identity VALUES(?,?,?,?)''',
            (bssid.upper(), mac.upper(), identity, method))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertIdentity" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertIdentity Error " + str(error))
        return int(1)


def insertSeenClient(cursor, verbose, mac, time, tool, signal_rssi,
                     lat, lon, alt):
    ''''''
    try:
        cursor.execute('''INSERT INTO SeenClient
                       VALUES(?,?,?,?,?,?,?)''',
                       (mac.upper(), time, tool, signal_rssi, lat, lon, alt))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertSeenClient" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertSeenClient Error " + str(error))
        return int(1)


def insertSeenAP(cursor, verbose, bssid, time, tool, signal_rsi,
                 lat, lon, alt, bsstimestamp):
    ''''''
    try:
        cursor.execute('''INSERT INTO SeenAp VALUES(?,?,?,?,?,?,?,?)''',
                       (bssid.upper(), time, tool, signal_rsi,
                        lat, lon, alt, bsstimestamp))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertSeenAP" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertSeenAP Error " + str(error))
        return int(1)


def setHashcat(cursor, verbose, bssid, mac, file, hashcat):
    try:
        # Remove enter at the end
        hashcat = hashcat.strip()
        with open(file, 'rb') as file_handle:
            hash = getHash(file_handle.read())
        if verbose:
            print("HASH: ", hash)
        cursor.execute('''INSERT OR REPLACE INTO Handshake
                          VALUES(?,?,?,?,?)''',
                       (bssid.upper(), mac.upper(), file, hash, hashcat))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("setHashcat" + str(error))
        return int(1)


def insertFile(cursor, verbose, file):
    try:
        # Get MD5
        with open(file, 'rb') as file_handle:
            hash = getHash(file_handle.read())
        if verbose:
            print("HASH: ", hash)
        cursor.execute('''INSERT OR REPLACE INTO Files VALUES(?,?,?,?)''',
                       (file, "False", hash, datetime.datetime.now()))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("insertFile" + str(error))
        return int(1)


def getHash(file):
    return hashlib.sha256(file).hexdigest()


def setFileProcessed(cursor, verbose, file):
    try:
        cursor.execute('''UPDATE Files SET processed = (?) where file = ?''',
                       ("True", file))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("setFileProcessed" + str(error))
        return int(1)


def checkFileProcessed(cursor, verbose, file):
    if not os.path.exists(file):
        if verbose:
            print("File", file, "does not exist")
        return int(0)

    with open(file, 'rb') as file_handle:
        hash = getHash(file_handle.read())

    try:
        cursor.execute('''SELECT file FROM Files WHERE hashSHA = (?)
                          AND processed = "True"''', (hash,))

        output = cursor.fetchall()
        if len(output) > 0:
            return int(1)

        return int(0)
    except sqlite3.IntegrityError as error:
        print("checkFileProcessed" + str(error))
        return int(2)


# obfuscated the database AA:BB:CC:XX:XX:XX-DEFG,
# needs database and not cursos to commit
def obfuscateDB(database, verbose):
    # APs!
    try:
        # Get all APs
        if verbose:
            print("obfuscated APs")
        cursor = database.cursor()
        sql = "SELECT bssid from AP; "
        cursor.execute(sql)

        output = cursor.fetchall()
        for row in output:
            # Replace all APs bssid (add random letter to avoid duplicates)
            letter = string.ascii_lowercase
            aux = ''.join(random.choice(letter) for _ in range(8))
            new = (row[0][0:9] + ('XX:XX:XX') + '-' + aux)
            # print (new)

            cursor.execute('''UPDATE AP set bssid = (?) where bssid = ?''',
                           (new, row[0]))
            database.commit()

        database.commit()

    except sqlite3.IntegrityError as error:
        print("obfuscateDB" + str(error))

    # Clients!
    try:
        # Get all Clients
        if verbose:
            print("obfuscated clients")
        cursor = database.cursor()
        sql = "SELECT mac from Client; "
        cursor.execute(sql)

        output = cursor.fetchall()
        for row in output:
            # Replace all APs bssid (add random letter to avoid duplicates)
            letter = string.ascii_lowercase
            aux = ''.join(random.choice(letter) for _ in range(8))
            new = (row[0][0:9] + ('XX:XX:XX') + '-' + aux)

            cursor.execute('''UPDATE Client set mac = (?) where mac = ?''',
                           (new.upper(), row[0].upper()))
            database.commit()

        database.commit()
        return int(0)
    except sqlite3.IntegrityError as error:
        print("obfuscateDB" + str(error))
        return int(1)

# exists = '11:22:33:44:55:77' in whitelist


def clearWhitelist(database, verbose, whitelist):
    with open(whitelist) as f:
        whitelist = f.read().splitlines()
    cursor = database.cursor()
    for mac in whitelist:
        mac = mac.upper()
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
