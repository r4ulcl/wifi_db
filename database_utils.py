#!/bin/python3
''' Utils to SQLite DB '''
# -*- coding: utf-8 -*-
import sqlite3
import os


def connect_database(name, verbose):
    '''Function to connect to the database'''
    database = sqlite3.connect(name)
    database.text_factory = str
    if verbose:
        print("DB connected OK")
    return database


def insertAP(cursor, verbose, bssid, essid, manuf, channel, freqmhz, carrier,
             encryption, packets_total, lat, lon):
    ''''''
    try:
        cursor.execute('''INSERT INTO AP VALUES(?,?,?,?,?,?,?,?,?,?) ''',
                       (bssid, essid, manuf, channel, freqmhz, carrier,
                        encryption, packets_total, lat, lon))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        try:
            if verbose:
                print("insertAP " + str(error))
            cursor.execute(
                "UPDATE AP SET channel = CASE WHEN channel=='-1' THEN ('%s') "
                "ELSE channel END "
                "WHERE bssid = '%s'" % (channel, bssid))

            # Write if empty
            cursor.execute(
                "UPDATE AP SET ssid = CASE WHEN ssid=='' THEN ('%s') "
                "WHEN ssid IS NULL THEN ('%s') ELSE ssid END "
                "WHERE bssid = '%s'" % (essid, essid, bssid))

            cursor.execute(
                "UPDATE AP SET manuf = CASE WHEN manuf=='' THEN ('%s') "
                "WHEN manuf IS NULL THEN ('%s') ELSE manuf END "
                "WHERE bssid = '%s'" % (manuf, manuf, bssid))

            cursor.execute(
                "UPDATE AP SET channel = CASE WHEN channel=='' THEN ('%s') "
                "WHEN channel IS NULL THEN ('%s') ELSE channel END "
                "WHERE bssid = '%s'" % (channel, channel, bssid))

            cursor.execute(
                "UPDATE AP SET frequency = CASE WHEN frequency=='' THEN ('%s')"
                " WHEN frequency IS NULL THEN ('%s') ELSE frequency END "
                "WHERE bssid = '%s'" % (freqmhz, freqmhz, bssid))

            cursor.execute(
                "UPDATE AP SET carrier = CASE WHEN carrier=='' THEN ('%s') "
                "WHEN carrier IS NULL THEN ('%s') ELSE carrier END "
                "WHERE bssid = '%s'" % (carrier, carrier, bssid))

            cursor.execute(
                "UPDATE AP SET encryption = CASE WHEN encryption=='' "
                "THEN ('%s') WHEN encryption IS NULL THEN ('%s') "
                "ELSE encryption END "
                "WHERE bssid = '%s'" % (encryption, encryption, bssid))

            cursor.execute(
                "UPDATE AP SET packetsTotal = packetsTotal + %s "
                "WHERE bssid = '%s'"
                % (packets_total, bssid))

            cursor.execute(
                "UPDATE AP SET lat_t = CASE WHEN lat_t == 0.0 THEN ('%s')"
                "ELSE lat_t END, lon_t = CASE WHEN lon_t == 0.0 THEN ('%s') "
                "ELSE lon_t END "
                "WHERE bssid = '%s'" % (lat, lon, bssid))

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
                  type, packets_total, device):
    '''Function to insert clients in the database'''
    try:
        cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                       (mac, ssid, manuf, type, packets_total, device))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertClients " + str(error))
        try:
            cursor.execute(
                "UPDATE client SET packetsTotal = packetsTotal \
                    + %s WHERE mac = '%s'" % (packets_total, mac))

            # Write if empty
            cursor.execute(
                "UPDATE client SET ssid = CASE WHEN ssid==''"
                " THEN ('%s') "
                "WHEN ssid IS NULL THEN ('%s') ELSE ssid END "
                "WHERE mac = '%s'" % (ssid, ssid, mac))

            cursor.execute(
                "UPDATE client SET manuf = CASE WHEN manuf=='' "
                "THEN ('%s') WHEN manuf IS NULL "
                "THEN ('%s') ELSE manuf END "
                "WHERE mac = '%s'" % (manuf, manuf, mac))

            cursor.execute(
                "UPDATE client SET type = CASE WHEN type=='' "
                "THEN ('%s') WHEN type IS NULL THEN ('%s') "
                "ELSE type END "
                "WHERE mac = '%s'" % (type, type, mac))

            cursor.execute(
                "UPDATE client SET device = CASE WHEN device=='' "
                "THEN ('%s') WHEN device IS NULL THEN ('%s') ELSE device END "
                "WHERE mac = '%s'" % (device, device, mac))

            return int(0)
        except sqlite3.IntegrityError as error:
            if verbose:
                print("insertClients2 " + str(error))
            return int(1)
        # print('Record already exists')
    except sqlite3.Error as error:
        if verbose:
            print("insertClients Error " + str(error))
        return int(1)


def insertProbe(cursor, verbose, bssid, essid, time):
    ''''''
    try:
        cursor.execute('''INSERT INTO Probe VALUES(?,?,?)''',
                       (bssid, essid, time))
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


def insertConnected(cursor, verbose, bssid, mac):
    ''''''
    try:
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO connected VALUES(?,?)''',
            (bssid, mac))
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

def insertHandshake(cursor, verbose, bssid, mac, file):
    ''''''
    try:
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO handshake VALUES(?,?,?)''',
            (bssid.upper(), mac.upper(), file))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertHandshake" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertHandshake Error " + str(error))
        return int(1)

def insertIdentity(cursor, verbose, bssid, mac, identity):
    ''''''
    try:
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO identity VALUES(?,?,?)''',
            (bssid.upper(), mac.upper(), identity))
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
                       (mac, time, tool, signal_rssi, lat, lon, alt))
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
                       (bssid, time, tool, signal_rsi,
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


def create_database(database, verbose):
    '''Function to create the tables in the database'''
    script_path = os.path.dirname(os.path.abspath(__file__))
    path = script_path+'/wifi_db_database.sql'
    views_file = open(path, 'r')
    views = views_file.read()
    try:
        cursor = database.cursor()
        for statement in views.split(';'):
            if statement:
                cursor.execute(statement + ';')
        database.commit()
        if verbose:
            print("Database created")
    except sqlite3.IntegrityError as error:
        print("create_database" + str(error))


def create_views(database, verbose):
    '''Function to create the Views in the database'''
    script_path = os.path.dirname(os.path.abspath(__file__))
    path = script_path+'/view.sql'
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
        print("create_views" + str(error))


def fake_lat(database, lat):
    try:
        cursor = database.cursor()

        sql = "UPDATE AP SET lat_t = " + lat
        cursor.execute(sql)
        sql = "UPDATE SeenAP SET lat = " + lat
        cursor.execute(sql)
        sql = "UPDATE SeenClient SET lat = " + lat
        cursor.execute(sql)

        database.commit()
    except sqlite3.IntegrityError as error:
        print("fake_lat" + str(error))


def fake_lon(database, lon):
    try:
        cursor = database.cursor()

        sql = "UPDATE AP SET lon_t = " + lon
        cursor.execute(sql)
        sql = "UPDATE SeenAP SET lon = " + lon
        cursor.execute(sql)
        sql = "UPDATE SeenClient SET lon = " + lon
        cursor.execute(sql)

        database.commit()
    except sqlite3.IntegrityError as error:
        print("fake_lon" + str(error))


# exists = '11:22:33:44:55:77' in whitelist
def clear_whitelist(database, whitelist):
    with open(whitelist) as f:
        whitelist = f.read().splitlines()
    cursor = database.cursor()
    for mac in whitelist:
        mac = mac.upper()
        try:
            cursor.execute(
                "DELETE from Handshake where bssid='%s'" % (mac))
            cursor.execute(
                "DELETE from Identity where bssid='%s'" % (mac))
            cursor.execute(
                "DELETE from SeenAP where bssid='%s'" % (mac))
            cursor.execute(
                "DELETE from SeenClient where mac='%s'" % (mac))
            cursor.execute(
                "DELETE from Probe where mac='%s'" % (mac))
            cursor.execute(
                "DELETE from Connected where bssid='%s' OR mac='%s'"
                % (mac, mac))
            cursor.execute(
                "DELETE from AP where bssid='%s'" % (mac))
            cursor.execute(
                "DELETE from Client where mac='%s'" % (mac))

            database.commit()

        except sqlite3.IntegrityError as error:
            print("clear_whitelist" + str(error))
    print("CLEARED WHITELIST MACS")
