''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-
import csv
import xml.etree.ElementTree as ET
import sqlite3
import os
import re
import argparse
import ftfy

def connect_database(name, verbose):
    '''Function to connect to the database'''
    database = sqlite3.connect(name)
    database.text_factory = str
    if verbose:
        print("DB connected OK")
    return database


def create_database(database, verbose):
    '''Function to create the tables in the database'''
    path = 'database.sql'
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
        print(error)


def create_views(database, verbose):
    '''Function to create the Views in the database'''

    path = 'view.sql'
    views_file = open(path, 'r')
    views = views_file.read()
    try:
        cursor = database.cursor()
        #cursor.executemany(views)
        for statement in views.split(';'):
            if statement:
                cursor.execute(statement + ';')
        database.commit()
        if verbose:
            print("Views created")
    except sqlite3.IntegrityError as error:
        print(error)


def parse_netxml(name, database, verbose):
    '''Function to parse the .kismet.netxml files'''

    exists = os.path.isfile(name+".kismet.netxml")
    try:
        cursor = database.cursor()
        if exists:
            with open(name+".kismet.netxml", 'r') as file:
                filedata = file.read()
            # fix aircrack error, remove spaces &#x 0;
            filedata = re.sub(r'&#x[ ]+', '&#x', filedata)

            # fix aircrack error, remove NULL byte &#x0;
            filedata = filedata.replace('&#x0;', '')

            raiz = ET.fromstring(filedata)
            for wireless in raiz:
                if wireless.get("type") == "probe":
                    bssid = wireless.find("BSSID").text
                    manuf = wireless.find("manuf").text
                    packets_total = wireless.find("packets").find("total").text
                    # print bssid, manuf, "W", packetsT
                    try:
                        cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                                       (bssid, '', manuf, 'W', packets_total, 'Misc'))
                    except sqlite3.IntegrityError as error:
                        try:
                            cursor.execute(
                                "UPDATE client SET packetsTotal = packetsTotal \
                                    + %s WHERE mac = '%s'" % (packets_total, bssid))
                        except sqlite3.IntegrityError as error:
                            print(error)
                        # print('Record already exists')

                    # probe
                    if wireless.find("wireless-client").find("SSID").find("ssid") is not None:
                        essid_probe = wireless.find("wireless-client").findall("SSID")
                        for ssid in essid_probe:
                            # print bssid, ssid.find("ssid").text
                            try:
                                cursor.execute('''INSERT INTO Probe VALUES(?,?,?)''',
                                               (bssid, ssid.find("ssid").text, 0))
                            except sqlite3.IntegrityError as error:
                                if verbose:
                                    print(error)

                elif wireless.get("type") == "infrastructure":
                    # ap
                    essid = wireless.find("SSID").find("essid").text
                    if essid is not None:
                        essid = ftfy.fix_text(essid)
                        # print(essid)
                    else:
                        essid = ""
                    bssid = wireless.find("BSSID").text
                    manuf = wireless.find("manuf").text
                    channel = wireless.find("channel").text
                    freqmhz = wireless.find("freqmhz").text.split()[0]
                    carrier = wireless.find("carrier").text
                    manuf = wireless.find("manuf").text
                    if wireless.find("SSID").find("encryption") is not None:
                        encryption = wireless.find("SSID").find("encryption").text
                    else:
                        encryption = ""

                    packets_total = wireless[8].find("total").text

                    try:
                        cursor.execute('''INSERT INTO AP VALUES(?,?,?,?,?,?,?,?,?,?)''',
                                       (bssid, essid, manuf, channel, freqmhz, carrier,
                                        encryption, packets_total, 0, 0))
                    except sqlite3.IntegrityError as error:
                        try:
                            cursor.execute(
                                "UPDATE AP SET packetsTotal = packetsTotal + %s WHERE bssid = '%s'"\
                                    % (packets_total, bssid))
                        except sqlite3.IntegrityError as error:
                            print(error)
                    # print bssid, essid, manuf, channel,freqmhz, carrier, encryption, packetsT

                    # client
                    clients = wireless.findall("wireless-client")
                    for client in clients:
                        client_mac = client.find("client-mac").text
                        manuf = client.find("client-manuf").text
                        packets_total = client.find("packets").find("total").text
                        # print client_mac, manuf, "W", packetsT
                        try:
                            cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                                           (client_mac, '', manuf, 'W', packets_total, 'Misc'))
                        except sqlite3.IntegrityError as error:
                            try:
                                cursor.execute(
                                    "UPDATE client SET packetsTotal = packetsTotal + %s \
                                        WHERE mac = '%s'" % (packets_total, bssid))
                            except sqlite3.IntegrityError as error:
                                print(error)
                        # connected
                        # print (bssid, client_mac)
                        try:
                            cursor.execute(
                                '''INSERT INTO connected VALUES(?,?)''', (bssid, client_mac))
                        except sqlite3.IntegrityError as error:
                            try:
                                cursor.execute(
                                    "UPDATE client SET packetsTotal = packetsTotal + %s \
                                        WHERE mac = '%s'" % (packets_total, bssid))
                            except sqlite3.IntegrityError as error:
                                print(error)
            database.commit()
            print(".kismet.netxml OK")
        else:
            print(".kismet.netxml not exists")
    except Exception as error:
        print(error)
        print("Error in kismet.netxml")

def parse_kismet_csv(name, database, verbose):
    '''Function to parse the .kismet.csv files'''
    exists = os.path.isfile(name+".kismet.csv")
    try:
        cursor = database.cursor()
        if exists:
            with open(name+".kismet.csv") as csv_file:
                csv_reader = csv.reader((x.replace('\0', '')
                                         for x in csv_file), delimiter=';')
                for row in csv_reader:
                    if row and row[0] != "Network":
                        try:
                            bssid = row[3]
                            ssid = row[2]
                            manuf = ""
                            channel = row[5]
                            freq = 0
                            carrier = ""
                            encrypt = row[7]
                            packets_total = row[16]
                            lat = row[34]
                            lon = row[35]

                            cursor.execute('''INSERT INTO AP VALUES(?,?,?,?,?,?,?,?,?,?)''', (
                                bssid, ssid, manuf, channel, freq, carrier,
                                encrypt, packets_total, lat, lon))
                            # manuf y carrier implementar
                        except sqlite3.IntegrityError as error:
                            if verbose:
                                print(error)
                            try:
                                cursor.execute(
                                    "UPDATE AP SET packetsTotal = packetsTotal + %s \
                                        WHERE bssid = '%s'" % (packets_total, bssid))
                            except sqlite3.IntegrityError:
                                print(error)
            database.commit()
            print(".kismet.csv OK")
        else:
            print(".kismet.csv not exists")
    except Exception as error:
        print(error)
        print("Error in kismet.csv")

def parse_csv(name, database, verbose):
    '''Function to parse the .csv files'''
    exists = os.path.isfile(name+".csv")
    try:
        cursor = database.cursor()
        if exists:
            with open(name+".csv") as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                client = False
                for row in csv_reader:
                    if row  and row[0] == "Station MAC":
                        client = True
                    elif row and client:
                        # print(row[0])
                        mac = row[0]
                        packets = row[4]
                        try:
                            cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                                           (mac, '', 'Unknown', 'W', packets, 'Misc'))
                            # manuf implementar
                        except sqlite3.IntegrityError as error:
                            try:
                                cursor.execute(
                                    "UPDATE client SET packetsTotal = packetsTotal + %s \
                                        WHERE mac = '%s'" % (packets, mac))
                            except sqlite3.IntegrityError:
                                if verbose:
                                    print(error)

                        if row[5] != " (not associated) ":
                            try:
                                # print(row[5].replace(' ', ''))
                                cursor.execute(
                                    '''INSERT INTO connected VALUES(?,?)''',
                                    (row[5].replace(' ', ''), row[0]))
                            except sqlite3.IntegrityError as error:
                                if verbose:
                                    print(error)

                        contador = 6
                        while contador < len(row) and row[contador] != "":
                            try:
                                cursor.execute(
                                    '''INSERT INTO Probe VALUES(?,?,?)''',
                                    (row[0], row[contador], 0))
                            except sqlite3.IntegrityError as error:
                                if verbose:
                                    print(error)
                            contador += 1
            database.commit()
            print(".csv OK")
        else:
            print(".csv not exists")
    except Exception as error:
        print(error)
        print("Error in .csv")

def parse_log_csv(name, database, verbose):
    ''' Parse .log.csv file from Aircrack-ng to the database '''
    exists = os.path.isfile(name+".log.csv")
    try:
        cursor = database.cursor()
        if exists:
            with open(name+".log.csv") as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                for row in csv_reader:
                    if row[0] != "LocalTime":
                        if len(row) >= 10 and row[10] == "Client":
                            try:
                                cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                                               (row[3], '', 'Unknown', 'W', -1, 'Misc'))
                            except sqlite3.IntegrityError as error:
                                if verbose:
                                    print(error)

                            try:
                                if row[6] != 0.0:
                                    cursor.execute('''INSERT INTO SeenClient
                                                   VALUES(?,?,?,?,?,?,?)''',
                                                   (row[3], row[0], 'aircrack-ng',
                                                    row[4], row[6], row[7], '0.0'))
                            except sqlite3.IntegrityError as error:
                                if verbose:
                                    print(error)

                        if len(row) >= 10 and row[10] == "AP":

                            try:
                                cursor.execute('''INSERT INTO AP VALUES(?,?,?,?,?,?,?,?,?,?)''', (
                                    row[3], row[2], '', 0, 0, '', '', 0, 0, 0))
                                # manuf y carrier implementar
                            except sqlite3.IntegrityError as error:
                                if verbose:
                                    print(error)

                            try:
                                cursor.execute('''INSERT INTO SeenAp VALUES(?,?,?,?,?,?,?,?)''',
                                               (row[3], row[0], 'aircrack-ng',
                                                row[4], row[6], row[7], '0.0', 0))
                            except sqlite3.IntegrityError as error:
                                if verbose:
                                    print(error)
            database.commit()
            print(".log.csv OK")
        else:
            print(".log.csv not exists")
    except Exception as error:
        print(error)
        print("Error in log")

def main():
    '''Function main. Parse argument and exec the functions '''
    #args
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("database", type=str,
                        help="output database, if exist append to the given database")
    parser.add_argument("capture", type=str,
                        help="capture file (.csv,.kismet.csv, .kismet.netxml, .log.csv), \
                        if no extension add all")
    args = parser.parse_args()

    #vars
    verbose = args.verbose
    name = args.database
    capture = args.capture

    if verbose:
        print("verbosity turned on")


    database = connect_database(name, verbose)
    create_database(database, verbose)
    create_views(database, verbose)
    parse_netxml(capture, database, verbose)
    parse_kismet_csv(capture, database, verbose)
    parse_csv(capture, database, verbose)
    parse_log_csv(capture, database, verbose)


if __name__ == "__main__":
    main()
