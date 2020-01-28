#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
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


def create_database(database, verbose):
    '''Function to create the tables in the database'''
    script_path = os.path.dirname(os.path.abspath( __file__ ))
    path = script_path+'/database.sql'
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
    script_path = os.path.dirname(os.path.abspath( __file__ ))
    path = script_path+'/view.sql'
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


def parse_netxml(ouiMap, name, database, verbose):
    '''Function to parse the .kismet.netxml files'''

    exists = os.path.isfile(name+".kismet.netxml")
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            with open(name+".kismet.netxml", 'r') as file:
                filedata = file.read()
            # fix aircrack error, remove spaces &#x 0;
            filedata = re.sub(r'&#x[ ]+', '&#x', filedata)

            # fix aircrack error, remove NULL byte &#x0;
            filedata = filedata.replace('&#x0;', '')
            filedata = filedata.replace('&#x0;', '')
            if "</detection-run>" not in filedata: #fix xml not well formed, end before write all the file
                if verbose:
                    print("ERROR, not end")
                filedata= filedata[:filedata.rfind("<wireless-network ")] + " </detection-run>"

            raiz = ET.fromstring(filedata)
            for wireless in raiz:
                if wireless.get("type") == "probe":
                    bssid = wireless.find("BSSID").text
                    manuf = oui.get_vendor(ouiMap, bssid)
                    packets_total = wireless.find("packets").find("total").text
                    if verbose:
                        print (bssid, manuf, "W", packets_total)
                    try:
                        cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                                       (bssid, '', manuf , 'W', packets_total, 'Misc'))
                    except sqlite3.IntegrityError as error:
                        errors += 1
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
                            essid = ftfy.fix_text(ssid.find("ssid").text)
                            try:
                                cursor.execute('''INSERT INTO Probe VALUES(?,?,?)''',
                                               (bssid, essid, 0))
                            except sqlite3.IntegrityError as error:
                                errors += 1
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
                    # manuf = wireless.find("manuf").text
                    channel = wireless.find("channel").text
                    freqmhz = wireless.find("freqmhz").text.split()[0]
                    carrier = wireless.find("carrier").text
                    

                    manuf = oui.get_vendor(ouiMap, bssid)

                    if wireless.find("SSID").find("encryption") is not None:
                        encryption = wireless.find("SSID").find("encryption").text
                    else:
                        encryption = ""
                        

                    lat = "0.0"
                    lon = "0.0"
                    gps_info=wireless.find("gps-info")
                    if gps_info is not None:
                        if gps_info.find("max-lat") is not None:
                            lat = gps_info.find("max-lat").text
                            lon = gps_info.find("max-lon").text
                        else:
                            lat = "0.0"
                            lon = "0.0"

                    packets_total = wireless[8].find("total").text

                    try:
                        cursor.execute('''INSERT INTO AP VALUES(?,?,?,?,?,?,?,?,?,?)''',
                                       (bssid, essid, manuf, channel, freqmhz, carrier,
                                        encryption, packets_total, lat, lon))
                    except sqlite3.IntegrityError as error:
                        errors += 1
                        try:
                            cursor.execute(
                                "UPDATE AP SET packetsTotal = packetsTotal + %s WHERE bssid = '%s'"\
                                    % (packets_total, bssid))
                            cursor.execute(
                                "UPDATE AP SET lat_t = CASE WHEN lat_t == 0.0 THEN ('%s') ELSE lat_t "\
                                    "END, lon_t = CASE WHEN lon_t == 0.0 THEN ('%s') ELSE lon_t END "\
                                        "WHERE bssid = '%s'" % (lat, lon, bssid))

                        except sqlite3.IntegrityError as error:
                            print("a"+error)
                    # print bssid, essid, manuf, channel,freqmhz, carrier, encryption, packetsT

                    # client
                    clients = wireless.findall("wireless-client")
                    for client in clients:
                        client_mac = client.find("client-mac").text
                        manuf = oui.get_vendor(ouiMap, client_mac)

                        packets_total = client.find("packets").find("total").text
                        # print (client_mac, manuf, "W", packets_total)
                        try:
                            cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                                           (client_mac, '', manuf, 'W', packets_total, 'Misc'))
                        except sqlite3.IntegrityError as error:
                            errors += 1
                            try:
                                cursor.execute(
                                    "UPDATE client SET packetsTotal = packetsTotal + %s \
                                        WHERE mac = '%s'" % (packets_total, client_mac))
                            except sqlite3.IntegrityError as error:
                                print(error)
                        # connected
                        # print (bssid, client_mac)
                        try:
                            cursor.execute(
                                '''INSERT INTO connected VALUES(?,?)''', (bssid, client_mac))
                        except sqlite3.IntegrityError as error:
                            errors += 1
                            try:
                                cursor.execute(
                                    "UPDATE client SET packetsTotal = packetsTotal + %s \
                                        WHERE mac = '%s'" % (packets_total, bssid))
                            except sqlite3.IntegrityError as error:
                                print(error)
            database.commit()
            if verbose:
                print(".kismet.netxml OK, lines with errors or duplicates:", errors)
            else:
                print(".kismet.netxml OK")

        else:
            print(".kismet.netxml not exists")
    except Exception as error:
        print(error)
        print("Error in kismet.netxml")

def parse_kismet_csv(ouiMap, name, database, verbose):
    '''Function to parse the .kismet.csv files'''    
    
    exists = os.path.isfile(name+".kismet.csv")
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            with open(name+".kismet.csv") as csv_file:
                csv_reader = csv.reader((x.replace('\0', '')
                                         for x in csv_file), delimiter=';')
                for row in csv_reader:
                    if len(row)>35 and row[0] != "Network":
                        try:
                            bssid = row[3]
                            ssid = row[2]
                            
                            manuf = oui.get_vendor(ouiMap, bssid)
                            
                            channel = row[5]
                            freq = 0
                            carrier = ""
                            encrypt = row[7]
                            packets_total = row[16]
                            lat = row[32]
                            lon = row [33]

                            cursor.execute('''INSERT INTO AP VALUES(?,?,?,?,?,?,?,?,?,?)''', (
                                bssid, ssid, manuf, channel, freq, carrier,
                                encrypt, packets_total, lat, lon))
                            # manuf y carrier implementar
                        except sqlite3.IntegrityError as error:
                            errors += 1
                            if verbose:
                                print(error)
                            try:
                                cursor.execute(
                                    "UPDATE AP SET packetsTotal = packetsTotal + %s \
                                        WHERE bssid = '%s'" % (packets_total, bssid))
                                
                                cursor.execute(
                                "UPDATE AP SET lat_t = CASE WHEN lat_t == 0.0 THEN ('%s') ELSE lat_t "\
                                    "END, lon_t = CASE WHEN lon_t == 0.0 THEN ('%s') ELSE lon_t END "\
                                        "WHERE bssid = '%s'"\
                                    % (lat, lon, bssid))
                            except sqlite3.IntegrityError:
                                print(error)
            database.commit()
            if verbose:
                print(".kismet.csv OK, lines with errors or duplicates:", errors)
            else:
                print(".kismet.csv OK")
        else:
            print(".kismet.csv not exists")
    except Exception as error:
        print(error)
        print("Error in kismet.csv")

def parse_csv(ouiMap, name, database, verbose):
    '''Function to parse the .csv files'''
   
    exists = os.path.isfile(name+".csv")
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            with open(name+".csv") as csv_file:
                csv_reader = csv.reader((x.replace('\0', '')
                                         for x in csv_file), delimiter=',')
                client = False
                for row in csv_reader:
                    if row:
                        if client == False and len(row)>13 and row[0] != "BSSID":
                            #insert AP de aqui tambien
                            bssid = row[0]
                            essid = row[13]
                            manuf = oui.get_vendor(ouiMap, bssid)
                            channel = row[3]
                            freq = ""
                            carrier = ""
                            encrypt = row[5] + row[6] + row[7]
                            packets_total = row[10]
                            try:
                                cursor.execute('''INSERT INTO AP VALUES(?,?,?,?,?,?,?,?,?,?)''', (
                                    bssid, essid[1:], manuf, channel, freq, carrier,
                                    encrypt, packets_total, 0, 0))
                            except sqlite3.IntegrityError as error:
                                if verbose:
                                    print(error)
                        
                        
                        if row  and row[0] == "Station MAC":
                            client = True
                        elif row and client and len(row) > 5:
                            # print(row[0])
                            mac = row[0]
                            manuf = oui.get_vendor(ouiMap, mac)
                            packets = row[4]
                            # print(mac, manuf)

                            try:
                                cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                                            (mac, '', manuf, 'W', packets, 'Misc'))
                                # manuf implementar
                            except sqlite3.IntegrityError as error:
                                errors += 1
                                try:
                                    cursor.execute(
                                        "UPDATE client SET packetsTotal = packetsTotal + %s \
                                            WHERE mac = '%s'" % (packets, mac))
                                except sqlite3.IntegrityError:
                                    if verbose:
                                        print(error)

                            if len(row)>5 and row[5] != " (not associated) ":
                                try:
                                    # print(row[5].replace(' ', ''))
                                    cursor.execute(
                                        '''INSERT INTO connected VALUES(?,?)''',
                                        (row[5].replace(' ', ''), row[0]))
                                except sqlite3.IntegrityError as error:
                                    errors += 1
                                    if verbose:
                                        print(error)

                            contador = 6
                            while contador < len(row) and row[contador] != "":
                                try:
                                    cursor.execute(
                                        '''INSERT INTO Probe VALUES(?,?,?)''',
                                        (row[0], row[contador], 0))
                                except sqlite3.IntegrityError as error:
                                    errors += 1
                                    if verbose:
                                        print(error)
                                contador += 1
            database.commit()
            if verbose:
                print(".csv OK, lines with errors or duplicates:", errors)
            else:
                print(".csv OK")
        else:
            print(".csv not exists")
    except Exception as error:
        print(error)
        print("Error in .csv")

def parse_log_csv(ouiMap, name, database, verbose):
    ''' Parse .log.csv file from Aircrack-ng to the database '''    
    
    exists = os.path.isfile(name+".log.csv")
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            with open(name+".log.csv") as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                for row in csv_reader:
                    if row[0] != "LocalTime":
                        if len(row) > 10 and row[10] == "Client":
                            try:
                                manuf = oui.get_vendor(ouiMap, row[3])
                                cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?)''',
                                               (row[3], '', manuf, 'W', -1, 'Misc'))
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
                                errors += 1
                                if verbose:
                                    print(error)

                        if len(row) > 10 and row[10] == "AP":

                            try:
                                manuf = oui.get_vendor(ouiMap, row[3])
                                    
                                cursor.execute('''INSERT INTO AP VALUES(?,?,?,?,?,?,?,?,?,?)''', (
                                    row[3], row[2], manuf, 0, 0, '', '', 0, row[6], row[7]))
                                # manuf y carrier implementar
                            except sqlite3.IntegrityError as error:
                                cursor.execute(
                                "UPDATE AP SET lat_t = CASE WHEN lat_t == 0.0 THEN ('%s') ELSE lat_t "\
                                    "END, lon_t = CASE WHEN lon_t == 0.0 THEN ('%s') ELSE lon_t END "\
                                        "WHERE bssid = '%s'" % (row[6], row[7], row[3]))
                                if verbose:
                                    print(error)

                            # if row[6] != "0.000000":
                            try:
                                cursor.execute('''INSERT INTO SeenAp VALUES(?,?,?,?,?,?,?,?)''',
                                            (row[3], row[0], 'aircrack-ng',
                                                row[4], row[6], row[7], '0.0', 0))
                            except sqlite3.IntegrityError as error:
                                errors += 1
                                if verbose:
                                    print(error)
                    
                            
            database.commit()
            if verbose:
                print(".log.csv OK, lines with errors or duplicates:", errors)
            else:
                print(".log.csv OK")
        else:
            print(".log.csv not exists")
    except Exception as error:
        print(error)
        print("Error in log")

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
        print(error)
                            
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
        print(error)

      
def main():
    '''Function main. Parse argument and exec the functions '''
    #args
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("-f", "--folder", help="insert a folder",
                        action="store_true")

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

    if verbose:
        print("verbosity turned on")


    database = connect_database(name, verbose)
    create_database(database, verbose)
    create_views(database, verbose)
    
    
    ouiMap = oui.load_vendors()
    
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
            parse_netxml(ouiMap, capture_aux, database, verbose)
            parse_kismet_csv(ouiMap, capture_aux, database, verbose)
            parse_csv(ouiMap, capture_aux, database, verbose)
            parse_log_csv(ouiMap, capture_aux, database, verbose)
    else:
        parse_netxml(ouiMap, capture, database, verbose)
        parse_kismet_csv(ouiMap, capture, database, verbose)
        parse_csv(ouiMap, capture, database, verbose)
        parse_log_csv(ouiMap, capture, database, verbose)


if __name__ == "__main__":
    main()


'''
UPDATE AP
SET lat_t = CASE WHEN lat_t == 0.0 THEN (123) ELSE lat_t END
WHERE bssid="C8:F9:F9:4D:73:42";
'''
