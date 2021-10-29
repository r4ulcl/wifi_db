#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-
import csv
import xml.etree.ElementTree as ET
import os
import re
import oui
import ftfy
import database_utils


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
            # fix xml not well formed, end before write all the file
            if "</detection-run>" not in filedata:
                if verbose:
                    print("ERROR, not end")
                filedata = filedata[:filedata.rfind("<wireless-network ")]
                filedata += "</detection-run>"

            raiz = ET.fromstring(filedata)
            for wireless in raiz:
                if wireless.get("type") == "probe":
                    bssid = wireless.find("BSSID").text
                    manuf = oui.get_vendor(ouiMap, bssid)
                    packets_total = wireless.find("packets").find("total").text
                    if verbose:
                        print(bssid, manuf, "W", packets_total)

                    errors += database_utils.insertClients(
                        cursor, verbose, bssid, '',
                        manuf, 'W', packets_total, 'Misc')

                    # probe
                    ssid1 = wireless.find("wireless-client").find("SSID")
                    ssid = ssid1.find("ssid")
                    if ssid is not None:
                        client = wireless.find("wireless-client")
                        essid_probe = client.findall("SSID")
                        for ssid in essid_probe:
                            # print bssid, ssid.find("ssid").text
                            essid = ftfy.fix_text(ssid.find("ssid").text)
                            errors += database_utils.insertProbe(
                                cursor, verbose, bssid, essid, 0)

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
                        encryption = ""
                        for e in wireless.find("SSID").findall("encryption"):
                            encryption += e.text + ", "
                    else:
                        encryption = ""

                    lat = "0.0"
                    lon = "0.0"
                    gps_info = wireless.find("gps-info")
                    if gps_info is not None:
                        if gps_info.find("max-lat") is not None:
                            lat = gps_info.find("max-lat").text
                            lon = gps_info.find("max-lon").text
                        else:
                            lat = "0.0"
                            lon = "0.0"

                    packets_total = wireless[8].find("total").text

                    errors += database_utils.insertAP(
                        cursor, verbose, bssid, essid, manuf, channel,
                        freqmhz, carrier, encryption, packets_total, lat, lon)

                    # client
                    clients = wireless.findall("wireless-client")
                    for client in clients:
                        client_mac = client.find("client-mac").text
                        manuf = oui.get_vendor(ouiMap, client_mac)

                        packets = client.find("packets")
                        packets_total = packets.find("total").text
                        # print (client_mac, manuf, "W", packets_total)
                        errors += database_utils.insertClients(
                            cursor, verbose, client_mac, '', manuf,
                            'W', packets_total, 'Misc')

                        # connected
                        # print (bssid, client_mac)
                        errors += database_utils.insertConnected(
                            cursor, verbose, bssid, client_mac)
            database.commit()
            print(".kismet.netxml OK, errors", errors)
        else:
            print(".kismet.netxml missing")
    except Exception as error:
        print("parse_netxml " + str(error))
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
                    if len(row) > 35 and row[0] != "Network":
                        try:
                            bssid = row[3]
                            essid = row[2]
                            essid = essid.replace("'", "''")

                            manuf = oui.get_vendor(ouiMap, bssid)

                            channel = row[5]
                            freqmhz = -1
                            carrier = ""
                            encryption = row[7]
                            packets_total = row[16]
                            lat = row[32]
                            lon = row[33]

                            errors += database_utils.insertAP(
                                cursor, verbose, bssid, essid, manuf, channel,
                                freqmhz, carrier, encryption, packets_total,
                                lat, lon)
                            # manuf y carrier implementar
                        except Exception as error:
                            if verbose:
                                print("Uncontrolled error UPDATE AP "
                                      "kismet csv: ", error)

            database.commit()
            print(".kismet.csv OK, errors", errors)
        else:
            print(".kismet.csv missing")
    except Exception as error:
        print("parse_kismet_csv " + str(error))
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
                        if client is False and len(row) > 13 \
                           and row[0] != "BSSID":
                            # insert AP de aqui tambien
                            bssid = row[0]
                            essid = row[13]
                            essid = essid.replace("'", "''")
                            manuf = oui.get_vendor(ouiMap, bssid)
                            channel = row[3]
                            freq = ""
                            carrier = ""
                            encrypt = row[5] + row[6] + row[7]
                            packets_total = row[10]

                            errors += database_utils.insertAP(
                                cursor, verbose,  bssid, essid[1:], manuf,
                                channel, freq, carrier, encrypt,
                                packets_total, 0, 0)

                        if row and row[0] == "Station MAC":
                            client = True
                        elif row and client and len(row) > 5:
                            # print(row[0])
                            mac = row[0]
                            manuf = oui.get_vendor(ouiMap, mac)
                            packets = row[4]
                            # print(mac, manuf)

                            errors += database_utils.insertClients(
                                cursor, verbose, mac, '', manuf, 'W',
                                packets, 'Misc')

                            if len(row) > 5 and row[5] != " (not associated) ":
                                a = database_utils.insertConnected(
                                    cursor, verbose, row[5].replace(' ', ''),
                                    row[0])

                                errors += a

                            contador = 6
                            while contador < len(row) and row[contador] != "":
                                errors += database_utils.insertProbe(
                                    cursor, verbose, row[0], row[contador], 0)
                                contador += 1
            database.commit()

            print(".csv OK, errors", errors)
        else:
            print(".csv missing")
    except Exception as error:
        print("parse_csv " + str(error))
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
                            manuf = oui.get_vendor(ouiMap, row[3])
                            if row[6] != 0.0:
                                errors += database_utils.insertSeenClient(
                                    cursor, verbose, row[3], row[0],
                                    'aircrack-ng', row[4], row[6],
                                    row[7], '0.0')

                        if len(row) > 10 and row[10] == "AP":
                            manuf = oui.get_vendor(ouiMap, row[3])
                            errors += database_utils.insertAP(
                                cursor, verbose,  row[3], row[2], manuf, 0,
                                0, '', '', 0, row[6], row[7])

                            # if row[6] != "0.000000":
                            errors += database_utils.insertSeenAP(
                                cursor, verbose,  row[3], row[0],
                                'aircrack-ng', row[4], row[6], row[7],
                                '0.0', 0)

            database.commit()
            print(".log.csv done, errors", errors)
        else:
            print(".log.csv missing")
    except Exception as error:
        print("parse_log_csv " + str(error))
        print("Error in log")
