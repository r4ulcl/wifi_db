''' Parse the text-based Aircrack/Kismet/Wigle CSV outputs (.kismet.csv,
airodump .csv and .log.csv) into the SQLite DB. The .kismet.netxml parser
lives in netxml_parser. These parsers do not need pyshark/tshark. '''
# -*- coding: utf-8 -*-
import csv
import os

from utils import oui
from utils import database_utils


def _is_ap_row(row):
    '''True when an airodump .csv row is an AP row (not the BSSID header).'''
    return len(row) > 13 and row[0] != "BSSID"


def _csv_insert_ap(cursor, verbose, ouiMap, row):
    '''Insert one AP row from an airodump-ng .csv. Returns insert errors.'''
    bssid = row[0]
    firstTimeSeen = row[1]
    essid = row[13].replace("'", "''")
    manuf = oui.get_vendor(ouiMap, bssid, verbose)
    encrypt = row[5] + row[6] + row[7]
    return database_utils.insertAP(
        cursor, verbose, database_utils.APRow(
            bssid=bssid, essid=essid[1:], manuf=manuf, channel=row[3],
            freqmhz="", carrier="", encryption=encrypt, packets_total=row[10],
            lat=0, lon=0, cloaked='False', mfpc='False', mfpr='False',
            firstTimeSeen=firstTimeSeen))


def _csv_insert_station(cursor, verbose, ouiMap, row):
    '''Insert one station row (plus its connection and probes) from a .csv.'''
    mac = row[0]
    firstTimeSeen = row[1]
    manuf = oui.get_vendor(ouiMap, mac, verbose)
    errors = database_utils.insertClients(
        cursor, verbose, database_utils.ClientRow(
            mac=mac, ssid='', manuf=manuf, client_type='W',
            packets_total=row[4], device='Misc', firstTimeSeen=firstTimeSeen))
    if len(row) > 5 and row[5] != " (not associated) ":
        errors += database_utils.insertConnected(
            cursor, verbose, row[5].replace(' ', ''), row[0])
    contador = 6
    while contador < len(row) and row[contador] != "":
        errors += database_utils.insertProbe(
            cursor, verbose, row[0], row[contador], 0)
        contador += 1
    return errors


def _parse_csv_rows(cursor, verbose, ouiMap, csv_reader):
    '''Insert APs then stations from an airodump-ng .csv reader. Returns errors.

    The file lists every AP first, then a "Station MAC" header, then the
    stations; `client` flips to True once that header is reached.'''
    errors = 0
    client = False
    for row in csv_reader:
        if not row:
            continue
        if client is False and _is_ap_row(row):
            errors += _csv_insert_ap(cursor, verbose, ouiMap, row)
        if row[0] == "Station MAC":
            client = True
        elif client and len(row) > 5:
            errors += _csv_insert_station(cursor, verbose, ouiMap, row)
    return errors


def parse_csv(ouiMap, name, database, verbose):
    '''Function to parse the .csv files'''
    errors = 0
    if not os.path.isfile(name):
        print(".csv missing")
        return
    try:
        cursor = database.cursor()
        with open(name, encoding='utf-8') as csv_file:
            csv_reader = csv.reader(
                (x.replace('\0', '') for x in csv_file), delimiter=',')
            errors += _parse_csv_rows(cursor, verbose, ouiMap, csv_reader)
        database.commit()
        print(".csv OK, errors", errors)
    except Exception as error:
        errors += 1
        print("parse_csv " + str(error))
        print("Error in .csv")
        print(".csv OK, errors", errors)
