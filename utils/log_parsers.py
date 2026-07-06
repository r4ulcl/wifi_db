''' Parse the Kismet .kismet.csv and Aircrack-ng .log.csv (GPS log) outputs
into the SQLite DB. These parsers do not need pyshark/tshark. The airodump
.csv parser lives in text_parsers. '''
# -*- coding: utf-8 -*-
import csv
import datetime
import os

from utils import oui
from utils import database_utils


def _kismet_insert_ap(cursor, verbose, ouiMap, row):
    '''Insert one AP row from a .kismet.csv. A per-row parse error is logged but
    not counted (matching the original), so it returns 0 in that case.'''
    try:
        bssid = row[3]
        essid = row[2].replace("'", "''")
        date_object = datetime.datetime.strptime(
            row[19], "%a %b %d %H:%M:%S %Y")
        firstTimeSeen = date_object.strftime("%Y-%m-%d %H:%M:%S")
        manuf = oui.get_vendor(ouiMap, bssid, verbose)
        return database_utils.insertAP(
            cursor, verbose, database_utils.APRow(
                bssid=bssid, essid=essid, manuf=manuf, channel=row[5],
                freqmhz=0, carrier="", encryption=row[7], packets_total=row[16],
                lat=row[32], lon=row[33], cloaked='False', mfpc='False',
                mfpr='False', firstTimeSeen=firstTimeSeen))
    except Exception as error:
        if verbose:
            print("Uncontrolled error UPDATE AP kismet csv: ", error)
        return 0


def parse_kismet_csv(ouiMap, name, database, verbose):
    '''Function to parse the .kismet.csv files'''
    errors = 0
    if not os.path.isfile(name):
        print(".kismet.csv missing")
        return
    try:
        cursor = database.cursor()
        with open(name, encoding='utf-8') as csv_file:
            csv_reader = csv.reader(
                (x.replace('\0', '') for x in csv_file), delimiter=';')
            for row in csv_reader:
                if len(row) > 35 and row[0] != "Network":
                    errors += _kismet_insert_ap(cursor, verbose, ouiMap, row)
        database.commit()
        print(".kismet.csv OK, errors", errors)
    except Exception as error:
        errors += 1
        print("parse_kismet_csv " + str(error))
        print("Error in kismet.csv")
        print(".kismet.csv OK, errors", errors)


def _coords(row, fake_lat, fake_lon):
    '''Resolve (lat, lon) for a .log.csv row, honoring the fake overrides.'''
    lat = fake_lat if fake_lat != "" else row[6]
    lon = fake_lon if fake_lon != "" else row[7]
    return lat, lon


def _log_insert_client(cursor, verbose, ouiMap, row, time, fake_lat, fake_lon):
    '''Insert a client and its sighting from a .log.csv row. Returns errors.'''
    mac = row[3]
    manuf = oui.get_vendor(ouiMap, mac, verbose)
    lat, lon = _coords(row, fake_lat, fake_lon)
    errors = database_utils.insertClients(
        cursor, verbose, database_utils.ClientRow(
            mac=mac, ssid="", manuf=manuf, client_type="", packets_total="",
            device="", firstTimeSeen=time))
    errors += database_utils.insertSeenClient(
        cursor, verbose, database_utils.SeenClientRow(
            mac=mac, time=time, tool='aircrack-ng', signal_rssi=row[4],
            lat=lat, lon=lon, alt='0.0'))
    return errors


def _log_insert_ap(cursor, verbose, ouiMap, row, time, fake_lat, fake_lon):
    '''Insert an AP and its sighting from a .log.csv row. Returns errors.'''
    manuf = oui.get_vendor(ouiMap, row[3], verbose)
    lat, lon = _coords(row, fake_lat, fake_lon)
    errors = database_utils.insertAP(
        cursor, verbose, database_utils.APRow(
            bssid=row[3], essid=row[2], manuf=manuf, channel=0, freqmhz=0,
            carrier='', encryption='', packets_total=0, lat=lat, lon=lon,
            cloaked='False', mfpc='False', mfpr='False', firstTimeSeen=time))
    errors += database_utils.insertSeenAP(
        cursor, verbose, database_utils.SeenAPRow(
            bssid=row[3], time=time, tool='aircrack-ng', signal_rsi=row[4],
            lat=lat, lon=lon, alt='0.0', bsstimestamp=0))
    return errors


def parse_log_csv(ouiMap, name, database, verbose, fake_lat, fake_lon):
    ''' Parse .log.csv file from Aircrack-ng to the database '''
    errors = 0
    if not os.path.isfile(name):
        print(".log.csv missing")
        return
    try:
        cursor = database.cursor()
        with open(name, encoding='utf-8') as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            for row in csv_reader:
                time = row[0]
                if time == "LocalTime":
                    continue
                # `kind` (and thus the row[6]/row[7] coords) is only read when
                # len(row) > 10, so short rows cannot raise an IndexError.
                kind = row[10] if len(row) > 10 else ""
                if kind == "Client":
                    errors += _log_insert_client(cursor, verbose, ouiMap, row,
                                                 time, fake_lat, fake_lon)
                elif kind == "AP":
                    errors += _log_insert_ap(cursor, verbose, ouiMap, row,
                                             time, fake_lat, fake_lon)
        database.commit()
        print(".log.csv done, errors", errors)
    except Exception as error:
        errors += 1
        print("parse_log_csv " + str(error))
        print("Error in log")
        print(".log.csv done, errors", errors)
