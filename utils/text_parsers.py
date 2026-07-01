''' Parse the text-based Aircrack/Kismet/Wigle outputs (.kismet.netxml,
.kismet.csv, airodump .csv and .log.csv) into the SQLite DB. These parsers do
not need pyshark/tshark. '''
# -*- coding: utf-8 -*-
import csv
import datetime
import os
import re
# import xml.etree.ElementTree as ET # vuln!
import defusedxml.ElementTree as ET
import ftfy

from utils import oui
from utils import database_utils


def _netxml_read_root(filename, verbose):
    '''Read a .kismet.netxml file, repair the known aircrack quirks and return
    the parsed XML root element.'''
    with open(filename, 'r', encoding='utf-8') as file:
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

    return ET.fromstring(filedata)


def _netxml_parse_probe(cursor, verbose, ouiMap, wireless):
    '''Insert the client and probe rows for a netxml "probe" entry. Returns the
    number of insert errors.'''
    errors = 0
    bssid = wireless.find("BSSID").text
    manuf = oui.get_vendor(ouiMap, bssid, verbose)
    packets_total = wireless.find("packets").find("total").text
    if verbose:
        print(bssid, manuf, "W", packets_total)

    errors += database_utils.insertClients(
        cursor, verbose, database_utils.ClientRow(
            mac=bssid, ssid='', manuf=manuf, client_type='W',
            packets_total=packets_total, device='Misc', firstTimeSeen=0))

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
    return errors


def _netxml_parse_infra_clients(cursor, verbose, ouiMap, wireless, bssid):
    '''Insert the client and connection rows for an "infrastructure" entry.
    Returns the number of insert errors.'''
    errors = 0
    clients = wireless.findall("wireless-client")
    for client in clients:
        client_mac = client.find("client-mac").text
        manuf = oui.get_vendor(ouiMap, client_mac, verbose)

        firstTimeSeen_string = client.attrib['first-time']
        date_object = datetime.datetime.strptime(
            firstTimeSeen_string, "%a %b %d %H:%M:%S %Y"
        )
        firstTimeSeen = date_object.strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        packets = client.find("packets")
        packets_total = packets.find("total").text
        # print (client_mac, manuf, "W", packets_total)
        errors += database_utils.insertClients(
            cursor, verbose, database_utils.ClientRow(
                mac=client_mac, ssid='', manuf=manuf, client_type='W',
                packets_total=packets_total, device='Misc',
                firstTimeSeen=firstTimeSeen))

        # connected
        # print (bssid, client_mac)
        errors += database_utils.insertConnected(
            cursor, verbose, bssid, client_mac)
    return errors


def _netxml_coords(wireless):
    '''(lat, lon) from a netxml entry's gps-info, defaulting to "0.0".'''
    gps_info = wireless.find("gps-info")
    if gps_info is not None and gps_info.find("max-lat") is not None:
        return gps_info.find("max-lat").text, gps_info.find("max-lon").text
    return "0.0", "0.0"


def _netxml_parse_infrastructure(cursor, verbose, ouiMap, wireless):
    '''Insert the AP, client and connection rows for a netxml
    "infrastructure" entry. Returns the number of insert errors.'''
    errors = 0
    # ap
    essid = wireless.find("SSID").find("essid").text
    if essid is not None:
        essid = ftfy.fix_text(essid)
        # print(essid)
    else:
        essid = ""

    cloakedtxt = wireless.find("SSID").find(
        "essid").attrib['cloaked']
    # print("cloaked: " + cloakedtxt)
    if cloakedtxt == "true":
        cloaked = 'True'  # ftfy.fix_text(cloaked)
        # print(essid)
    else:
        cloaked = 'False'

    bssid = wireless.find("BSSID").text
    # manuf = wireless.find("manuf").text
    channel = wireless.find("channel").text
    freqmhz = wireless.find("freqmhz").text.split()[0]
    carrier = wireless.find("carrier").text

    # firstTimeSeen
    firstTimeSeen_string = wireless.find(
        "SSID"
    ).attrib['first-time']
    date_object = datetime.datetime.strptime(
        firstTimeSeen_string, "%a %b %d %H:%M:%S %Y"
    )
    firstTimeSeen = date_object.strftime("%Y-%m-%d %H:%M:%S")

    manuf = oui.get_vendor(ouiMap, bssid, verbose)

    if wireless.find("SSID").find("encryption") is not None:
        encryption = ""
        for e in wireless.find("SSID").findall("encryption"):
            encryption += e.text + ", "
    else:
        encryption = ""

    lat, lon = _netxml_coords(wireless)

    packets_total = wireless[8].find("total").text

    errors += database_utils.insertAP(
        cursor, verbose, database_utils.APRow(
            bssid=bssid, essid=essid, manuf=manuf, channel=channel,
            freqmhz=freqmhz, carrier=carrier, encryption=encryption,
            packets_total=packets_total, lat=lat, lon=lon, cloaked=cloaked,
            mfpc='False', mfpr='False', firstTimeSeen=firstTimeSeen))

    # client
    errors += _netxml_parse_infra_clients(
        cursor, verbose, ouiMap, wireless, bssid)
    return errors


def parse_netxml(ouiMap, name, database, verbose):
    '''Function to parse the .kismet.netxml files'''

    filename = name
    exists = os.path.isfile(filename)
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            raiz = _netxml_read_root(filename, verbose)
            for wireless in raiz:
                if wireless.get("type") == "probe":
                    errors += _netxml_parse_probe(
                        cursor, verbose, ouiMap, wireless)
                elif wireless.get("type") == "infrastructure":
                    errors += _netxml_parse_infrastructure(
                        cursor, verbose, ouiMap, wireless)
            database.commit()
            print(".kismet.netxml OK, errors", errors)
        else:
            print(".kismet.netxml missing")
    except Exception as error:
        errors += 1
        print("parse_netxml " + str(error))
        print("Error in kismet.netxml")
        print(".kismet.netxml OK, errors", errors)


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
