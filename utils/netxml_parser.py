''' Parse the Kismet .kismet.netxml output into the SQLite DB. Split out of
text_parsers to keep each parser module small; needs no pyshark/tshark. '''
# -*- coding: utf-8 -*-
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
