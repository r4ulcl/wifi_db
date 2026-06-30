#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-
import csv
import os
import re
# import platform
import asyncio
import binascii
import contextlib
import datetime
import subprocess  # nosec B404 - only used with a fixed, absolute-path command
# import xml.etree.ElementTree as ET # vuln!
import defusedxml.ElementTree as ET
import ftfy


# Python 3.14 removed the asyncio child-watcher API (get_child_watcher /
# set_child_watcher / AbstractChildWatcher / *ChildWatcher classes). pyshark
# 0.6 and nest_asyncio still reference it; on 3.14 the event loop manages
# subprocesses on its own, so install no-op shims to keep pyshark's
# FileCapture working. Must run before pyshark is imported/used and before
# nest_asyncio.apply(). Each name is checked independently in case a given
# Python version only removed some of them.
class _NullChildWatcher:
    '''Minimal stand-in for the removed asyncio child watcher.'''
    def __init__(self, *args, **kwargs):
        pass

    def attach_loop(self, loop):
        pass

    def add_child_handler(self, *args, **kwargs):
        pass

    def remove_child_handler(self, *args, **kwargs):
        return True

    def close(self):
        pass

    def is_active(self):
        return True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


_NULL_CHILD_WATCHER = _NullChildWatcher()
if not hasattr(asyncio, "get_child_watcher"):
    asyncio.get_child_watcher = lambda *a, **k: _NULL_CHILD_WATCHER
if not hasattr(asyncio, "set_child_watcher"):
    asyncio.set_child_watcher = lambda *a, **k: None
for _watcher_name in ("AbstractChildWatcher", "SafeChildWatcher",
                      "ThreadedChildWatcher", "FastChildWatcher",
                      "PidfdChildWatcher", "MultiLoopChildWatcher"):
    if not hasattr(asyncio, _watcher_name):
        setattr(asyncio, _watcher_name, _NullChildWatcher)

import pyshark  # noqa: E402  (imported after the child-watcher shim above)
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import (NameOID, ExtensionOID,
                                   AuthorityInformationAccessOID)
from utils import oui
from utils import database_utils


# EAP method types as registered by IANA, used to label the authentication
# method seen for each identity.
# https://www.iana.org/assignments/eap-numbers/eap-numbers.xhtml
# Type 1 (Identity) is handled separately to capture the identity string.
EAP_METHOD_TYPES = {
    '2': "EAP-Notification",
    '3': "EAP-Legacy-Nak",
    '4': "EAP-MD5",
    '5': "EAP-OTP",
    '6': "EAP-GTC",
    '9': "EAP-RSA",
    '10': "EAP-DSS",
    '11': "EAP-KEA",
    '12': "EAP-KEA-VALIDATE",
    '13': "EAP-TLS",
    '15': "EAP-SecurID",
    '17': "EAP-LEAP",
    '18': "EAP-SIM",
    '19': "EAP-SRP-SHA1",
    '21': "EAP-TTLS",
    '23': "EAP-AKA",
    '25': "EAP-PEAP",
    '26': "MS-EAP-Authentication",
    '29': "EAP-MSCHAPv2",
    '43': "EAP-FAST",
    '46': "EAP-PAX",
    '47': "EAP-PSK",
    '48': "EAP-SAKE",
    '49': "EAP-IKEv2",
    '50': "EAP-AKA'",
    '51': "EAP-GPSK",
    '52': "EAP-pwd",
    '53': "EAP-EKE",
    '54': "EAP-PT",
    '55': "EAP-TEAP",
}


# RSN AKM (Authentication and Key Management) suite selectors, OUI 00-0F-AC.
# https://www.iana.org/assignments/... (IEEE 802.11 RSN suite types)
RSN_AKM_SUITES = {
    '1': "802.1X",
    '2': "PSK",
    '3': "FT-802.1X",
    '4': "FT-PSK",
    '5': "802.1X-SHA256",
    '6': "PSK-SHA256",
    '7': "TDLS",
    '8': "SAE",
    '9': "FT-SAE",
    '10': "AP-PeerKey",
    '11': "802.1X-SuiteB-SHA256",
    '12': "802.1X-SuiteB-SHA384",
    '13': "FT-802.1X-SHA384",
    '14': "FILS-SHA256",
    '15': "FILS-SHA384",
    '16': "FT-FILS-SHA256",
    '17': "FT-FILS-SHA384",
    '18': "OWE",
    '19': "FT-PSK-SHA384",
    '20': "PSK-SHA384",
}

# AKM selectors that indicate an enterprise (802.1X / EAP) network.
RSN_ENTERPRISE_AKMS = {1, 3, 5, 11, 12, 13, 14, 15, 16, 17}

# RSN cipher suite selectors, OUI 00-0F-AC.
RSN_CIPHERS = {
    '0': "Use-Group",
    '1': "WEP-40",
    '2': "TKIP",
    '4': "CCMP-128",
    '5': "WEP-104",
    '6': "BIP-CMAC-128",
    '8': "GCMP-128",
    '9': "GCMP-256",
    '10': "CCMP-256",
    '11': "BIP-GMAC-128",
    '12': "BIP-GMAC-256",
    '13': "BIP-CMAC-256",
}

# 802.11 management-frame element (tag) numbers used to detect AP capabilities.
TAG_MOBILITY_DOMAIN = 54   # 802.11r Fast BSS Transition (MDE)
TAG_RM_ENABLED_CAP = 70    # 802.11k Radio Resource Measurement (neighbor rep.)
TAG_MULTIPLE_BSSID = 71    # Multiple BSSID set
TAG_CHANNEL_SWITCH = 37    # Channel Switch Announcement (CSA)
TAG_EXTENDED_CSA = 60      # Extended Channel Switch Announcement


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


def parse_cap(name, database, verbose, hcxpcapngtool, tshark):
    if tshark:
        parse_handshakes(name, database, verbose)
        parse_WPS(name, database, verbose)
        parse_identities(name, database, verbose)
        parse_MFP(name, database, verbose)
        parse_certificates(name, database, verbose)
        parse_security(name, database, verbose)
        parse_capabilities(name, database, verbose)
        parse_hidden_ssid(name, database, verbose)
        parse_eap_md5(name, database, verbose)
        parse_probe_fingerprint(name, database, verbose)
    if hcxpcapngtool:
        exec_hcxpcapngtool(name, database, verbose)


# Get handshakes from .cap
def _handshake_for_pkt(cursor, verbose, pkt, prev, file):
    '''Process one EAPOL packet for a 4-way-handshake message-2 match.

    `prev` is the (src, dst, key_info) of the previous EAPOL frame. Returns
    (errors, new_prev): a message-2 (key info containing '10a') that follows the
    matching message-1 ('08a') in the opposite direction is a valid pair; any
    other EAPOL-Key frame is remembered as a potential message-1.'''
    if verbose:
        print(pkt.eapol.field_names)
        print(pkt.eapol.type)
    if pkt.eapol.type != '3':  # only EAPOL-Key frames
        return 0, prev
    src = pkt.wlan.ta
    dst = pkt.wlan.da
    flag = pkt.eapol.wlan_rsna_keydes_key_info
    if flag.find('10a') == -1:
        return 0, (src, dst, flag)  # remember as a potential message-1
    prevSrc, prevDst, prevFlag = prev
    if prevFlag.find('08a') != -1 and dst == prevSrc and src == prevDst:
        if verbose:
            print("Valid handshake from client " + prevSrc + " to AP " +
                  prevDst)
        return database_utils.insertHandshake(
            cursor, verbose, dst, src, file), prev
    return 0, prev


def parse_handshakes(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        cap = pyshark.FileCapture(file, display_filter="eapol")
        # cap.set_debug()
        prev = ("", "", "")

        for pkt in cap:
            try:
                delta, prev = _handshake_for_pkt(cursor, verbose, pkt, prev,
                                                 file)
                errors += delta
            except Exception as error:
                errors += 1
                if verbose:
                    print(error)
        database.commit()
        print(".cap Handshake done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_handshakes (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
        print(".cap Handshake done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_handshakes (CAP): ", error)
        print(".cap Handshake done, errors", errors)


# Get MFP data from .cap
def _insert_one_mfp(cursor, verbose, pkt):
    '''Store MFP (PMF) capable/required flags for one management frame, read
    from its RSN Capabilities bitfield. Returns the insert error count (0/1).'''
    if not (pkt['wlan.mgt'].wlan_rsn_capabilities and pkt.wlan.ta):
        return 0
    capabilities = pkt['wlan.mgt'].wlan_rsn_capabilities
    # MFP lives in the RSN Capabilities bitfield:
    #   bit 7 (0x80) = MFP Capable
    #   bit 6 (0x40) = MFP Required
    # Test the bits instead of matching exact values, so APs with other
    # capability bits set are detected too.
    cap_int = int(capabilities, 16)
    mfpc = 'True' if cap_int & 0x80 else 'False'
    mfpr = 'True' if cap_int & 0x40 else 'False'
    if not (mfpc == 'True' or mfpr == 'True'):
        return 0
    if verbose:
        print(f"MFPC: {mfpc}")
        print(f"MFPR: {mfpr}")
    return database_utils.insertMFP(cursor, verbose, pkt.wlan.ta, mfpc, mfpr)


def parse_MFP(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        # cap = pyshark.FileCapture(file,
        # display_filter='wlan.fc.type_subtype == 0x0008')
        # Filter only with mfpr or mfpc enable
        cap = pyshark.FileCapture(file,
                                  display_filter='\
                                  ((wlan.rsn.capabilities.mfpr == 1)||\
                                  (wlan.rsn.capabilities.mfpc == 1))&&\
                                  (wlan.fc.type_subtype == 0x0008)')
        # cap.set_debug()

        for pkt in cap:
            try:
                errors += _insert_one_mfp(cursor, verbose, pkt)
            except Exception as error:
                errors += 1
                if verbose:
                    print(error)
        database.commit()
        print(".cap MFP done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_MFP (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
        print(".cap MFP done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_MFP (CAP): ", error)
        print(".cap MFP done, errors", errors)


# Get handshakes from .cap
def parse_WPS(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name
        cap = pyshark.FileCapture(
            file, display_filter="wps.wifi_protected_setup_state == 0x02 and\
                                  wlan.da == ff:ff:ff:ff:ff:ff")
        # cap.set_debug()

        for pkt in cap:
            # print(dir(pkt['wlan.mgt'].wps_version))
            wmgt = 'wlan.mgt'
            # bssid is the only field a WPS row genuinely needs. Every other
            # field below is an optional WPS attribute that is frequently
            # absent from a given frame, so each is decoded defensively with
            # _safe(): a missing field yields '' instead of inflating the
            # error count (which is why a clean capture used to report dozens
            # of "errors").
            bssid = _safe(lambda: pkt.wlan.sa.upper())

            # tshark exposes the SSID as colon-separated hex; decode it the
            # same way the other .cap parsers do, defaulting to '' on a
            # non-hex / undecodable value instead of raising
            # "Non-hexadecimal digit found".
            wlan_ssid = _safe(lambda: binascii.unhexlify(
                pkt[wmgt].wlan_ssid.replace(':', '')).decode('ascii'))

            # WPS 2.0 advertises itself through the Version2 extension. Read it
            # on its own so a non-hex SSID can no longer suppress the 2.0 flag
            # (the two used to share a try/except, so a bad SSID forced 1.0).
            wps_ext_version2 = _safe(lambda: pkt[wmgt].wps_ext_version2)
            wps_version = '2.0' if '20' in (wps_ext_version2 or '') else '1.0'

            wps_device_name = _safe(lambda: pkt[wmgt].wps_device_name)
            wps_model_name = _safe(lambda: pkt[wmgt].wps_model_name)
            wps_model_number = _safe(lambda: pkt[wmgt].wps_model_number)
            wps_config_methods = _safe(lambda: pkt[wmgt].wps_config_methods)
            wps_config_methods_keypad = _safe(
                lambda: pkt[wmgt].wps_config_methods_keypad)

            if verbose:
                print('==============================')
                print(bssid)
                print(wps_version)
                print(wps_ext_version2)

            errors += database_utils.insertWPS(
                cursor, verbose, database_utils.WPSRow(
                    bssid=bssid, wlan_ssid=wlan_ssid, wps_version=wps_version,
                    wps_device_name=wps_device_name,
                    wps_model_name=wps_model_name,
                    wps_model_number=wps_model_number,
                    wps_config_methods=wps_config_methods,
                    wps_config_methods_keypad=wps_config_methods_keypad))

        database.commit()
        print(".cap WPS done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_WPS (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
        print(".cap WPS done, errors", errors)
    except Exception:
        errors += 1
        print("Critical error in parse_WPS (CAP)")
        print(".cap WPS done, errors", errors)


# Get Identities from MGT login
def _identity_for_pkt(cursor, verbose, pkt, state):
    '''Process one EAP packet, accumulating (dst, src, identity, method) state.

    Returns (errors, new_state). An EAP Identity request/response (type 1)
    refreshes the addresses (and the identity on code 2); any other EAP type is
    a method that gets stored against the most recent identity.'''
    dst, src, identity, method = state
    # EAP Success (code 3) and Failure (code 4) frames carry no Type field and
    # are not identities. Skip them, otherwise the pkt.eap.type access below
    # raises AttributeError and every such frame is miscounted as an error.
    if pkt.eap.code in ('3', '4'):
        return 0, state
    if pkt.eap.type == '1':  # EAP Identity
        dst = pkt.wlan.da
        src = pkt.wlan.sa
        if pkt.eap.code == '2':
            try:
                identity = pkt.eap.identity
            except Exception as error:
                if verbose:
                    print(error)
                return 1, (dst, src, identity, method)
        return 0, (dst, src, identity, method)
    # Look up the authentication method by its EAP type, falling back to a
    # generic label for unknown types.
    method = EAP_METHOD_TYPES.get(
        pkt.eap.type, "OTHER (UNKNOWN EAP METHOD) - ID: " + pkt.eap.type)
    database_utils.insertIdentity(cursor, verbose, dst, src, identity, method)
    return 0, (dst, src, identity, method)


def parse_identities(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        cap = pyshark.FileCapture(file, display_filter="eap")
        # cap.set_debug()

        # The information is: Identity, method, method... ,
        # Identity2, method2, method2...
        state = ("", "", "", "")
        for pkt in cap:
            # print(pkt.eapol.field_names)
            try:
                delta, state = _identity_for_pkt(cursor, verbose, pkt, state)
                errors += delta
            except Exception as e:
                errors += 1
                if verbose:
                    print("ERROR:", e)

        database.commit()
        print(".cap Identity done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_identities (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
        print(".cap Identity done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_identities (CAP): ", error)
        print(".cap Identity done, errors", errors)


def _name_attribute(name, oid):
    '''Return the first value of an X.509 Name attribute (OID) or ""'''
    try:
        attributes = name.get_attributes_for_oid(oid)
        if attributes:
            return attributes[0].value
    except Exception as error:
        # A missing/invalid attribute is expected for many certificates;
        # fall back to an empty string instead of failing the whole parse.
        print("Error in _name_attribute: ", error)
    return ""


def _public_key_algorithm(public_key):
    '''Map a cryptography public key object to a readable algorithm name'''
    class_name = type(public_key).__name__
    if 'RSA' in class_name:
        return 'RSA'
    if 'EllipticCurve' in class_name:
        return 'EC'
    if 'DSA' in class_name:
        return 'DSA'
    if 'Ed25519' in class_name:
        return 'Ed25519'
    if 'Ed448' in class_name:
        return 'Ed448'
    return class_name


def _subject_alt_names(cert):
    '''Return the Subject Alternative Names (DNS, IP, email) as a string'''
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        values = []
        for general_name in ext:
            try:
                values.append(str(general_name.value))
            except Exception:
                values.append(str(general_name))
        return ", ".join(values)
    except Exception:
        return ""


def _key_usage(cert):
    '''Return the Key Usage flags as a comma separated string'''
    try:
        usage = cert.extensions.get_extension_for_oid(
            ExtensionOID.KEY_USAGE).value
        flags = [
            ('digital_signature', 'digitalSignature'),
            ('content_commitment', 'contentCommitment'),
            ('key_encipherment', 'keyEncipherment'),
            ('data_encipherment', 'dataEncipherment'),
            ('key_agreement', 'keyAgreement'),
            ('key_cert_sign', 'keyCertSign'),
            ('crl_sign', 'cRLSign'),
        ]
        result = [label for attr, label in flags
                  if getattr(usage, attr, False)]
        # encipher_only/decipher_only are only valid when key_agreement is set
        # (any unexpected error is handled by the outer except).
        if getattr(usage, 'key_agreement', False):
            if usage.encipher_only:
                result.append('encipherOnly')
            if usage.decipher_only:
                result.append('decipherOnly')
        return ", ".join(result)
    except Exception:
        return ""


def _ext_key_usage(cert):
    '''Return the Extended Key Usage OIDs (e.g. serverAuth, clientAuth)'''
    try:
        eku = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE).value
        # pylint: disable=protected-access
        return ", ".join(getattr(o, '_name', None) or o.dotted_string
                         for o in eku)
    except Exception:
        return ""


def _basic_constraints(cert):
    '''Return (is_ca, path_length) from the Basic Constraints extension'''
    try:
        constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS).value
        is_ca = 'True' if constraints.ca else 'False'
        return is_ca, constraints.path_length
    except Exception:
        return "", None


def _key_identifier(cert, oid, attribute):
    '''Return a hex key identifier (authority or subject) or ""'''
    def _read():
        value = cert.extensions.get_extension_for_oid(oid).value
        identifier = getattr(value, attribute, None)
        return identifier.hex() if identifier else ""
    return _safe(_read)


def _crl_urls(cert):
    '''Return the CRL distribution point URLs as a string'''
    try:
        points = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS).value
        urls = []
        for point in points:
            if point.full_name:
                for general_name in point.full_name:
                    urls.append(str(general_name.value))
        return ", ".join(urls)
    except Exception:
        return ""


def _ocsp_urls(cert):
    '''Return the OCSP responder URLs from Authority Information Access'''
    try:
        descriptions = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
        urls = []
        for description in descriptions:
            if description.access_method == AuthorityInformationAccessOID.OCSP:
                urls.append(str(description.access_location.value))
        return ", ".join(urls)
    except Exception:
        return ""


def _safe(func, default=""):
    '''Call func() and return its value, or `default` on any error. Keeps the
    per-field certificate extraction terse and resilient to malformed certs.'''
    try:
        return func()
    except Exception:
        return default


def _cert_datetime(cert, attr):
    '''Return the not_valid_before/after datetime, preferring the timezone
    aware *_utc accessors added in cryptography 42.0.'''
    return getattr(cert, attr + '_utc', None) or getattr(cert, attr)


def _public_key_details(cert):
    '''Return (algorithm, size, curve, exponent) describing the public key.'''
    public_key = cert.public_key()
    algorithm = _public_key_algorithm(public_key)
    size = _safe(lambda: public_key.key_size, 0)
    curve = ""
    exponent = ""
    if algorithm == 'EC':
        curve = _safe(lambda: public_key.curve.name)
    elif algorithm == 'RSA':
        exponent = _safe(lambda: str(public_key.public_numbers().e))
    return algorithm, size, curve, exponent


def _cert_names(cert):
    '''Subject/issuer CN/O/OU attributes for a certificate.'''
    return {
        'subject_cn': _name_attribute(cert.subject, NameOID.COMMON_NAME),
        'subject_o': _name_attribute(cert.subject, NameOID.ORGANIZATION_NAME),
        'subject_ou': _name_attribute(
            cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        'issuer_cn': _name_attribute(cert.issuer, NameOID.COMMON_NAME),
        'issuer_o': _name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME),
        'issuer_ou': _name_attribute(
            cert.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
    }


def _extract_cert_fields(der, cert_index):
    '''Parse a DER encoded X.509 certificate and return all its fields
    as a dict ready to be inserted in the Certificate table.'''
    cert = x509.load_der_x509_certificate(der)

    not_before_dt = _safe(lambda: _cert_datetime(cert, 'not_valid_before'),
                          None)
    not_after_dt = _safe(lambda: _cert_datetime(cert, 'not_valid_after'), None)

    def _fmt(value):
        return value.strftime("%Y-%m-%d %H:%M:%S") if value else ""

    algorithm, size, curve, exponent = _safe(
        lambda: _public_key_details(cert), ("", 0, "", ""))
    is_ca, path_length = _basic_constraints(cert)

    # cryptography exposes the readable OID name only via the internal
    # `_name` attribute; SHA1 is used solely as the standard cert thumbprint.
    # pylint: disable=protected-access
    return {
        'cert_index': cert_index,
        'version': _safe(lambda: cert.version.name),
        'serial_number': _safe(lambda: format(cert.serial_number, 'x')),
        'signature_algorithm': _safe(
            lambda: cert.signature_algorithm_oid._name),
        'issuer': _safe(lambda: cert.issuer.rfc4514_string()),
        'subject': _safe(lambda: cert.subject.rfc4514_string()),
        'not_before': _fmt(not_before_dt),
        'not_after': _fmt(not_after_dt),
        **_cert_names(cert),
        'public_key_algorithm': algorithm,
        'public_key_size': size,
        'public_key_curve': curve,
        'public_key_exponent': exponent,
        'subject_alt_names': _subject_alt_names(cert),
        'key_usage': _key_usage(cert),
        'ext_key_usage': _ext_key_usage(cert),
        'is_ca': is_ca,
        'path_length': path_length,
        'self_signed': _safe(
            lambda: 'True' if cert.subject == cert.issuer else 'False'),
        'authority_key_id': _key_identifier(
            cert, ExtensionOID.AUTHORITY_KEY_IDENTIFIER, 'key_identifier'),
        'subject_key_id': _key_identifier(
            cert, ExtensionOID.SUBJECT_KEY_IDENTIFIER, 'digest'),
        'crl_urls': _crl_urls(cert),
        'ocsp_urls': _ocsp_urls(cert),
        'validity_days': _safe(
            lambda: (not_after_dt - not_before_dt).days, None),
        'sha1_fingerprint': _safe(
            lambda: cert.fingerprint(hashes.SHA1()).hex()),  # nosec B303
        'sha256_fingerprint': cert.fingerprint(hashes.SHA256()).hex(),
    }


def _cert_attribution(columns):
    '''Resolve (cert_field, bssid, mac, cert_type) for one tshark line.

    Uses the EAP direction to know whose certificate this is: the authenticator
    (AP) sends EAP-Request packets (code 1) carrying the server certificate,
    while the supplicant sends EAP-Response packets (code 2) carrying the client
    certificate. Either way the BSSID stored is the AP and the MAC the client.'''
    cert_field = columns[0]
    src = columns[1] if len(columns) > 1 else ""
    dst = columns[2] if len(columns) > 2 else ""
    eap_code = columns[3] if len(columns) > 3 else ""
    if eap_code == '2':  # EAP-Response: certificate sent by the client
        return cert_field, dst, src, 'Client'
    if eap_code == '1':  # EAP-Request: certificate sent by the AP/server
        return cert_field, src, dst, 'AP'
    return cert_field, src, dst, 'Unknown'


def _insert_one_cert(cursor, verbose, file, addr, cert_hex, cert_index):
    '''Parse and store a single hex-encoded certificate. Returns errors (0/1).

    `addr` is the (bssid, mac, cert_type) tuple from `_cert_attribution`.'''
    bssid, mac, cert_type = addr
    try:
        der = binascii.unhexlify(cert_hex.replace(':', ''))
        cert = _extract_cert_fields(der, cert_index)
        if verbose:
            print("Certificate (" + cert_type + ") for AP " +
                  str(bssid) + ": " + str(cert.get('subject')))
        return database_utils.insertCertificate(
            cursor, verbose, bssid, mac, cert_type, file, cert)
    except Exception as error:
        if verbose:
            print("parse_certificates cert error: " + str(error))
        return 1


def _insert_cert_line(cursor, verbose, file, columns):
    '''Insert every certificate found on one `tshark -T fields` output line.

    `columns` is the tab-split line: the certificate column (a chain is joined
    with commas by tshark), wlan.sa, wlan.da and eap.code. Returns the number
    of errors hit while parsing/inserting.'''
    cert_field, bssid, mac, cert_type = _cert_attribution(columns)

    # Without an AP address there is nothing to key the certificate on; skip
    # it rather than create a phantom empty-BSSID AP row.
    if not bssid:
        if verbose:
            print("Certificate without wlan addresses, skip")
        return 0

    errors = 0
    addr = (bssid, mac, cert_type)
    # A single Certificate message can carry a full chain (server, CA, ...);
    # tshark joins those certificates with a comma.
    for cert_index, cert_hex in enumerate(cert_field.split(',')):
        cert_hex = cert_hex.strip()
        if cert_hex:
            errors += _insert_one_cert(cursor, verbose, file, addr,
                                       cert_hex, cert_index)
    return errors


# Get X.509 certificates from EAP-TLS/PEAP/TTLS in .cap
def parse_certificates(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name

        # EAP-TLS certificates are reassembled by tshark across several EAPOL
        # fragments. pyshark's per-packet display-filter iteration does not
        # surface that reassembled `tls.handshake.certificate` field, so it
        # never finds anything. Extract it straight from tshark in `-T fields`
        # mode instead (the approach of the standalone reference tool), pulling
        # the certificate together with the wlan addresses and EAP code needed
        # to attribute it. Fixed absolute-path binary, no shell; the file name
        # is a separate argv element, so it cannot be used for injection.
        completed = subprocess.run(  # nosec B603
            ["/usr/bin/tshark", "-r", file,
             "-Y", "tls.handshake.certificate and eapol",
             "-T", "fields",
             "-e", "tls.handshake.certificate",
             "-e", "wlan.sa", "-e", "wlan.da", "-e", "eap.code"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)

        output = completed.stdout.decode('utf-8', 'replace')
        for raw_line in output.splitlines():
            columns = raw_line.split('\t')
            if not columns[0]:  # no certificate on this line
                continue
            errors += _insert_cert_line(cursor, verbose, file, columns)

        database.commit()
        print(".cap Certificate done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_certificates (CAP): ", error)
        print(".cap Certificate done, errors", errors)


def _all_field_values(layer, field_name):
    '''Return every value of a (possibly repeated) pyshark layer field'''
    values = []
    try:
        field = layer.get_field(field_name)
    except Exception:
        field = None
    if field is None:
        return values
    try:
        for sub_field in field.all_fields:
            value = sub_field.get_default_value()
            if value not in (None, ''):
                values.append(value)
    except Exception:
        with contextlib.suppress(Exception):
            values.append(str(field))
    return values


def _suite_name(value, mapping):
    '''Map an RSN suite selector number to its readable name'''
    try:
        key = str(int(value))
    except Exception:
        key = str(value)
    return mapping.get(key, key)


def _dedupe(values):
    '''Deduplicate a list while preserving order'''
    return list(dict.fromkeys(values))


def _to_int(value, base=10):
    '''Parse an int, returning None instead of raising.'''
    try:
        return int(value, base) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


def _pkt_bssid_mgt(pkt):
    '''Return (bssid, wlan.mgt layer) for a packet, or (None, None).'''
    try:
        return pkt.wlan.sa, pkt['wlan.mgt']
    except Exception:
        return None, None


def _classify_wpa(akm_ints):
    '''Map the numeric AKM set to a WPA version label.'''
    if akm_ints & {8, 9}:  # SAE / FT-SAE -> WPA3
        return "WPA2/WPA3" if akm_ints & {2, 4} else "WPA3"
    if 18 in akm_ints:  # OWE
        return "OWE"
    return "WPA2"


def _rsn_pmf(mgt):
    '''Return (pmf, rsn_capabilities, mfpc, mfpr) from the RSN capabilities
    bitfield: bit 7 (0x80) = MFP Capable, bit 6 (0x40) = MFP Required.'''
    mfpc = 'False'
    mfpr = 'False'
    field = mgt.get_field('wlan_rsn_capabilities')
    rsn_capabilities = (field.get_default_value()
                        if field is not None else "") or ""
    cap_int = _to_int(rsn_capabilities, 16)
    if cap_int is not None:
        mfpc = 'True' if cap_int & 0x80 else 'False'
        mfpr = 'True' if cap_int & 0x40 else 'False'
    if mfpr == 'True':
        pmf = "Required"
    elif mfpc == 'True':
        pmf = "Capable"
    else:
        pmf = "Disabled"
    return pmf, rsn_capabilities, mfpc, mfpr


def _field_value(layer, field_name):
    '''Return a single field's value (or '') from a pyshark layer, never
    raising.'''
    try:
        field = layer.get_field(field_name)
    except Exception:
        return ''
    if field is None:
        return ''
    try:
        return field.get_default_value() or ''
    except Exception:
        return ''


def _first_field_value(layer, field_names):
    '''Return the first non-empty value among several candidate field names
    (dissector field names vary between tshark versions).'''
    for name in field_names:
        value = _field_value(layer, name)
        if value not in (None, ''):
            return value
    return ''


def _field_is_set(value):
    '''True when a tshark boolean/bit field reads as set.'''
    return str(value).strip().lower() in ('1', 'true', 'yes')


def _mgt_tag_numbers(mgt):
    '''Return the set of 802.11 element (tag) numbers present in a management
    frame, as ints.'''
    values = _all_field_values(mgt, 'wlan_tag_number')
    return {i for i in (_to_int(v) for v in values) if i is not None}


def _ssid_from_mgt(mgt):
    '''Decode the SSID element of a management frame, returning '' for a
    hidden/wildcard SSID (empty or NUL padding). tshark may expose wlan.ssid
    either already decoded or as colon-separated hex bytes.'''
    raw = _field_value(mgt, 'wlan_ssid')
    if not raw:
        return ''
    candidate = raw
    if ':' in raw:
        try:
            candidate = binascii.unhexlify(
                raw.replace(':', '')).decode('utf-8', 'replace')
        except Exception:
            candidate = raw
    return candidate.replace('\x00', '').strip()


# Detect 802.11r/k/v fast-roaming, Multiple BSSID and Channel Switch
# Announcement advertisements from beacons and probe responses, storing the
# flags on the AP row.
def _seen_or_invalid(bssid, mgt, seen):
    '''True when a packet lacks a usable BSSID/mgt or its AP is already seen
    (one row per BSSID is enough; the config is stable per AP).'''
    return bssid is None or mgt is None or bssid.upper() in seen


def _capability_flags(mgt):
    '''Return the 802.11r/k/v + MBSSID/CSA capability flags for one mgt frame.'''
    tags = _mgt_tag_numbers(mgt)
    return {
        'ft': 'True' if TAG_MOBILITY_DOMAIN in tags else 'False',
        'rrm': 'True' if TAG_RM_ENABLED_CAP in tags else 'False',
        'mbssid': 'True' if TAG_MULTIPLE_BSSID in tags else 'False',
        'csa': ('True' if (TAG_CHANNEL_SWITCH in tags
                           or TAG_EXTENDED_CSA in tags) else 'False'),
        # 802.11v BSS Transition Management is a bit (b19) of the Extended
        # Capabilities element, not an element of its own.
        'bss_trans': ('True' if _field_is_set(
            _field_value(mgt, 'wlan_extcap_b19')) else 'False'),
        'mdid': _first_field_value(
            mgt, ['wlan_mobility_domain_mdid', 'wlan_ft_mdid']),
        'max_bssid_indicator': _to_int(_first_field_value(
            mgt, ['wlan_mbssid_max_bssid_indicator', 'wlan_mbssid_index'])),
        'csa_new_channel': _to_int(_first_field_value(
            mgt, ['wlan_csa_new_channel_number',
                  'wlan_ext_chansw_announce_new_chan'])),
    }


def _insert_one_capability(cursor, verbose, bssid, mgt):
    '''Store fast-roaming / MBSSID / CSA capabilities for one AP if any are
    advertised. Returns the number of insert errors (0/1).'''
    f = _capability_flags(mgt)
    if not any(f[k] == 'True'
               for k in ('ft', 'rrm', 'bss_trans', 'mbssid', 'csa')):
        return 0
    if verbose:
        print("Capabilities for AP " + str(bssid) + ": 11r=" + f['ft'] +
              " 11k=" + f['rrm'] + " 11v=" + f['bss_trans'] + " MBSSID=" +
              f['mbssid'] + " CSA=" + f['csa'])
    return database_utils.insertCapabilities(
        cursor, verbose, database_utils.CapabilitiesRow(
            bssid=bssid, ft_80211r=f['ft'], mobility_domain_id=f['mdid'],
            rrm_80211k=f['rrm'], bss_transition_80211v=f['bss_trans'],
            mbssid=f['mbssid'], max_bssid_indicator=f['max_bssid_indicator'],
            csa=f['csa'], csa_new_channel=f['csa_new_channel']))


def parse_capabilities(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        # Beacons (0x08) and probe responses (0x05) carry the capability IEs.
        cap = pyshark.FileCapture(
            file, display_filter="wlan.fc.type_subtype == 0x08 || "
            "wlan.fc.type_subtype == 0x05")
        # cap.set_debug()

        seen = set()
        for pkt in cap:
            try:
                bssid, mgt = _pkt_bssid_mgt(pkt)
                if _seen_or_invalid(bssid, mgt, seen):
                    continue
                errors += _insert_one_capability(cursor, verbose, bssid, mgt)
                seen.add(bssid.upper())
            except Exception as error:
                errors += 1
                if verbose:
                    print(error)

        database.commit()
        print(".cap Capabilities done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_capabilities (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
        print(".cap Capabilities done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_capabilities (CAP): ", error)
        print(".cap Capabilities done, errors", errors)


# Recover cloaked (hidden) SSIDs from probe responses and (re)association
# requests, which carry the real SSID even when the beacon hides it.
def _hidden_ssid_for_pkt(cursor, verbose, pkt, seen):
    '''Recover and store one AP's cloaked SSID. Returns insert errors (0/1);
    `seen` tracks the BSSIDs already handled and is mutated in place.'''
    mgt = pkt['wlan.mgt']
    ssid = _ssid_from_mgt(mgt)
    if not ssid:
        return 0
    bssid = pkt.wlan.bssid
    if bssid is None or bssid.upper() in seen:
        return 0
    seen.add(bssid.upper())
    if verbose:
        print("Revealed SSID for AP " + str(bssid) + ": " + ssid)
    return database_utils.insertHiddenSSID(cursor, verbose, bssid, ssid)


def parse_hidden_ssid(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        # Probe responses (0x05) and (re)association requests (0x00 / 0x02)
        # carrying a non-wildcard SSID element. wlan.bssid is the AP in all of
        # them, so no per-subtype address handling is needed.
        cap = pyshark.FileCapture(
            file, display_filter="(wlan.fc.type_subtype == 0x05 || "
            "wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x02) "
            "&& wlan.ssid")
        # cap.set_debug()

        seen = set()
        for pkt in cap:
            try:
                errors += _hidden_ssid_for_pkt(cursor, verbose, pkt, seen)
            except Exception as error:
                errors += 1
                if verbose:
                    print(error)

        database.commit()
        print(".cap Hidden SSID done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_hidden_ssid (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
        print(".cap Hidden SSID done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_hidden_ssid (CAP): ", error)
        print(".cap Hidden SSID done, errors", errors)


# Get RSN/WPA security details (AKM suites and ciphers) from beacons and
# probe responses.
def _akm_ints(akm_values):
    '''Parse AKM suite type strings into the set of their integer values.'''
    return {i for i in (_to_int(v) for v in akm_values) if i is not None}


def _security_row(mgt):
    '''Build the RSN/WPA security row for one mgt frame, or None when the frame
    carries no AKM suite (so the caller can skip it without marking it seen).'''
    akm_values = _all_field_values(mgt, 'wlan_rsn_akms_type')
    if not akm_values:
        return None
    pcs_values = _all_field_values(mgt, 'wlan_rsn_pcs_type')
    gcs_values = _all_field_values(mgt, 'wlan_rsn_gcs_type')
    akm_ints = _akm_ints(akm_values)
    pmf, rsn_capabilities, mfpc, mfpr = _rsn_pmf(mgt)
    return {
        'akm_suites': ", ".join(_dedupe(
            [_suite_name(a, RSN_AKM_SUITES) for a in akm_values])),
        'pairwise_ciphers': ", ".join(_dedupe(
            [_suite_name(p, RSN_CIPHERS) for p in pcs_values])),
        'group_cipher': ", ".join(_dedupe(
            [_suite_name(g, RSN_CIPHERS) for g in gcs_values])),
        'wpa_version': _classify_wpa(akm_ints),
        'enterprise': 'True' if akm_ints & RSN_ENTERPRISE_AKMS else 'False',
        'pmf': pmf,
        'rsn_capabilities': rsn_capabilities,
        'mfpc': mfpc,
        'mfpr': mfpr,
    }


def _insert_one_security(cursor, verbose, file, bssid, mgt):
    '''Store RSN/WPA security (and MFP) for one AP. Returns the insert error
    count, or None when the frame has no AKM suite.'''
    row = _security_row(mgt)
    if row is None:
        return None
    if verbose:
        print("Security for AP " + str(bssid) + ": " + row['wpa_version'] +
              " [" + row['akm_suites'] + "] PMF=" + row['pmf'])
    errors = database_utils.insertSecurity(
        cursor, verbose, database_utils.SecurityRow(
            bssid=bssid, wpa_version=row['wpa_version'],
            akm_suites=row['akm_suites'],
            pairwise_ciphers=row['pairwise_ciphers'],
            group_cipher=row['group_cipher'], enterprise=row['enterprise'],
            pmf=row['pmf'], rsn_capabilities=row['rsn_capabilities'],
            file=file))
    # Beacons are far more common than the association frames parsed by
    # parse_MFP, so also update the AP mfpc/mfpr from here.
    if row['mfpc'] == 'True' or row['mfpr'] == 'True':
        errors += database_utils.insertMFP(
            cursor, verbose, bssid, row['mfpc'], row['mfpr'])
    return errors


def parse_security(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        # Beacons (0x08) and probe responses (0x05) that carry an RSN IE.
        cap = pyshark.FileCapture(
            file, display_filter="(wlan.fc.type_subtype == 0x08 || "
            "wlan.fc.type_subtype == 0x05) && wlan.rsn.akms.type")
        # cap.set_debug()

        seen = set()
        for pkt in cap:
            bssid, mgt = _pkt_bssid_mgt(pkt)
            if _seen_or_invalid(bssid, mgt, seen):
                continue
            result = _insert_one_security(cursor, verbose, file, bssid, mgt)
            if result is None:  # no AKM suite on this frame; try later ones
                continue
            errors += result
            seen.add(bssid.upper())

        database.commit()
        print(".cap Security done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_security (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
        print(".cap Security done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_security (CAP): ", error)
        print(".cap Security done, errors", errors)


def _eap_md5_packet(pkt):
    '''Return (code, eap_id, src, dst, md5_value) for an EAP-MD5 packet, or
    None when a required field is missing.'''
    try:
        md5_value = pkt.eap.md5_value.replace(':', '')
        if not md5_value:
            return None
        return pkt.eap.code, pkt.eap.id, pkt.wlan.sa, pkt.wlan.da, md5_value
    except Exception:
        return None


def _eap_md5_hashcat(eap_id, challenge, response):
    '''Build the hashcat -m 4800 line response:challenge:id; the EAP id is
    hex-encoded (pyshark exposes eap.id as decimal).'''
    value = _to_int(eap_id)
    eap_id_hex = format(value, '02x') if value is not None else eap_id
    return response + ":" + challenge + ":" + eap_id_hex


def _eap_md5_for_pkt(cursor, verbose, pkt, challenges, file):
    '''Correlate one EAP-MD5 packet against pending challenges. Returns the
    insert error count (0/1). `challenges` maps (ap, client, eap_id) -> challenge
    hex and is updated in place with each Request seen.'''
    parsed = _eap_md5_packet(pkt)
    if parsed is None:
        return 0
    code, eap_id, src, dst, md5_value = parsed
    if code == '1':  # EAP-Request/MD5-Challenge sent by the AP
        challenges[(src, dst, eap_id)] = md5_value
        return 0
    if code != '2':  # only Responses produce a crackable pair
        return 0
    challenge = challenges.get((dst, src, eap_id))
    if not challenge:
        return 0
    hashcat = _eap_md5_hashcat(eap_id, challenge, md5_value)
    if verbose:
        print("EAP-MD5 " + str(src) + " -> " + str(dst) + ": " + hashcat)
    return database_utils.insertEAPMD5(
        cursor, verbose, database_utils.EAPMD5Row(
            bssid=dst, mac=src, identity="", eap_id=eap_id, challenge=challenge,
            response=md5_value, hashcat=hashcat, file=file))


# Get EAP-MD5 challenge/response pairs (crackable with hashcat -m 4800)
def parse_eap_md5(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        cap = pyshark.FileCapture(file, display_filter="eap.type == 4")
        # cap.set_debug()

        # Correlate the Request (challenge, from the AP) with the Response
        # (response, from the client) sharing the same EAP id.
        challenges = {}  # (ap, client, eap_id) -> challenge hex
        for pkt in cap:
            errors += _eap_md5_for_pkt(cursor, verbose, pkt, challenges, file)

        database.commit()
        print(".cap EAP-MD5 done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_eap_md5 (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
        print(".cap EAP-MD5 done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_eap_md5 (CAP): ", error)
        print(".cap EAP-MD5 done, errors", errors)


def _probe_fingerprint_for_pkt(cursor, verbose, pkt, seen, file):
    '''Fingerprint one probe-request frame by its ordered IE tag list. Returns
    insert errors (0/1); `seen` de-duplicates (mac, ssid, fingerprint) keys and
    is mutated in place.'''
    mac = _safe(lambda: pkt.wlan.sa, None)
    if mac is None:
        return 0
    mgt = _safe(lambda: pkt['wlan.mgt'], None)
    if mgt is None:
        return 0
    tags = _all_field_values(mgt, 'wlan_tag_number')
    if not tags:
        return 0
    ie_order = ",".join(str(tag) for tag in tags)
    fingerprint = database_utils.getHash(ie_order.encode())[:32]
    # The probed SSID ('' for broadcast probe requests). The merged Probe row is
    # keyed by (mac, ssid), so the fingerprint attaches to the SSID seen in this
    # frame. Decoded defensively (hex like the other .cap parsers), defaulting
    # to '' on any failure.
    ssid = _safe(lambda: binascii.unhexlify(
        mgt.wlan_ssid.replace(':', '')).decode('ascii'))
    key = (mac.upper(), ssid, fingerprint)
    if key in seen:
        return 0
    seen.add(key)
    if verbose:
        print("Probe fingerprint " + str(mac) + ": " + ie_order)
    return database_utils.insertProbeFingerprint(
        cursor, verbose, mac, ssid, fingerprint, ie_order, file)


# Fingerprint clients by the ordered set of information elements (tags) they
# include in their probe requests; useful to identify device model/OS.
def parse_probe_fingerprint(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        cap = pyshark.FileCapture(
            file, display_filter="wlan.fc.type_subtype == 0x04")
        # cap.set_debug()

        seen = set()
        for pkt in cap:
            errors += _probe_fingerprint_for_pkt(cursor, verbose, pkt, seen,
                                                 file)

        database.commit()
        print(".cap ProbeFingerprint done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_probe_fingerprint (CAP), probably PCAP cut in "
              "the middle of a packet: ", error)
        print(".cap ProbeFingerprint done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_probe_fingerprint (CAP): ", error)
        print(".cap ProbeFingerprint done, errors", errors)


# Use hcxpcapngtool to get the 22000 hash to hashcat
def exec_hcxpcapngtool(name, database, verbose):
    try:
        # cmd = "where" if platform.system() == "Windows" else "which"
        # subprocess.call([cmd, "hcxpcapngtool"])
        cursor = database.cursor()
        errors = 0
        fileName = name
        # exec_hcxpcapngtool. Fixed absolute-path binary, no shell; the input
        # file name is passed as a separate argv element (not interpolated),
        # so it cannot be used for command injection.
        execute_process = subprocess.Popen(  # nosec B603
            ["/usr/bin/hcxpcapngtool", "--all", fileName, "-o", "test.22000"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        execute_process.wait()  # Wait for the installation process to complete
        # Read output (fileName) each line
        file_exists = os.path.exists('test.22000')
        if not file_exists:
            return
        with open('test.22000', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines:
                # update in database aka insert_hash
                split = line.split('*')
                ap_lower = split[3].upper()
                client_lower = split[4].upper()
                # : format
                ap = (':'.join(ap_lower[i:i + 2] for i in range(0, 12, 2)))
                client = (':'.join(client_lower[i:i + 2] for i in
                          range(0, 12, 2)))
                if verbose:
                    print(ap)
                    print(client)
                    print(line)
                # Update handshake

                errors += database_utils.setHashcat(cursor, verbose,
                                                    ap, client, fileName,
                                                    line)
        database.commit()
        os.remove("test.22000")
        print(".cap hcxpcapngtool done, errors", errors)

    except Exception as error:
        errors += 1
        print("Error in exec_hcxpcapngtool (CAP): ", error)
        print(".cap hcxpcapngtool done, errors", errors)
