#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB '''
# -*- coding: utf-8 -*-
import csv
import os
import re
# import platform
import binascii
import datetime
import subprocess  # nosec B404 - only used with a fixed, absolute-path command
# import xml.etree.ElementTree as ET # vuln!
import defusedxml.ElementTree as ET
import ftfy
import pyshark
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


def parse_netxml(ouiMap, name, database, verbose):
    '''Function to parse the .kismet.netxml files'''

    filename = name
    exists = os.path.isfile(filename)
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
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

            raiz = ET.fromstring(filedata)
            for wireless in raiz:
                if wireless.get("type") == "probe":
                    bssid = wireless.find("BSSID").text
                    manuf = oui.get_vendor(ouiMap, bssid, verbose)
                    packets_total = wireless.find("packets").find("total").text
                    if verbose:
                        print(bssid, manuf, "W", packets_total)

                    errors += database_utils.insertClients(
                        cursor, verbose, bssid, '',
                        manuf, 'W', packets_total, 'Misc', 0)

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

                    mfpc = 'False'
                    mfpr = 'False'
                    errors += database_utils.insertAP(
                        cursor, verbose, bssid, essid, manuf, channel,
                        freqmhz, carrier, encryption, packets_total, lat, lon,
                        cloaked, mfpc, mfpr, firstTimeSeen)

                    # client
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
                            cursor, verbose, client_mac, '', manuf,
                            'W', packets_total, 'Misc', firstTimeSeen)

                        # connected
                        # print (bssid, client_mac)
                        errors += database_utils.insertConnected(
                            cursor, verbose, bssid, client_mac)
            database.commit()
            print(".kismet.netxml OK, errors", errors)
        else:
            print(".kismet.netxml missing")
    except Exception as error:
        errors += 1
        print("parse_netxml " + str(error))
        print("Error in kismet.netxml")
        print(".kismet.netxml OK, errors", errors)


def parse_kismet_csv(ouiMap, name, database, verbose):
    '''Function to parse the .kismet.csv files'''
    exists = os.path.isfile(name)
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            with open(name, encoding='utf-8') as csv_file:
                csv_reader = csv.reader((x.replace('\0', '')
                                         for x in csv_file), delimiter=';')
                for row in csv_reader:
                    if len(row) > 35 and row[0] != "Network":
                        try:
                            bssid = row[3]
                            essid = row[2]
                            essid = essid.replace("'", "''")

                            # firstTimeSeen
                            firstTimeSeen_string = row[19]

                            date_object = datetime.datetime.strptime(
                                firstTimeSeen_string, "%a %b %d %H:%M:%S %Y"
                            )
                            firstTimeSeen = date_object.strftime(
                                "%Y-%m-%d %H:%M:%S"
                            )

                            manuf = oui.get_vendor(ouiMap, bssid, verbose)

                            channel = row[5]
                            freqmhz = 0
                            carrier = ""
                            encryption = row[7]
                            packets_total = row[16]
                            lat = row[32]
                            lon = row[33]
                            cloaked = 'False'
                            mfpc = 'False'
                            mfpr = 'False'
                            errors += database_utils.insertAP(
                                cursor, verbose, bssid, essid, manuf, channel,
                                freqmhz, carrier, encryption, packets_total,
                                lat, lon, cloaked, mfpc, mfpr, firstTimeSeen)

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
        errors += 1
        print("parse_kismet_csv " + str(error))
        print("Error in kismet.csv")
        print(".kismet.csv OK, errors", errors)


def parse_csv(ouiMap, name, database, verbose):
    '''Function to parse the .csv files'''
    exists = os.path.isfile(name)
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            with open(name, encoding='utf-8') as csv_file:
                csv_reader = csv.reader((x.replace('\0', '')
                                         for x in csv_file), delimiter=',')
                client = False
                for row in csv_reader:
                    if row:
                        if client is False and len(row) > 13 \
                           and row[0] != "BSSID":
                            # insert AP de aqui tambien
                            bssid = row[0]
                            firstTimeSeen = row[1]
                            essid = row[13]
                            essid = essid.replace("'", "''")
                            manuf = oui.get_vendor(ouiMap, bssid, verbose)
                            channel = row[3]
                            freq = ""
                            carrier = ""
                            encrypt = row[5] + row[6] + row[7]
                            packets_total = row[10]
                            cloaked = 'False'

                            mfpc = 'False'
                            mfpr = 'False'

                            errors += database_utils.insertAP(
                                cursor, verbose, bssid, essid[1:], manuf,
                                channel, freq, carrier, encrypt,
                                packets_total, 0, 0, cloaked, mfpc, mfpr,
                                firstTimeSeen)

                        if row and row[0] == "Station MAC":
                            client = True
                        elif row and client and len(row) > 5:
                            # print(row[0])
                            mac = row[0]
                            firstTimeSeen = row[1]
                            manuf = oui.get_vendor(ouiMap, mac, verbose)
                            packets = row[4]
                            # print(mac, manuf)

                            errors += database_utils.insertClients(
                                cursor, verbose, mac, '', manuf, 'W',
                                packets, 'Misc', firstTimeSeen)

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
        errors += 1
        print("parse_csv " + str(error))
        print("Error in .csv")
        print(".csv OK, errors", errors)


def parse_log_csv(ouiMap, name, database, verbose, fake_lat, fake_lon):
    ''' Parse .log.csv file from Aircrack-ng to the database '''
    exists = os.path.isfile(name)
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            with open(name, encoding='utf-8') as csv_file:
                csv_reader = csv.reader(csv_file, delimiter=',')
                for row in csv_reader:
                    time = row[0]
                    if time != "LocalTime":
                        if len(row) > 10 and row[10] == "Client":
                            mac = row[3]
                            manuf = oui.get_vendor(ouiMap, mac, verbose)
                            signal_rssi = row[4]
                            lat = row[6]
                            lon = row[7]
                            if fake_lat != "":  # just write file in db
                                lat = fake_lat
                            if fake_lon != "":
                                lon = fake_lon
                            ssid = ""
                            typeAux = ""
                            packets_total = ""
                            device = ""
                            errors += database_utils.insertClients(
                                cursor, verbose, mac, ssid, manuf,
                                typeAux, packets_total, device, time)

                            errors += database_utils.insertSeenClient(
                                cursor, verbose, mac, time,
                                'aircrack-ng', signal_rssi, lat, lon,
                                '0.0')

                        if len(row) > 10 and row[10] == "AP":
                            lat = row[6]
                            lon = row[7]
                            if fake_lat != "":
                                lat = fake_lat
                            if fake_lon != "":
                                lon = fake_lon
                            manuf = oui.get_vendor(ouiMap, row[3], verbose)
                            cloaked = 'False'
                            mfpc = 'False'
                            mfpr = 'False'
                            errors += database_utils.insertAP(
                                cursor, verbose, row[3], row[2],
                                manuf, 0, 0, '', '', 0, lat, lon,
                                cloaked, mfpc, mfpr, time)

                            # if row[6] != "0.000000":
                            errors += database_utils.insertSeenAP(
                                cursor, verbose, row[3], time,
                                'aircrack-ng', row[4], lat, lon,
                                '0.0', 0)

            database.commit()
            print(".log.csv done, errors", errors)
        else:
            print(".log.csv missing")
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
        parse_eap_md5(name, database, verbose)
        parse_probe_fingerprint(name, database, verbose)
    if hcxpcapngtool:
        exec_hcxpcapngtool(name, database, verbose)


# Get handshakes from .cap
def parse_handshakes(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name
        cap = pyshark.FileCapture(file, display_filter="eapol")
        # cap.set_debug()
        prevSrc = ""
        prevDst = ""
        prevFlag = ""

        for pkt in cap:
            try:
                if verbose:
                    print(pkt.eapol.field_names)
                    print(pkt.eapol.type)
                if pkt.eapol.type == '3':  # EAPOL = 3
                    src = pkt.wlan.ta
                    dst = pkt.wlan.da
                    flag = pkt.eapol.wlan_rsna_keydes_key_info
                    # print(flag)
                    # IF is the second and the prev is the first one
                    # add handshake
                    if flag.find('10a') != -1:
                        # print('handhsake 2 of 4')
                        if (prevFlag.find('08a') != -1
                                and dst == prevSrc and src == prevDst):
                            # first
                            if verbose:
                                print("Valid handshake from client " +
                                      prevSrc + " to AP " + prevDst)
                            errors += database_utils.insertHandshake(cursor,
                                                                     verbose,
                                                                     dst,
                                                                     src, file)
                    else:
                        prevSrc = src
                        prevDst = dst
                        prevFlag = flag
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
def parse_MFP(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
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
                mfpc = 'False'
                mfpr = 'False'
                if pkt['wlan.mgt'].wlan_rsn_capabilities and pkt.wlan.ta:
                    capabilities = pkt['wlan.mgt'].wlan_rsn_capabilities
                    # MFP lives in the RSN Capabilities bitfield:
                    #   bit 7 (0x80) = MFP Capable
                    #   bit 6 (0x40) = MFP Required
                    # Test the bits instead of matching exact values, so APs
                    # with other capability bits set are detected too.
                    cap_int = int(capabilities, 16)
                    if cap_int & 0x80:
                        mfpc = 'True'
                    if cap_int & 0x40:
                        mfpr = 'True'
                    src = pkt.wlan.ta
                    # if mfpc is 1 insert in DB
                    if mfpc == 'True' or mfpr == 'True':
                        if verbose:
                            print(f"MFPC: {mfpc}")
                            print(f"MFPR: {mfpr}")
                        errors += database_utils.insertMFP(cursor,
                                                           verbose,
                                                           src, mfpc,
                                                           mfpr)
                # wlan_options = pkt['wlan.mgt'].field_names
                # print(wlan_options)
                # print(pkt['wlan.mgt'])
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
            bssid = ''
            wlan_ssid = ''
            wps_device_name = ''
            wps_model_name = ''
            wps_model_number = ''
            wps_config_methods = ''
            wps_config_methods_keypad = ''
            wps_version = '1.0'  # Default 1.0
            wmgt = 'wlan.mgt'
            try:
                wlan_ssid = pkt['wlan.mgt'].wlan_ssid
                bssid = pkt.wlan.sa
                bssid = bssid.upper()
            except Exception:
                errors += 1
            try:
                w_s_hex = pkt[wmgt].wlan_ssid
                wlan_ssid_bytes = binascii.unhexlify(w_s_hex.replace(':', ''))
                wlan_ssid_decode = wlan_ssid_bytes.decode('ascii')
                if wlan_ssid_decode != "":
                    wlan_ssid = wlan_ssid_decode
                if ('20' in pkt[wmgt].wps_ext_version2):
                    wps_version = '2.0'
            except Exception as e:
                if verbose:
                    print(e)
                errors += 1
            try:
                wps_device_name = pkt[wmgt].wps_device_name
            except Exception:
                errors += 1
            try:
                wps_model_name = pkt[wmgt].wps_model_name
            except Exception:
                errors += 1
            try:
                wps_model_number = pkt[wmgt].wps_model_number
            except Exception:
                errors += 1
            try:
                wps_config_methods = pkt[wmgt].wps_config_methods
            except Exception:
                errors += 1
            try:
                wps_config_methods_keypad = pkt[wmgt].wps_config_methods_keypad
            except Exception:
                errors += 1

            try:
                if verbose:
                    print('==============================')
                    print(bssid)
                    print(wps_version)
                    print(pkt[wmgt].wps_ext_version2)
            except Exception:
                errors += 1

            errors += database_utils.insertWPS(cursor, verbose, bssid,
                                               wlan_ssid, wps_version,
                                               wps_device_name, wps_model_name,
                                               wps_model_number,
                                               wps_config_methods,
                                               wps_config_methods_keypad)

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
def parse_identities(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name
        cap = pyshark.FileCapture(file, display_filter="eap")
        # cap.set_debug()

        dst = ""
        src = ""
        identity = ""
        method = ""

        # The information is: Identity, method, method... ,
        # Identity2, method2, method2...
        for pkt in cap:
            # print(pkt.eapol.field_names)
            try:
                if pkt.eap.type == '1':  # EAP Identity
                    dst = pkt.wlan.da
                    src = pkt.wlan.sa
                    if pkt.eap.code == '2':
                        try:
                            identity = pkt.eap.identity
                        except Exception as error:
                            errors += 1
                            if verbose:
                                print(error)
                else:
                    # Look up the authentication method by its EAP type,
                    # falling back to a generic label for unknown types.
                    method = EAP_METHOD_TYPES.get(
                        pkt.eap.type,
                        "OTHER (UNKNOWN EAP METHOD) - ID: " + pkt.eap.type)
                    # Insert, if its already error and continue
                    database_utils.insertIdentity(cursor, verbose,
                                                  dst, src, identity, method)
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
    try:
        value = cert.extensions.get_extension_for_oid(oid).value
        identifier = getattr(value, attribute, None)
        if identifier:
            return identifier.hex()
    except Exception:
        pass
    return ""


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
        'subject_cn': _name_attribute(cert.subject, NameOID.COMMON_NAME),
        'subject_o': _name_attribute(
            cert.subject, NameOID.ORGANIZATION_NAME),
        'subject_ou': _name_attribute(
            cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
        'issuer_cn': _name_attribute(cert.issuer, NameOID.COMMON_NAME),
        'issuer_o': _name_attribute(cert.issuer, NameOID.ORGANIZATION_NAME),
        'issuer_ou': _name_attribute(
            cert.issuer, NameOID.ORGANIZATIONAL_UNIT_NAME),
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


def _get_cert_hexes(pkt, verbose):
    '''Return the list of colon separated hex strings of every X.509
    certificate present in a TLS Certificate handshake packet.'''
    field = _safe(lambda: pkt.tls.get_field('handshake_certificate'), None)
    if field is None:
        field = _safe(lambda: pkt.tls.handshake_certificate, None)
    if field is None:
        return []

    # A single Certificate message can carry a full chain (server, CA, ...),
    # so collect every value of the field.
    values = _safe(
        lambda: [f.get_default_value() for f in field.all_fields], None)
    if values is None:
        values = _safe(lambda: [str(field)], [])
        if not values and verbose:
            print("Could not read certificate field")
    return [value for value in values if value]


# Get X.509 certificates from EAP-TLS/PEAP/TTLS in .cap
def parse_certificates(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name
        cap = pyshark.FileCapture(
            file, display_filter="tls.handshake.certificate")
        # cap.set_debug()

        for pkt in cap:
            try:
                src = pkt.wlan.sa
                dst = pkt.wlan.da
            except Exception:
                if verbose:
                    print("Certificate packet without wlan addresses, skip")
                continue

            # Use the EAP direction to know whose certificate this is. The
            # authenticator (AP) sends EAP-Request packets (code 1) carrying
            # the server certificate, while the supplicant sends EAP-Response
            # packets (code 2) carrying the client certificate. Either way the
            # BSSID stored is the AP and the MAC is the client.
            try:
                eap_code = pkt.eap.code
            except Exception:
                eap_code = None

            if eap_code == '2':  # EAP-Response: certificate sent by the client
                bssid = dst
                mac = src
                cert_type = 'Client'
            elif eap_code == '1':  # EAP-Request: cert sent by the AP/server
                bssid = src
                mac = dst
                cert_type = 'AP'
            else:
                # Direction unknown, assume the AP relays it (server cert)
                bssid = src
                mac = dst
                cert_type = 'Unknown'

            for cert_index, cert_hex in enumerate(_get_cert_hexes(pkt,
                                                                  verbose)):
                try:
                    der = binascii.unhexlify(cert_hex.replace(':', ''))
                    cert = _extract_cert_fields(der, cert_index)
                    if verbose:
                        print("Certificate (" + cert_type + ") for AP " +
                              str(bssid) + ": " + str(cert.get('subject')))
                    errors += database_utils.insertCertificate(
                        cursor, verbose, bssid, mac, cert_type, file, cert)
                except Exception as error:
                    errors += 1
                    if verbose:
                        print("parse_certificates cert error: " + str(error))

        database.commit()
        print(".cap Certificate done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_certificates (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
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
        try:
            values.append(str(field))
        except Exception:
            pass
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


# Get RSN/WPA security details (AKM suites and ciphers) from beacons and
# probe responses.
def parse_security(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name
        # Beacons (0x08) and probe responses (0x05) that carry an RSN IE.
        cap = pyshark.FileCapture(
            file, display_filter="(wlan.fc.type_subtype == 0x08 || "
            "wlan.fc.type_subtype == 0x05) && wlan.rsn.akms.type")
        # cap.set_debug()

        seen = set()
        for pkt in cap:
            bssid, mgt = _pkt_bssid_mgt(pkt)
            # One row per BSSID is enough; the config is stable per AP.
            if bssid is None or mgt is None or bssid.upper() in seen:
                continue

            akm_values = _all_field_values(mgt, 'wlan_rsn_akms_type')
            if not akm_values:
                continue
            pcs_values = _all_field_values(mgt, 'wlan_rsn_pcs_type')
            gcs_values = _all_field_values(mgt, 'wlan_rsn_gcs_type')

            akm_suites = ", ".join(_dedupe(
                [_suite_name(a, RSN_AKM_SUITES) for a in akm_values]))
            pairwise_ciphers = ", ".join(_dedupe(
                [_suite_name(p, RSN_CIPHERS) for p in pcs_values]))
            group_cipher = ", ".join(_dedupe(
                [_suite_name(g, RSN_CIPHERS) for g in gcs_values]))

            akm_ints = {i for i in (_to_int(v) for v in akm_values)
                        if i is not None}
            wpa_version = _classify_wpa(akm_ints)
            enterprise = ('True' if akm_ints & RSN_ENTERPRISE_AKMS
                          else 'False')
            pmf, rsn_capabilities, mfpc, mfpr = _rsn_pmf(mgt)

            if verbose:
                print("Security for AP " + str(bssid) + ": " +
                      wpa_version + " [" + akm_suites + "] PMF=" + pmf)

            errors += database_utils.insertSecurity(
                cursor, verbose, bssid, wpa_version, akm_suites,
                pairwise_ciphers, group_cipher, enterprise, pmf,
                rsn_capabilities, file)
            # Beacons are far more common than the association frames parsed by
            # parse_MFP, so also update the AP mfpc/mfpr from here.
            if mfpc == 'True' or mfpr == 'True':
                errors += database_utils.insertMFP(
                    cursor, verbose, bssid, mfpc, mfpr)
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


# Get EAP-MD5 challenge/response pairs (crackable with hashcat -m 4800)
def parse_eap_md5(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name
        cap = pyshark.FileCapture(file, display_filter="eap.type == 4")
        # cap.set_debug()

        # Correlate the Request (challenge, from the AP) with the Response
        # (response, from the client) sharing the same EAP id.
        challenges = {}  # (ap, client, eap_id) -> challenge hex
        for pkt in cap:
            try:
                code = pkt.eap.code
                eap_id = pkt.eap.id
                src = pkt.wlan.sa
                dst = pkt.wlan.da
            except Exception:
                continue

            try:
                md5_value = pkt.eap.md5_value.replace(':', '')
            except Exception:
                md5_value = None
            if not md5_value:
                continue

            if code == '1':  # EAP-Request/MD5-Challenge sent by the AP
                challenges[(src, dst, eap_id)] = md5_value
            elif code == '2':  # EAP-Response/MD5-Challenge sent by the client
                ap = dst
                client = src
                challenge = challenges.get((ap, client, eap_id))
                if not challenge:
                    continue
                response = md5_value
                # hashcat -m 4800 format: response:challenge:id where the EAP
                # id is hex-encoded (pyshark exposes eap.id as decimal).
                try:
                    eap_id_hex = format(int(eap_id), '02x')
                except Exception:
                    eap_id_hex = eap_id
                hashcat = response + ":" + challenge + ":" + eap_id_hex
                if verbose:
                    print("EAP-MD5 " + str(client) + " -> " + str(ap) +
                          ": " + hashcat)
                errors += database_utils.insertEAPMD5(
                    cursor, verbose, ap, client, "", eap_id, challenge,
                    response, hashcat, file)

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


# Fingerprint clients by the ordered set of information elements (tags) they
# include in their probe requests; useful to identify device model/OS.
def parse_probe_fingerprint(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name
        cap = pyshark.FileCapture(
            file, display_filter="wlan.fc.type_subtype == 0x04")
        # cap.set_debug()

        seen = set()
        for pkt in cap:
            try:
                mac = pkt.wlan.sa
            except Exception:
                continue
            try:
                mgt = pkt['wlan.mgt']
            except Exception:
                continue

            tags = _all_field_values(mgt, 'wlan_tag_number')
            if not tags:
                continue
            ie_order = ",".join(str(tag) for tag in tags)
            fingerprint = database_utils.getHash(ie_order.encode())[:32]

            key = (mac.upper(), fingerprint)
            if key in seen:
                continue
            seen.add(key)

            if verbose:
                print("Probe fingerprint " + str(mac) + ": " + ie_order)
            errors += database_utils.insertProbeFingerprint(
                cursor, verbose, mac, fingerprint, ie_order, file)

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
        os.remove("test.22000")
        print(".cap hcxpcapngtool done, errors", errors)

    except Exception as error:
        errors += 1
        print("Error in exec_hcxpcapngtool (CAP): ", error)
        print(".cap hcxpcapngtool done, errors", errors)
