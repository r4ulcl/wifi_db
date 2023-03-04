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
import pyshark
import subprocess
import platform
import binascii

def parse_netxml(ouiMap, name, database, verbose):
    '''Function to parse the .kismet.netxml files'''

    filename = name+".kismet.netxml"
    exists = os.path.isfile(filename)
    errors = 0
    try:
        cursor = database.cursor()
        if exists:
            with open(filename, 'r') as file:
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
                        freqmhz, carrier, encryption, packets_total, lat, lon,
                        cloaked)

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
        errors += 1
        print("parse_netxml " + str(error))
        print("Error in kismet.netxml")
        print(".kismet.netxml OK, errors", errors)


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
                            freqmhz = 0
                            carrier = ""
                            encryption = row[7]
                            packets_total = row[16]
                            lat = row[32]
                            lon = row[33]
                            cloaked = 'False'
                            errors += database_utils.insertAP(
                                cursor, verbose, bssid, essid, manuf, channel,
                                freqmhz, carrier, encryption, packets_total,
                                lat, lon, cloaked)
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
                            cloaked = 'False'

                            errors += database_utils.insertAP(
                                cursor, verbose,  bssid, essid[1:], manuf,
                                channel, freq, carrier, encrypt,
                                packets_total, 0, 0, cloaked)

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
        errors += 1
        print("parse_csv " + str(error))
        print("Error in .csv")
        print(".csv OK, errors", errors)


def parse_log_csv(ouiMap, name, database, verbose, fake_lat, fake_lon):
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
                                lat = row[6]
                                lon = row[7]
                                if fake_lat != "":  # just write file in db
                                    lat = fake_lat
                                if fake_lon != "":
                                    lon = fake_lon
                                errors += database_utils.insertSeenClient(
                                    cursor, verbose, row[3], row[0],
                                    'aircrack-ng', row[4], lat, lon,
                                    '0.0')

                        if len(row) > 10 and row[10] == "AP":
                            lat = row[6]
                            lon = row[7]
                            if fake_lat != "":
                                lat = fake_lat
                            if fake_lon != "":
                                lon = fake_lon
                            manuf = oui.get_vendor(ouiMap, row[3])
                            cloaked = 'False'
                            errors += database_utils.insertAP(
                                cursor, verbose,  row[3], row[2],
                                manuf, 0, 0, '', '', 0, lat, lon,
                                cloaked)

                            # if row[6] != "0.000000":
                            errors += database_utils.insertSeenAP(
                                cursor, verbose,  row[3], row[0],
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
    if hcxpcapngtool:
        exec_hcxpcapngtool(name, database, verbose)


# Get handshakes from .cap
def parse_handshakes(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name+".cap"
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
                    # IF is the second and the prev is the first one add handshake
                    if flag.find('10a') != -1:
                        # print('handhsake 2 of 4')
                        if (prevFlag.find('08a') and
                                dst == prevSrc and src == prevDst):  # first
                            if verbose:
                                print("Valid handshake from client " + prevSrc +
                                      " to AP " + prevDst)
                            errors += database_utils.insertHandshake(cursor,
                                                                     verbose, dst,
                                                                     src, file)
                    else:
                        prevSrc = src
                        prevDst = dst
                        prevFlag = flag
            except:
                errors += 1
        database.commit()
        print(".cap Handshake done, errors", errors)
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in parse_handshakes (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
    except Exception as error:
        errors += 1
        print("Error in parse_handshakes (CAP): ", error)
        print(".cap Handshake done, errors", errors)


# Get handshakes from .cap
def parse_WPS(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name+".cap"
        cap = pyshark.FileCapture(
            file, display_filter="wps.wifi_protected_setup_state == 0x02 and wlan.da == ff:ff:ff:ff:ff:ff")
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
                bssid = pkt.wlan.sa
                bssid = bssid.upper()
            except Exception:
                errors += 1
            try:
                wlan_ssid_hex = pkt[wmgt].wlan_ssid
                wlan_ssid_bytes = binascii.unhexlify(wlan_ssid_hex.replace(':', ''))
                wlan_ssid = wlan_ssid_bytes.decode('ascii')
                if ('20' in pkt[wmgt].wps_ext_version2):
                    wps_version = '2.0'
            except Exception as e:
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

            errors += database_utils.insertWPS(cursor, verbose, bssid, wlan_ssid,
                                               wps_version, wps_device_name,
                                               wps_model_name, wps_model_number,
                                               wps_config_methods,
                                               wps_config_methods_keypad)

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
        file = name+".cap"
        cap = pyshark.FileCapture(file, display_filter="eap")
        # cap.set_debug()

        dst = ""
        src = ""
        identity = ""
        method = ""

        # The information is: Identity, method, method... , Identity2, method2, method2...
        for pkt in cap:
            # print(pkt.eapol.field_names)
            try:
                if pkt.eap.type == '1':  # EAP = 1
                    dst = pkt.wlan.da
                    src = pkt.wlan.sa
                    if pkt.eap.code == '2':
                        try:
                            identity = pkt.eap.identity
                        except:
                            errors += 1
                # EAP-PEAP
                elif pkt.eap.type == '25':  # Found EAP-PEAP
                    method = "EAP-PEAP"
                    # Insert, if its already error and continue
                    database_utils.insertIdentity(cursor, verbose,
                                                  dst, src, identity, method)

                elif pkt.eap.type == '13':  # Found EAP-TLS
                    method = "EAP-TLS"
                    database_utils.insertIdentity(cursor, verbose,
                                                  dst, src, identity, method)
                else:
                    method = "OTHER (NOT EAP-PEAP OR EAP-TLS) - ID: " + \
                        pkt.eap.type
                    database_utils.insertIdentity(cursor, verbose,
                                                  dst, src, identity, method)
            except Exception as e:
                if verbose:
                    print("ERROR:", e)
                    errors += 1

        database.commit()
        print(".cap Identity done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_identities (CAP): ", error)
        print(".cap Identity done, errors", errors)


# Use hcxpcapngtool to get the 22000 hash to hashcat
def exec_hcxpcapngtool(name, database, verbose):
    try:
        # cmd = "where" if platform.system() == "Windows" else "which"
        # subprocess.call([cmd, "hcxpcapngtool"])
        cursor = database.cursor()
        errors = 0
        fileName = name + ".cap"
        # exec_hcxpcapngtool
        arguments = fileName + ' -o test.22000'

        execution = subprocess.check_output("hcxpcapngtool --all " + arguments,
                                            shell=True)
        if verbose:
            print(execution)

        # Read output (fileName) each line
        file_exists = os.path.exists('test.22000')
        if not file_exists:
            return
        with open('test.22000') as f:
            lines = f.readlines()
            for line in lines:
                # update in database aka insert_hash
                split = line.split('*')
                ap_lower = split[3].upper()
                client_lower = split[4].upper()
                # : format
                ap = (':'.join(ap_lower[i:i+2] for i in range(0, 12, 2)))
                client = (':'.join(client_lower[i:i+2] for i in
                          range(0, 12, 2)))
                if verbose:
                    print(ap)
                    print(client)
                    print(line)
                # Update handshake

                errors += database_utils.set_hashcat(cursor, verbose,
                                                     ap, client, fileName,
                                                     line)
        os.remove("test.22000")
        print(".cap hcxpcapngtool done, errors", errors)

    except Exception as error:
        errors += 1
        print("Error in exec_hcxpcapngtool (CAP): ", error)
        print(".cap hcxpcapngtool done, errors", errors)
