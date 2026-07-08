#!/bin/python3
# -*- coding: utf-8 -*-
''' Get macs vendor'''
import tempfile
from shutil import copyfile
import csv
import os
import time


def load_vendors():
    '''Download and load vendors'''
    print('Download and load vendors')
    url = 'https://maclookup.app/downloads/csv-database/get-db'
    # urlOld = 'https://macaddress.io/database/macaddress.io-db.json'#Notfree
    oui = {}
    script_path = os.path.dirname(os.path.abspath(__file__))
    fileCSV = script_path + "/mac-vendors-export.csv"

    # Check if file downloaded in last 2h
    redownload = True
    if os.path.exists(fileCSV):
        modification_time = os.path.getmtime(fileCSV)
        current_time = time.time()
        # Check if the file was modified more than 24 hours ago
        if current_time - modification_time < 2 * 60 * 60:
            print("File was download within the last 2 hours - SKIP")
            redownload = False

    if redownload:  # download again if >2h or file dont exists
        with tempfile.NamedTemporaryFile(delete=True) as tmp:
            print(tmp.name)
            try:
                import requests
                headersR = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; "
                            "Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0",
                            "Accept": "text/html,application/"
                            "xhtml+xml,application/xml;"
                            "q=0.9,image/avif,image/webp,*/*;q=0.8",
                            "Accept-Language":
                            "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3",
                            "Accept-Encoding": "gzip, deflate",
                            "Upgrade-Insecure-Requests": "1",
                            "Sec-Fetch-Dest": "document",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1",
                            "Te": "trailers"}
                response = requests.get(url, headers=headersR, timeout=5)
                tmp.write(response.content)
                tmp.seek(0)

                # if downloaded update the saved
                src = tmp.name
                print("Copy new file to", fileCSV)
                copyfile(src, fileCSV)
            # error control and copy local (old file)
            except requests.exceptions.RequestException as e:
                # catastrophic error. bail.
                print(e)
            tmp.close()
            # os.unlink(tmp.name)

    with open(fileCSV, encoding='cp850') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in csv_reader:
            if line_count == 0:
                line_count += 1
            else:
                line_count += 1
                oui[row[0].replace(':', '')] = row[1]
        # print(f'Processed {line_count} lines.')

    return oui


def get_vendor(oui, mac, verbose):
    '''Get vendors from mac in oui'''
    mac = mac.replace(':', '')[:-3]
    while mac not in oui and len(mac) >= 6:
        if verbose:
            print(mac)
        mac = mac[:-1]
    return oui.get(mac, 'Unknown')
