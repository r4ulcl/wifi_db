#!/bin/python3
# -*- coding: utf-8 -*-
''' Get macs vendor'''
import json
import requests
import os
import tempfile
from shutil import copyfile
import csv

def load_vendors():
    '''Download and load vendors'''
    print('Download and load vendors')
    url='https://maclookup.app/downloads/csv-database/get-db'
    #urlOld = 'https://macaddress.io/database/macaddress.io-db.json' # Not free
    oui = {}

    with tempfile.NamedTemporaryFile() as tmp:
        print(tmp.name)
        try:
            import requests
            headersR = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:93.0) Gecko/20100101 Firefox/93.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8", "Accept-Language": "es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3", "Accept-Encoding": "gzip, deflate", "Upgrade-Insecure-Requests": "1", "Sec-Fetch-Dest": "document", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Site": "none", "Sec-Fetch-User": "?1", "Te": "trailers"}
            response = requests.get(url, headers=headersR)
            tmp.write(response.content)
            tmp.seek(0)
        # error control and copy local (old file)
        except :
            print("Copy local file")
            src = "./mac-vendors-export.csv"
            dst = tmp.name
            copyfile(src, dst)
        with open(tmp.name) as csv_file:
            csv_reader = csv.reader(csv_file, delimiter=',')
            line_count = 0
            for row in csv_reader:
                if line_count == 0:
                    line_count +=1
                else:
                    #print(f'\t{row[0]} works in the {row[1]} department, and was born in {row[2]}.')
                    line_count += 1
                    oui[row[0].replace(':', '')] = row[1]
            print(f'Processed {line_count} lines.')

    return oui

# In case use old macaddress.io-db.json file
def load_local_vendors():
    '''load vendors'''
    oui = {}

    with tempfile.NamedTemporaryFile() as tmp:
        print(tmp.name)
        #if not os.path.isfile(file):  #if file not exists in tmp...
        #with open('/tmp/macaddress.io-db.json', "wb") as file:
        print("Copy local file")
        src = "./macaddress.io-db.json"
        dst = tmp.name
        copyfile(src, dst)

        #with open('/tmp/macaddress.io-db.json', mode="r", encoding="utf-8") as file:
        for line in tmp:
            data_json = json.loads(line)
            #oui[data_json['oui'].replace(':', '')] = data_json['companyName'] #OLD not free
            oui[data_json['macPrefix'].replace(':', '')] = data_json['vendorName']

    return oui


def get_vendor(oui, mac):
    '''Get vendors from mac in oui'''
    mac = mac.replace(':', '')[:-3]
    while mac not in oui and len(mac) >= 6:
        mac = mac[:-1]
    return oui.get(mac, 'Unknown')
