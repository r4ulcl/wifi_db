#!/bin/python3
# -*- coding: utf-8 -*-
''' Get macs vendor'''
import json
import requests
import os
from shutil import copyfile

def load_vendors():
    '''Download and load vendors'''
    url = 'https://macaddress.io/database/macaddress.io-db.json'
    file = "/tmp/macaddress.io-db.json"

    if not os.path.isfile(file):  #if file not exists in tmp...
        with open('/tmp/macaddress.io-db.json', "wb") as file:
            try:
                response = requests.get(url)
                file.write(response.content)
                # error control and copy local (old file)!!!!!!!!!!!!!!!!!!!!!!!!!!!!! TODO
            except :
                print("Copy local file")
                src = "./macaddress.io-db.json"
                dst = "/tmp/macaddress.io-db.json"
                copyfile(src, dst)

    oui = {}
    with open('/tmp/macaddress.io-db.json', mode="r", encoding="utf-8") as file:
        for line in file:
            data_json = json.loads(line)
            oui[data_json['oui'].replace(':', '')] = data_json['companyName']
    return oui


def get_vendor(oui, mac):
    '''Get vendors from mac in oui'''
    mac = mac.replace(':', '')[:-3]
    while mac not in oui and len(mac) >= 6:
        mac = mac[:-1]
    return oui.get(mac, 'Unknown')
