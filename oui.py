''' Get macs vendor'''
import json
import requests


def load_vendors():
    '''Download and load vendors'''
    url = 'https://macaddress.io/database/macaddress.io-db.json'

    with open('macaddress.io-db.json', "wb") as file:
        response = requests.get(url)
        file.write(response.content)

    oui = {}
    with open('macaddress.io-db.json', mode="r", encoding="utf-8") as file:
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
