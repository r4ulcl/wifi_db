#!/bin/python3
''' Row dataclasses: column carriers for the wide insert helpers in db_inserts. '''
# -*- coding: utf-8 -*-
from dataclasses import dataclass
from typing import Any


# Fields are typed Any because callers pass whatever the parser
# produced (str/int/'True'/'False'); values are not reinterpreted.
@dataclass
class APRow:
    '''Column values for one AP row (insertAP / _updateAP).'''
    bssid: Any
    essid: Any
    manuf: Any
    channel: Any
    freqmhz: Any
    carrier: Any
    encryption: Any
    packets_total: Any
    lat: Any
    lon: Any
    cloaked: Any
    mfpc: Any
    mfpr: Any
    firstTimeSeen: Any


@dataclass
class ClientRow:
    '''Column values for one Client row (insertClients).'''
    mac: Any
    ssid: Any
    manuf: Any
    client_type: Any
    packets_total: Any
    device: Any
    firstTimeSeen: Any


@dataclass
class WPSRow:
    '''WPS attributes merged onto an AP row (insertWPS).'''
    bssid: Any
    wlan_ssid: Any
    wps_version: Any
    wps_device_name: Any
    wps_model_name: Any
    wps_model_number: Any
    wps_config_methods: Any
    wps_config_methods_keypad: Any


@dataclass
class SecurityRow:
    '''RSN/WPA attributes merged onto an AP row (insertSecurity).'''
    bssid: Any
    wpa_version: Any
    akm_suites: Any
    pairwise_ciphers: Any
    group_cipher: Any
    enterprise: Any
    pmf: Any
    rsn_capabilities: Any
    file: Any


@dataclass
class CapabilitiesRow:
    '''802.11r/k/v + MBSSID/CSA attributes merged onto an AP row
    (insertCapabilities).'''
    bssid: Any
    ft_80211r: Any
    mobility_domain_id: Any
    rrm_80211k: Any
    bss_transition_80211v: Any
    mbssid: Any
    max_bssid_indicator: Any
    csa: Any
    csa_new_channel: Any


@dataclass
class EAPMD5Row:
    '''One captured EAP-MD5 challenge/response pair (insertEAPMD5).'''
    bssid: Any
    mac: Any
    identity: Any
    eap_id: Any
    challenge: Any
    response: Any
    hashcat: Any
    file: Any


@dataclass
class SeenClientRow:
    '''One client sighting (insertSeenClient).'''
    mac: Any
    time: Any
    tool: Any
    signal_rssi: Any
    lat: Any
    lon: Any
    alt: Any


@dataclass
class SeenAPRow:
    '''One AP sighting (insertSeenAP).'''
    bssid: Any
    time: Any
    tool: Any
    signal_rsi: Any
    lat: Any
    lon: Any
    alt: Any
    bsstimestamp: Any
