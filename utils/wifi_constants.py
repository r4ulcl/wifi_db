''' Shared constants for the aircrack/kismet/.cap parsers.

EAP method types, RSN AKM / cipher suite selectors and the 802.11
management-frame element (tag) numbers used to detect AP capabilities.
'''
# -*- coding: utf-8 -*-


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
