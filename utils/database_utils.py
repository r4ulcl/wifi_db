#!/bin/python3
''' Utils to SQLite DB '''
# -*- coding: utf-8 -*-
import sqlite3
import os
import secrets
import string
import datetime
import hashlib
from dataclasses import dataclass
from typing import Any


# Row carriers: bundle the column values for the wider insert helpers into one
# object so the helpers take (cursor, verbose, row) instead of a long positional
# list. Fields are typed Any because callers pass whatever the parser produced
# (str/int/'True'/'False'); the values are not reinterpreted here.
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


def _log(verbose, msg):
    '''Print `msg` only in verbose mode (one branch, reused everywhere).'''
    if verbose:
        print(msg)


def _exec(cursor, verbose, sql, params):
    '''Run a parameterised statement, optionally echoing it in verbose mode.

    Centralising the `if verbose: print(...)` guard keeps the insert/update
    helpers free of one branch per statement, which is what pushed several of
    them over the cyclomatic-complexity limit.'''
    if verbose:
        print(sql, params)
    cursor.execute(sql, params)


def connectDatabase(name, verbose):
    '''Function to connect to the database'''
    try:
        database = sqlite3.connect(name)
        database.text_factory = str
        database.execute("PRAGMA foreign_keys = 1")
        if verbose:
            print("DB connected OK")
        return database
    except Exception as error:
        print("FATAL ERROR createDatabase: " + str(error))
        exit()


def createDatabase(database, verbose):
    '''Function to create the tables in the database'''
    script_path = os.path.dirname(os.path.abspath(__file__))
    path = script_path + '/wifi_db_database.sql'
    with open(path, 'r', encoding='utf-8') as db_file:
        schema = db_file.read()
    try:
        # The schema is a trusted, static .sql file shipped with the project.
        # executescript runs the whole file in one call, so no per-statement
        # string building is needed.
        database.executescript(schema)
        database.commit()
        if verbose:
            print("Database created")
    except sqlite3.IntegrityError as error:
        print("createDatabase" + str(error))


def createViews(database, verbose):
    '''Function to create the Views in the database'''
    script_path = os.path.dirname(os.path.abspath(__file__))
    path = script_path + '/view.sql'
    with open(path, 'r', encoding='utf-8') as views_file:
        views = views_file.read()
    try:
        # view.sql is a trusted, static file shipped with the project.
        database.executescript(views)
        database.commit()
        if verbose:
            print("Views created")
    except sqlite3.IntegrityError as error:
        print("createViews" + str(error))


def _updateAP(cursor, verbose, ap):
    '''Merge new values into an existing AP row. Called by insertAP when the
    INSERT hits the primary-key constraint: only fills empty/placeholder
    columns and accumulates packetsTotal.'''
    bssid = ap.bssid.upper()
    # Per-column merge rules applied in order. Each only fills an
    # empty/placeholder value (or accumulates packetsTotal), so re-seeing an
    # AP enriches its row without overwriting existing data.
    updates = [
        ("""UPDATE AP SET ssid = CASE WHEN ssid = '' OR ssid IS NULL
            THEN (?) ELSE ssid END WHERE bssid = (?)""", (ap.essid, bssid)),
        ("""UPDATE AP SET manuf = CASE WHEN manuf = '' OR manuf IS NULL
            THEN (?) ELSE manuf END WHERE bssid = (?)""", (ap.manuf, bssid)),
        ("""UPDATE AP SET channel = CASE WHEN channel = '' OR channel IS NULL
            OR channel = 0 THEN (?) ELSE channel END WHERE bssid = (?)""",
         (ap.channel, bssid)),
        ("""UPDATE AP SET frequency = CASE WHEN frequency = '' OR frequency
            IS NULL OR frequency < 2000 THEN (?) ELSE frequency END
            WHERE bssid = (?)""", (ap.freqmhz, bssid)),
        ("""UPDATE AP SET carrier = CASE WHEN carrier = '' OR carrier IS NULL
            THEN (?) ELSE carrier END WHERE bssid = (?)""",
         (ap.carrier, bssid)),
        ("""UPDATE AP SET encryption = CASE WHEN encryption = '' OR encryption
            IS NULL THEN (?) ELSE encryption END WHERE bssid = (?)""",
         (ap.encryption, bssid)),
        ("""UPDATE AP SET packetsTotal = packetsTotal + (?)
            WHERE bssid = (?)""", (ap.packets_total, bssid)),
        ("""UPDATE AP SET lat_t = CASE WHEN lat_t = 0.0 THEN (?) ELSE lat_t
            END, lon_t = CASE WHEN lon_t = 0.0 THEN (?) ELSE lon_t END
            WHERE bssid = (?)""", (ap.lat, ap.lon, bssid)),
        ("""UPDATE AP SET cloaked = CASE WHEN cloaked = 'True' THEN 'True'
            ELSE (?) END WHERE bssid = (?)""", (ap.cloaked, bssid)),
        ("""UPDATE AP SET mfpc = CASE WHEN mfpc = 'False' THEN (?) ELSE mfpc
            END WHERE bssid = (?)""", (ap.mfpc, bssid)),
        ("""UPDATE AP SET mfpr = CASE WHEN mfpr = 'False' THEN (?) ELSE mfpr
            END WHERE bssid = (?)""", (ap.mfpr, bssid)),
    ]
    try:
        # Keep the earliest firstTimeSeen seen for this AP.
        if ap.firstTimeSeen != 0:
            sql = """UPDATE AP SET firstTimeSeen = CASE WHEN
                     firstTimeSeen = '' OR firstTimeSeen = '0' OR
                     firstTimeSeen IS NULL OR firstTimeSeen > (?) AND
                     (?) <> 0 AND firstTimeSeen <> 0 THEN (?) ELSE
                     firstTimeSeen END WHERE bssid = (?)"""
            cursor.execute(sql, (ap.firstTimeSeen, ap.firstTimeSeen,
                                 ap.firstTimeSeen, bssid))
        for sql, params in updates:
            _exec(cursor, verbose, sql, params)
        return int(0)
    except sqlite3.IntegrityError as update_error:
        _log(verbose, "insertAP2 " + str(update_error))
        return int(0)


def insertAP(cursor, verbose, ap):
    '''Insert an AP row, merging into the existing row on a primary-key clash.
    `ap` is an APRow.'''
    try:
        # Explicit column list so AP can carry extra attribute columns (the
        # merged Security/WPS fields) without breaking this 14-value insert.
        cursor.execute('''INSERT INTO AP
                          (bssid, ssid, cloaked, manuf, channel, frequency,
                           carrier, encryption, packetsTotal, lat_t, lon_t,
                           mfpc, mfpr, firstTimeSeen)
                          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                       (ap.bssid.upper(), ap.essid, ap.cloaked, ap.manuf,
                        ap.channel, ap.freqmhz, ap.carrier, ap.encryption,
                        ap.packets_total, ap.lat, ap.lon, ap.mfpc, ap.mfpr,
                        ap.firstTimeSeen))
        return int(0)
    except sqlite3.IntegrityError as error:
        _log(verbose, "insertAP " + str(error))
        return _updateAP(cursor, verbose, ap)
    except sqlite3.Error as error:
        _log(verbose, "insertAP Error " + str(error))
        return int(1)


def isRandomizedMAC(mac):
    '''A MAC is locally administered (randomized) when bit 1 of the first
    octet is set. Returns 'True'/'False' strings (codebase boolean style).'''
    try:
        first_octet = int(mac.replace(':', '').replace('-', '')[0:2], 16)
        return 'True' if first_octet & 0x02 else 'False'
    except Exception:
        return 'False'


def insertAPConstraint(cursor, verbose, bssid):
    '''Ensure the AP row referenced by a foreign key exists, creating a
    placeholder row if needed. Returns the insertAP result code.'''
    return insertAP(cursor, verbose, APRow(
        bssid=bssid, essid="", manuf="", channel="", freqmhz="", carrier="",
        encryption="", packets_total="", lat="0.0", lon="0.0", cloaked='False',
        mfpc='False', mfpr='False', firstTimeSeen=0))


def insertClientConstraint(cursor, verbose, mac):
    '''Ensure the Client row referenced by a foreign key exists, creating a
    placeholder row if needed. Returns the insertClients result code.'''
    return insertClients(cursor, verbose, ClientRow(
        mac=mac, ssid="", manuf="", client_type="", packets_total="0",
        device="", firstTimeSeen=0))


def insertClients(cursor, verbose, client):
    '''Function to insert clients in the database. `client` is a ClientRow.'''
    mac, ssid, manuf = client.mac, client.ssid, client.manuf
    client_type, packets_total = client.client_type, client.packets_total
    device, firstTimeSeen = client.device, client.firstTimeSeen
    try:
        randomized = isRandomizedMAC(mac)
        cursor.execute('''INSERT INTO client VALUES(?,?,?,?,?,?,?,?)''',
                       (mac.upper(), ssid, manuf, client_type, packets_total,
                        device, randomized,
                        firstTimeSeen))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        _log(verbose, "insertClients " + str(error))
        try:
            mac_up = mac.upper()

            # If firstTimeSeen is before current firstTimeSeen update.
            # Fill the row when the stored value is a placeholder
            # (empty/0/NULL) or later than the new one, as long as the new
            # value is real. The previous `AND firstTimeSeen <> 0` made a
            # 0 placeholder impossible to replace with a real timestamp.
            if firstTimeSeen != 0:
                _exec(cursor, verbose,
                      """UPDATE client SET firstTimeSeen = CASE WHEN
                         (firstTimeSeen = '' OR firstTimeSeen = '0' OR
                         firstTimeSeen IS NULL OR firstTimeSeen > (?)) AND
                         (?) <> 0 THEN (?) ELSE
                         firstTimeSeen END WHERE mac = (?)""",
                      (firstTimeSeen, firstTimeSeen, firstTimeSeen, mac_up))

            # Accumulate the packet counter.
            _exec(cursor, verbose,
                  """UPDATE client SET packetsTotal = packetsTotal + (?)
                     WHERE mac = (?)""",
                  (packets_total, mac_up))

            # Fill the remaining columns only when currently empty/NULL. Each
            # statement is a fixed literal (no column interpolation) to stay
            # injection-safe.
            fill_updates = (
                ("""UPDATE client SET ssid = CASE WHEN ssid = '' OR ssid IS
                    NULL THEN (?) ELSE ssid END WHERE mac = (?)""", ssid),
                ("""UPDATE client SET manuf = CASE WHEN manuf = '' OR manuf IS
                    NULL THEN (?) ELSE manuf END WHERE mac = (?)""", manuf),
                ("""UPDATE client SET type = CASE WHEN type = '' OR type IS
                    NULL THEN (?) ELSE type END WHERE mac = (?)""", client_type),
                ("""UPDATE client SET device = CASE WHEN device = '' OR
                    device IS NULL THEN (?) ELSE device END WHERE mac = (?)""",
                 device),
            )
            for sql, value in fill_updates:
                _exec(cursor, verbose, sql, (value, mac_up))

            return int(0)
        except sqlite3.IntegrityError as update_error:
            _log(verbose, "insertClients2 " + str(update_error))
            return int(1)
        # print('Record already exists')
    except sqlite3.Error as error:
        _log(verbose, "insertClients0 Error " + str(error))
        return int(1)


def insertProbe(cursor, verbose, bssid, essid, time):
    ''''''
    try:
        # Explicit column list: Probe also carries the merged probe-request
        # fingerprint columns (filled by insertProbeFingerprint), which this
        # SSID-only insert leaves NULL.
        cursor.execute('''INSERT INTO Probe (mac, ssid, time) VALUES(?,?,?)''',
                       (bssid.upper(), essid, time))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertProbe" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertProbe Error " + str(error))
        return int(1)


def insertWPS(cursor, verbose, wps):
    '''Store the WPS (Wi-Fi Protected Setup) details parsed for an AP.

    WPS configuration is a 1:1 AP attribute, so it lives on the AP row: the AP
    row is ensured to exist, then its WPS columns are merged in. `wps` is a
    WPSRow.'''
    bssid, wlan_ssid = wps.bssid, wps.wlan_ssid
    wps_version, wps_device_name = wps.wps_version, wps.wps_device_name
    wps_model_name, wps_model_number = wps.wps_model_name, wps.wps_model_number
    wps_config_methods = wps.wps_config_methods
    wps_config_methods_keypad = wps.wps_config_methods_keypad
    try:
        # Ensure the AP row exists, then merge the WPS columns into it.
        insertAPConstraint(cursor, verbose, bssid)

        cursor.execute('''UPDATE AP SET wlan_ssid = (?), wps_version = (?),
                          wps_device_name = (?), wps_model_name = (?),
                          wps_model_number = (?), wps_config_methods = (?),
                          wps_config_methods_keypad = (?) WHERE bssid = (?)''',
                       (wlan_ssid, wps_version, wps_device_name, wps_model_name,
                        wps_model_number, wps_config_methods,
                        wps_config_methods_keypad, bssid.upper()))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertWPS " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertWPS Error " + str(error))
        return int(1)


def insertCertificate(cursor, verbose, bssid, mac, cert_type, file, cert):
    '''Function to insert an X.509 certificate seen for an AP BSSID.

    `bssid` is always the access point and `mac` the client, regardless of
    which side sent the certificate. `cert_type` tells whose certificate it
    is ('AP', 'Client' or 'Unknown'). `cert` is a dict with the parsed
    certificate fields (see wifi_db_aircrack._extract_cert_fields).'''
    try:
        # Insert AP CONSTRAINT (create the AP row if it does not exist yet)
        insertAPConstraint(cursor, verbose, bssid)

        mac = mac.upper() if mac else mac

        cursor.execute('''INSERT INTO Certificate VALUES
                          (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                           ?,?,?,?,?,?,?,?,?,?)''',
                       (bssid.upper(), mac, cert_type, file,
                        cert.get('cert_index'),
                        cert.get('version'),
                        cert.get('serial_number'),
                        cert.get('signature_algorithm'),
                        cert.get('issuer'),
                        cert.get('subject'),
                        cert.get('not_before'),
                        cert.get('not_after'),
                        cert.get('subject_cn'),
                        cert.get('subject_o'),
                        cert.get('subject_ou'),
                        cert.get('issuer_cn'),
                        cert.get('issuer_o'),
                        cert.get('issuer_ou'),
                        cert.get('public_key_algorithm'),
                        cert.get('public_key_size'),
                        cert.get('public_key_curve'),
                        cert.get('public_key_exponent'),
                        cert.get('subject_alt_names'),
                        cert.get('key_usage'),
                        cert.get('ext_key_usage'),
                        cert.get('is_ca'),
                        cert.get('path_length'),
                        cert.get('self_signed'),
                        cert.get('authority_key_id'),
                        cert.get('subject_key_id'),
                        cert.get('crl_urls'),
                        cert.get('ocsp_urls'),
                        cert.get('validity_days'),
                        cert.get('sha1_fingerprint'),
                        cert.get('sha256_fingerprint')))
        return int(0)
    except sqlite3.IntegrityError as error:
        # Certificate already stored for this BSSID (same fingerprint)
        if verbose:
            print("insertCertificate " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertCertificate Error " + str(error))
        return int(1)


def insertSecurity(cursor, verbose, sec):
    '''Store the RSN/WPA security details parsed from an AP beacon.

    These are 1:1 AP attributes, so they live on the AP row itself: the AP
    row is ensured to exist, then its security columns are overwritten (the
    latest beacon wins, since the security configuration is stable for a given
    AP). `pmf` is the management-frame-protection state ('Required', 'Capable'
    or 'Disabled') and `rsn_capabilities` is the raw RSN capabilities bitfield.
    `sec` is a SecurityRow; its `file` field is accepted for call-site
    compatibility but no longer stored (AP rows track no per-attribute file).'''
    bssid, wpa_version, akm_suites = sec.bssid, sec.wpa_version, sec.akm_suites
    pairwise_ciphers, group_cipher = sec.pairwise_ciphers, sec.group_cipher
    enterprise, pmf = sec.enterprise, sec.pmf
    rsn_capabilities = sec.rsn_capabilities
    try:
        # Ensure the AP row exists, then merge the security columns into it.
        insertAPConstraint(cursor, verbose, bssid)

        cursor.execute('''UPDATE AP SET wpa_version = (?), akm_suites = (?),
                          pairwise_ciphers = (?), group_cipher = (?),
                          enterprise = (?), pmf = (?), rsn_capabilities = (?)
                          WHERE bssid = (?)''',
                       (wpa_version, akm_suites, pairwise_ciphers, group_cipher,
                        enterprise, pmf, rsn_capabilities, bssid.upper()))
        return int(0)
    except sqlite3.IntegrityError as error:
        if verbose:
            print("insertSecurity " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertSecurity Error " + str(error))
        return int(1)


def insertCapabilities(cursor, verbose, cap):
    '''Store the 802.11 management capabilities parsed from an AP beacon /
    probe response (fast roaming and Multiple BSSID / CSA advertisements).

    These are 1:1 AP attributes, so they live on the AP row. The boolean flags
    are merged "sticky" (once 'True' they stay 'True', so a later beacon that
    happens to omit the element does not clear it), while the detail fields
    (mobility domain id, max BSSID indicator, CSA target channel) take the
    latest non-empty value seen. `cap` is a CapabilitiesRow.'''
    bssid, ft_80211r = cap.bssid, cap.ft_80211r
    mobility_domain_id, rrm_80211k = cap.mobility_domain_id, cap.rrm_80211k
    bss_transition_80211v, mbssid = cap.bss_transition_80211v, cap.mbssid
    max_bssid_indicator, csa = cap.max_bssid_indicator, cap.csa
    csa_new_channel = cap.csa_new_channel
    try:
        # Ensure the AP row exists, then merge the capability columns into it.
        insertAPConstraint(cursor, verbose, bssid)

        cursor.execute(
            '''UPDATE AP SET
                 ft_80211r = CASE WHEN ft_80211r = 'True' THEN 'True'
                             ELSE (?) END,
                 mobility_domain_id = COALESCE(NULLIF((?), ''),
                                               mobility_domain_id),
                 rrm_80211k = CASE WHEN rrm_80211k = 'True' THEN 'True'
                              ELSE (?) END,
                 bss_transition_80211v = CASE WHEN bss_transition_80211v =
                              'True' THEN 'True' ELSE (?) END,
                 mbssid = CASE WHEN mbssid = 'True' THEN 'True' ELSE (?) END,
                 max_bssid_indicator = COALESCE((?), max_bssid_indicator),
                 csa = CASE WHEN csa = 'True' THEN 'True' ELSE (?) END,
                 csa_new_channel = COALESCE((?), csa_new_channel)
               WHERE bssid = (?)''',
            (ft_80211r, mobility_domain_id, rrm_80211k, bss_transition_80211v,
             mbssid, max_bssid_indicator, csa, csa_new_channel,
             bssid.upper()))
        return int(0)
    except sqlite3.IntegrityError as error:
        if verbose:
            print("insertCapabilities " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertCapabilities Error " + str(error))
        return int(1)


def insertHiddenSSID(cursor, verbose, bssid, ssid):
    '''Recover a cloaked SSID seen in a probe response or (re)association
    request and store it on the AP row. The SSID is only written when the AP
    row has no SSID yet (empty/NULL), so a real beacon SSID is never
    overwritten, and `ssid_revealed` records that the name was learned from a
    non-beacon frame.'''
    try:
        if not ssid:
            return int(0)
        # Ensure the AP row exists, then fill the SSID only if still unknown.
        insertAPConstraint(cursor, verbose, bssid)

        cursor.execute(
            '''UPDATE AP SET ssid = (?), ssid_revealed = 'True'
               WHERE bssid = (?) AND (ssid IS NULL OR ssid = '')''',
            (ssid, bssid.upper()))
        return int(0)
    except sqlite3.IntegrityError as error:
        if verbose:
            print("insertHiddenSSID " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertHiddenSSID Error " + str(error))
        return int(1)


def insertConnected(cursor, verbose, bssid, mac):
    ''''''
    try:
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO connected VALUES(?,?)''',
            (bssid.upper(), mac.upper()))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertConnected" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertConnected Error " + str(error))
        return int(1)


def insertMFP(cursor, verbose, bssid, mfpc, mfpr):
    ''''''
    try:
        # Ensure the AP row exists, carrying through the MFP flags.
        insertAP(cursor, verbose, APRow(
            bssid=bssid, essid="", manuf="", channel="", freqmhz="",
            carrier="", encryption="", packets_total="", lat="0.0", lon="0.0",
            cloaked='False', mfpc=mfpc, mfpr=mfpr, firstTimeSeen=0))

        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertMFP" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertMFP Error " + str(error))

        return int(1)


def insertHandshake(cursor, verbose, bssid, mac, file):
    ''''''
    try:
        error = 0
        # Insert file
        error += insertFile(cursor, verbose, file)

        # Get file hash MD5
        with open(file, 'rb') as file_handle:
            file_hash = getHash(file_handle.read())

        # insertHandshake Client and AP CONSTRAINT
        error += insertClientConstraint(cursor, verbose, mac)
        error += insertAPConstraint(cursor, verbose, bssid)

        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO handshake VALUES(?,?,?,?,?)''',
            (bssid.upper(), mac.upper(), file, file_hash, ""))
        return int(error)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertHandshake" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertHandshake Error " + str(error))
        return int(1)


def insertIdentity(cursor, verbose, bssid, mac, identity, method):
    ''''''
    error = 0
    try:
        # Insert Identity Client and AP CONSTRAINT
        error += insertClientConstraint(cursor, verbose, mac)
        error += insertAPConstraint(cursor, verbose, bssid)

        # The realm is the part after '@' in a user@realm identity (the
        # anonymous outer identity often carries only the realm).
        realm = ""
        if identity and '@' in identity:
            realm = identity.rsplit('@', 1)[1]

        if verbose:
            print('output ' + bssid.upper(), mac.upper(), identity, method,
                  realm)
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO identity VALUES(?,?,?,?,?)''',
            (bssid.upper(), mac.upper(), identity, method, realm))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertIdentity" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertIdentity Error " + str(error))
        return int(1)


def insertEAPMD5(cursor, verbose, eap):
    '''Insert a captured EAP-MD5 challenge/response pair (crackable offline
    with hashcat -m 4800). Keyed by (bssid, mac, eap_id). `eap` is an
    EAPMD5Row.'''
    bssid, mac, identity = eap.bssid, eap.mac, eap.identity
    eap_id, challenge = eap.eap_id, eap.challenge
    response, hashcat, file = eap.response, eap.hashcat, eap.file
    try:
        # Insert Client and AP CONSTRAINT
        insertClientConstraint(cursor, verbose, mac)
        insertAPConstraint(cursor, verbose, bssid)

        cursor.execute('''INSERT OR REPLACE INTO EAPMD5
                          VALUES(?,?,?,?,?,?,?,?)''',
                       (bssid.upper(), mac.upper(), identity, eap_id,
                        challenge, response, hashcat, file))
        return int(0)
    except sqlite3.IntegrityError as error:
        if verbose:
            print("insertEAPMD5 " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertEAPMD5 Error " + str(error))
        return int(1)


def insertProbeFingerprint(cursor, verbose, mac, ssid, fingerprint, ie_order,
                           file):
    '''Store a probe-request fingerprint (ordered list of information element
    IDs and its hash) for device identification.

    The fingerprint is a probe-request attribute, so it lives on the Probe row
    for the (mac, ssid) that was probed: the Client row is ensured to exist,
    then the fingerprint columns are merged into the matching Probe row
    (creating it if the SSID was not already seen). `ssid` is '' for broadcast
    probe requests.'''
    try:
        # Insert Client CONSTRAINT
        insertClientConstraint(cursor, verbose, mac)

        cursor.execute('''INSERT INTO Probe
                          (mac, ssid, time, fingerprint, ie_order, file)
                          VALUES (?,?,?,?,?,?)
                          ON CONFLICT(mac, ssid) DO UPDATE SET
                              fingerprint = excluded.fingerprint,
                              ie_order = excluded.ie_order,
                              file = excluded.file''',
                       (mac.upper(), ssid, 0, fingerprint, ie_order, file))
        return int(0)
    except sqlite3.IntegrityError as error:
        if verbose:
            print("insertProbeFingerprint " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertProbeFingerprint Error " + str(error))
        return int(1)


def insertSeenClient(cursor, verbose, seen):
    '''Insert one client sighting. `seen` is a SeenClientRow.'''
    mac, time, tool = seen.mac, seen.time, seen.tool
    signal_rssi, lat, lon, alt = seen.signal_rssi, seen.lat, seen.lon, seen.alt
    try:
        cursor.execute('''INSERT INTO SeenClient
                       VALUES(?,?,?,?,?,?,?)''',
                       (mac.upper(), time, tool, signal_rssi, lat, lon, alt))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertSeenClient" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertSeenClient Error " + str(error))
        return int(1)


def insertSeenAP(cursor, verbose, seen):
    '''Insert one AP sighting. `seen` is a SeenAPRow.'''
    bssid, time, tool, signal_rsi = seen.bssid, seen.time, seen.tool, \
        seen.signal_rsi
    lat, lon = seen.lat, seen.lon
    alt, bsstimestamp = seen.alt, seen.bsstimestamp
    try:
        cursor.execute('''INSERT INTO SeenAp VALUES(?,?,?,?,?,?,?,?)''',
                       (bssid.upper(), time, tool, signal_rsi,
                        lat, lon, alt, bsstimestamp))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertSeenAP" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertSeenAP Error " + str(error))
        return int(1)


def setHashcat(cursor, verbose, bssid, mac, file, hashcat):
    try:
        # Remove enter at the end
        hashcat = hashcat.strip()

        # Ensure the rows referenced by the Handshake foreign keys exist
        # before inserting. hcxpcapngtool --all extracts handshakes/PMKIDs
        # that the strict tshark 4-way parser may have skipped, so the AP,
        # Client and File rows are not guaranteed to already be present.
        # Without this the INSERT below fails with "FOREIGN KEY constraint
        # failed" and the hashcat hash is silently dropped, leaving the
        # handshake stored with an empty hash.
        insertFile(cursor, verbose, file)
        insertClientConstraint(cursor, verbose, mac)
        insertAPConstraint(cursor, verbose, bssid)

        with open(file, 'rb') as file_handle:
            file_hash = getHash(file_handle.read())
        if verbose:
            print("HASH: ", file_hash)
        cursor.execute('''INSERT OR REPLACE INTO Handshake
                          VALUES(?,?,?,?,?)''',
                       (bssid.upper(), mac.upper(), file, file_hash, hashcat))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("setHashcat" + str(error))
        return int(1)


def insertFile(cursor, verbose, file):
    try:
        # Get MD5
        with open(file, 'rb') as file_handle:
            file_hash = getHash(file_handle.read())
        if verbose:
            print("HASH: ", file_hash)
        # INSERT OR IGNORE, not OR REPLACE: the Files (file,hashSHA) row is the
        # parent of Handshake via an ON DELETE CASCADE foreign key. REPLACE
        # deletes the existing parent row (firing the cascade and wiping every
        # Handshake for this file) before re-inserting it, so callers that just
        # need to guarantee the row exists (insertHandshake, setHashcat during
        # the hcxpcapngtool pass) would silently destroy already-parsed
        # handshakes. IGNORE leaves the existing row untouched.
        # Store the timestamp as a formatted string instead of a datetime
        # object. Passing a datetime to sqlite3 relies on the default adapter,
        # deprecated since Python 3.12 (and slated for removal), which emitted
        # a DeprecationWarning on every insert. The "%Y-%m-%d %H:%M:%S" format
        # matches the firstTimeSeen timestamps stored elsewhere.
        cursor.execute('''INSERT OR IGNORE INTO Files VALUES(?,?,?,?)''',
                       (file, "False", file_hash,
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("insertFile" + str(error))
        return int(1)


def getHash(file):
    return hashlib.sha256(file).hexdigest()


def setFileProcessed(cursor, verbose, file):
    try:
        if verbose:
            print("setFileProcessed", file)
        cursor.execute('''UPDATE Files SET processed = (?) where file = ?''',
                       ("True", file))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("setFileProcessed" + str(error))
        return int(1)


def checkFileProcessed(cursor, verbose, file):
    if not os.path.exists(file):
        if verbose:
            print("File", file, "does not exist")
        return int(0)

    with open(file, 'rb') as file_handle:
        file_hash = getHash(file_handle.read())

    try:
        cursor.execute('''SELECT file FROM Files WHERE hashSHA = (?)
                          AND processed = "True"''', (file_hash,))

        output = cursor.fetchall()
        if len(output) > 0:
            return int(1)

        return int(0)
    except sqlite3.IntegrityError as error:
        print("checkFileProcessed" + str(error))
        return int(2)


# obfuscated the database AA:BB:CC:XX:XX:XX-DEFG,
# needs database and not cursos to commit
def _obfuscateColumn(database, verbose, label, select_sql, update_sql,
                     uppercase):
    '''Replace every address in one table column with AA:BB:CC:XX:XX:XX-<rand>.

    `select_sql`/`update_sql` are fixed literals supplied by the caller (no
    identifier interpolation, so the statements stay injection-safe). The 8
    random lowercase letters keep the obfuscated values unique.'''
    try:
        if verbose:
            print("obfuscated " + label)
        cursor = database.cursor()
        cursor.execute(select_sql)
        for row in cursor.fetchall():
            aux = ''.join(secrets.choice(string.ascii_lowercase)
                          for _ in range(8))
            new = row[0][0:9] + 'XX:XX:XX' + '-' + aux
            old = row[0]
            if uppercase:
                new, old = new.upper(), old.upper()
            cursor.execute(update_sql, (new, old))
        database.commit()
        return int(0)
    except sqlite3.IntegrityError as error:
        print("obfuscateDB" + str(error))
        return int(1)


def obfuscateDB(database, verbose):
    '''Obfuscate AP BSSIDs and Client MACs so the DB can be shared safely.'''
    _obfuscateColumn(database, verbose, "APs",
                     "SELECT bssid from AP; ",
                     "UPDATE AP set bssid = (?) where bssid = ?", False)
    return _obfuscateColumn(database, verbose, "clients",
                            "SELECT mac from Client; ",
                            "UPDATE Client set mac = (?) where mac = ?", True)

# exists = '11:22:33:44:55:77' in whitelist


def clearWhitelist(database, verbose, whitelist):
    with open(whitelist, encoding='utf-8') as f:
        whitelist = f.read().splitlines()
    cursor = database.cursor()
    for mac in whitelist:
        mac = mac.upper()
        if verbose:
            print("clearWhitelist", mac)
        try:
            cursor.execute(
                "DELETE from Handshake where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Identity where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from SeenAP where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from SeenClient where mac = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Probe where mac = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Connected where bssid = (?)  OR mac = (?) ",
                (mac.upper(), mac.upper(),))
            cursor.execute(
                "DELETE from AP where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Client where mac = (?) ", (mac.upper(),))

            database.commit()

        except sqlite3.IntegrityError as error:
            print("clearWhitelist" + str(error))
    print("CLEARED WHITELIST MACS")
