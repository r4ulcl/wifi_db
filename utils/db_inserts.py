#!/bin/python3
''' Insert/update helpers for the wider DB tables (row-dataclass based). '''
# -*- coding: utf-8 -*-
import sqlite3
from utils.db_rows import APRow, ClientRow


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


def insertWPS(cursor, verbose, wps):
    '''Store the WPS (Wi-Fi Protected Setup) details parsed for an AP.

    WPS configuration is a 1:1 AP attribute, so it lives on the AP row: the AP
    row is ensured to exist, then its WPS columns are merged in. The merge is
    "sticky": a Beacon carries only a reduced WPS IE (no device/model name),
    while a Probe Response carries the full set, and the two interleave in a
    capture -- so each detail column keeps its existing non-empty value rather
    than being overwritten with the '' a later Beacon yields, and wps_version
    only ever climbs to '2.0'. `wps` is a WPSRow.'''
    bssid, wlan_ssid = wps.bssid, wps.wlan_ssid
    wps_version, wps_device_name = wps.wps_version, wps.wps_device_name
    wps_model_name, wps_model_number = wps.wps_model_name, wps.wps_model_number
    wps_config_methods = wps.wps_config_methods
    wps_config_methods_keypad = wps.wps_config_methods_keypad
    try:
        # Ensure the AP row exists, then merge the WPS columns into it.
        insertAPConstraint(cursor, verbose, bssid)

        cursor.execute(
            '''UPDATE AP SET
                 wlan_ssid = COALESCE(NULLIF((?), ''), wlan_ssid),
                 wps_version = CASE WHEN wps_version = '2.0' THEN '2.0'
                               ELSE (?) END,
                 wps_device_name = COALESCE(NULLIF((?), ''), wps_device_name),
                 wps_model_name = COALESCE(NULLIF((?), ''), wps_model_name),
                 wps_model_number = COALESCE(NULLIF((?), ''), wps_model_number),
                 wps_config_methods = COALESCE(NULLIF((?), ''),
                                               wps_config_methods),
                 wps_config_methods_keypad = COALESCE(NULLIF((?), ''),
                                             wps_config_methods_keypad)
               WHERE bssid = (?)''',
            (wlan_ssid, wps_version, wps_device_name, wps_model_name,
             wps_model_number, wps_config_methods, wps_config_methods_keypad,
             bssid.upper()))
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
