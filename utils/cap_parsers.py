''' Parse .cap/.pcap capture files into the SQLite DB: EAPOL handshakes, MFP,
WPS, EAP identities, EAP-MD5 pairs and probe-request fingerprints, plus the
hcxpcapngtool 22000-hash extraction. `parse_cap` dispatches to every .cap
parser (including the certificate, security, capability and hidden-SSID parsers
that live in their own modules). '''
# -*- coding: utf-8 -*-
import binascii
import os
import subprocess  # nosec B404 - only used with a fixed, absolute-path command

from utils import database_utils
from utils.cap_common import pyshark, _safe, _all_field_values, _to_int
from utils.wifi_constants import EAP_METHOD_TYPES
from utils.cert_parsers import parse_certificates
from utils.beacon_parsers import (parse_security, parse_capabilities,
                                  parse_hidden_ssid)


def parse_cap(name, database, verbose, hcxpcapngtool, tshark):
    if tshark:
        parse_handshakes(name, database, verbose)
        parse_WPS(name, database, verbose)
        parse_identities(name, database, verbose)
        parse_MFP(name, database, verbose)
        parse_certificates(name, database, verbose)
        parse_security(name, database, verbose)
        parse_capabilities(name, database, verbose)
        parse_hidden_ssid(name, database, verbose)
        parse_eap_md5(name, database, verbose)
        parse_probe_fingerprint(name, database, verbose)
    if hcxpcapngtool:
        exec_hcxpcapngtool(name, database, verbose)


# Get handshakes from .cap
def _handshake_for_pkt(cursor, verbose, pkt, prev, file):
    '''Process one EAPOL packet for a 4-way-handshake message-2 match.

    `prev` is the (src, dst, key_info) of the previous EAPOL frame. Returns
    (errors, new_prev): a message-2 (key info containing '10a') that follows the
    matching message-1 ('08a') in the opposite direction is a valid pair; any
    other EAPOL-Key frame is remembered as a potential message-1.'''
    if verbose:
        print(pkt.eapol.field_names)
        print(pkt.eapol.type)
    if pkt.eapol.type != '3':  # only EAPOL-Key frames
        return 0, prev
    src = pkt.wlan.ta
    dst = pkt.wlan.da
    flag = pkt.eapol.wlan_rsna_keydes_key_info
    if flag.find('10a') == -1:
        return 0, (src, dst, flag)  # remember as a potential message-1
    prevSrc, prevDst, prevFlag = prev
    if prevFlag.find('08a') != -1 and dst == prevSrc and src == prevDst:
        if verbose:
            print("Valid handshake from client " + prevSrc + " to AP " +
                  prevDst)
        return database_utils.insertHandshake(
            cursor, verbose, dst, src, file), prev
    return 0, prev


def parse_handshakes(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        cap = pyshark.FileCapture(file, display_filter="eapol")
        # cap.set_debug()
        prev = ("", "", "")

        for pkt in cap:
            try:
                delta, prev = _handshake_for_pkt(cursor, verbose, pkt, prev,
                                                 file)
                errors += delta
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
def _insert_one_mfp(cursor, verbose, pkt):
    '''Store MFP (PMF) capable/required flags for one management frame, read
    from its RSN Capabilities bitfield. Returns the insert error count (0/1).'''
    if not (pkt['wlan.mgt'].wlan_rsn_capabilities and pkt.wlan.ta):
        return 0
    capabilities = pkt['wlan.mgt'].wlan_rsn_capabilities
    # MFP lives in the RSN Capabilities bitfield:
    #   bit 7 (0x80) = MFP Capable
    #   bit 6 (0x40) = MFP Required
    # Test the bits instead of matching exact values, so APs with other
    # capability bits set are detected too.
    cap_int = int(capabilities, 16)
    mfpc = 'True' if cap_int & 0x80 else 'False'
    mfpr = 'True' if cap_int & 0x40 else 'False'
    if not (mfpc == 'True' or mfpr == 'True'):
        return 0
    if verbose:
        print(f"MFPC: {mfpc}")
        print(f"MFPR: {mfpr}")
    return database_utils.insertMFP(cursor, verbose, pkt.wlan.ta, mfpc, mfpr)


def parse_MFP(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
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
                errors += _insert_one_mfp(cursor, verbose, pkt)
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


def _wps_fields_for_pkt(pkt):
    '''Decode the WPS attributes of one Beacon / Probe Response into
    (bssid, fields), where fields' keys are the WPSRow attribute names. Every
    attribute is read defensively with _safe(): an absent field yields ''
    rather than raising, since a Beacon's reduced WPS IE legitimately omits
    most of them.'''
    wmgt = 'wlan.mgt'
    bssid = _safe(lambda: pkt.wlan.sa.upper())
    # tshark exposes the SSID as colon-separated hex; decode it the same way as
    # the other .cap parsers, defaulting to '' on a non-hex / undecodable value
    # instead of raising "Non-hexadecimal digit found".
    wlan_ssid = _safe(lambda: binascii.unhexlify(
        pkt[wmgt].wlan_ssid.replace(':', '')).decode('ascii'))
    # WPS 2.0 advertises itself through the Version2 extension; read it on its
    # own so a non-hex SSID can no longer suppress the 2.0 flag.
    wps_ext_version2 = _safe(lambda: pkt[wmgt].wps_ext_version2)
    fields = {
        'wlan_ssid': wlan_ssid,
        'wps_version': '2.0' if '20' in (wps_ext_version2 or '') else '1.0',
        'wps_device_name': _safe(lambda: pkt[wmgt].wps_device_name),
        'wps_model_name': _safe(lambda: pkt[wmgt].wps_model_name),
        'wps_model_number': _safe(lambda: pkt[wmgt].wps_model_number),
        'wps_config_methods': _safe(lambda: pkt[wmgt].wps_config_methods),
        'wps_config_methods_keypad': _safe(
            lambda: pkt[wmgt].wps_config_methods_keypad),
    }
    return bssid, fields


def _merge_wps_fields(acc, fields):
    '''Sticky-merge one frame's WPS fields into the per-BSSID accumulator: keep
    the first non-empty value for each attribute (so a later Beacon's reduced
    IE never blanks a Probe Response's device/model name) and let wps_version
    climb to '2.0'. Returns the (new or updated) accumulator dict.'''
    if acc is None:
        return dict(fields)
    for key, value in fields.items():
        if key == 'wps_version':
            if value == '2.0':
                acc[key] = '2.0'
        elif value and not acc.get(key):
            acc[key] = value
    return acc


# Get WPS (Wi-Fi Protected Setup) details from AP Beacons / Probe Responses.
def parse_WPS(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name
        # The rich WPS attributes (device/model name, model number, config
        # methods) only appear in AP-originated Beacons and, in full form,
        # Probe Responses -- never in the client Probe Requests that also carry
        # a WPS IE. The old filter required wlan.da == broadcast, which matched
        # only Beacons (whose reduced WPS IE omits those attributes), so the
        # detail columns were always empty. Select Beacons (0x08) and Probe
        # Responses (0x05) that advertise the AP-only Wi-Fi Protected Setup
        # State; that attribute is absent from client Probe Requests, so they
        # are excluded and no client device lands in the AP table.
        cap = pyshark.FileCapture(
            file, display_filter="wps.wifi_protected_setup_state && "
            "(wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05)")
        # cap.set_debug()

        # A WPS-enabled AP re-advertises the same details in every Beacon and
        # Probe Response, so collapse them to one merged row per BSSID and run
        # insertWPS (which ensures the AP row and updates its WPS columns) once
        # per AP instead of once per frame.
        wps_by_bssid = {}
        for pkt in cap:
            bssid, fields = _wps_fields_for_pkt(pkt)
            if not bssid:
                continue
            wps_by_bssid[bssid] = _merge_wps_fields(
                wps_by_bssid.get(bssid), fields)

        for bssid, fields in wps_by_bssid.items():
            if verbose:
                print('==============================')
                print(bssid, fields['wps_version'])
            errors += database_utils.insertWPS(
                cursor, verbose,
                database_utils.WPSRow(bssid=bssid, **fields))

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
def _identity_for_pkt(cursor, verbose, pkt, state):
    '''Process one EAP packet, accumulating (dst, src, identity, method) state.

    Returns (errors, new_state). An EAP Identity request/response (type 1)
    refreshes the addresses (and the identity on code 2); any other EAP type is
    a method that gets stored against the most recent identity.'''
    dst, src, identity, method = state
    # EAP Success (code 3) and Failure (code 4) frames carry no Type field and
    # are not identities. Skip them, otherwise the pkt.eap.type access below
    # raises AttributeError and every such frame is miscounted as an error.
    if pkt.eap.code in ('3', '4'):
        return 0, state
    if pkt.eap.type == '1':  # EAP Identity
        dst = pkt.wlan.da
        src = pkt.wlan.sa
        if pkt.eap.code == '2':
            try:
                identity = pkt.eap.identity
            except Exception as error:
                if verbose:
                    print(error)
                return 1, (dst, src, identity, method)
        return 0, (dst, src, identity, method)
    # Look up the authentication method by its EAP type, falling back to a
    # generic label for unknown types.
    method = EAP_METHOD_TYPES.get(
        pkt.eap.type, "OTHER (UNKNOWN EAP METHOD) - ID: " + pkt.eap.type)
    database_utils.insertIdentity(cursor, verbose, dst, src, identity, method)
    return 0, (dst, src, identity, method)


def parse_identities(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        cap = pyshark.FileCapture(file, display_filter="eap")
        # cap.set_debug()

        # The information is: Identity, method, method... ,
        # Identity2, method2, method2...
        state = ("", "", "", "")
        for pkt in cap:
            # print(pkt.eapol.field_names)
            try:
                delta, state = _identity_for_pkt(cursor, verbose, pkt, state)
                errors += delta
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


def _eap_md5_packet(pkt):
    '''Return (code, eap_id, src, dst, md5_value) for an EAP-MD5 packet, or
    None when a required field is missing.'''
    try:
        md5_value = pkt.eap.md5_value.replace(':', '')
        if not md5_value:
            return None
        return pkt.eap.code, pkt.eap.id, pkt.wlan.sa, pkt.wlan.da, md5_value
    except Exception:
        return None


def _eap_md5_hashcat(eap_id, challenge, response):
    '''Build the hashcat -m 4800 line response:challenge:id; the EAP id is
    hex-encoded (pyshark exposes eap.id as decimal).'''
    value = _to_int(eap_id)
    eap_id_hex = format(value, '02x') if value is not None else eap_id
    return response + ":" + challenge + ":" + eap_id_hex


def _eap_md5_for_pkt(cursor, verbose, pkt, challenges, file):
    '''Correlate one EAP-MD5 packet against pending challenges. Returns the
    insert error count (0/1). `challenges` maps (ap, client, eap_id) -> challenge
    hex and is updated in place with each Request seen.'''
    parsed = _eap_md5_packet(pkt)
    if parsed is None:
        return 0
    code, eap_id, src, dst, md5_value = parsed
    if code == '1':  # EAP-Request/MD5-Challenge sent by the AP
        challenges[(src, dst, eap_id)] = md5_value
        return 0
    if code != '2':  # only Responses produce a crackable pair
        return 0
    challenge = challenges.get((dst, src, eap_id))
    if not challenge:
        return 0
    hashcat = _eap_md5_hashcat(eap_id, challenge, md5_value)
    if verbose:
        print("EAP-MD5 " + str(src) + " -> " + str(dst) + ": " + hashcat)
    return database_utils.insertEAPMD5(
        cursor, verbose, database_utils.EAPMD5Row(
            bssid=dst, mac=src, identity="", eap_id=eap_id, challenge=challenge,
            response=md5_value, hashcat=hashcat, file=file))


# Get EAP-MD5 challenge/response pairs (crackable with hashcat -m 4800)
def parse_eap_md5(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        cap = pyshark.FileCapture(file, display_filter="eap.type == 4")
        # cap.set_debug()

        # Correlate the Request (challenge, from the AP) with the Response
        # (response, from the client) sharing the same EAP id.
        challenges = {}  # (ap, client, eap_id) -> challenge hex
        for pkt in cap:
            errors += _eap_md5_for_pkt(cursor, verbose, pkt, challenges, file)

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


def _probe_fingerprint_for_pkt(cursor, verbose, pkt, seen, file):
    '''Fingerprint one probe-request frame by its ordered IE tag list. Returns
    insert errors (0/1); `seen` de-duplicates (mac, ssid, fingerprint) keys and
    is mutated in place.'''
    mac = _safe(lambda: pkt.wlan.sa, None)
    if mac is None:
        return 0
    mgt = _safe(lambda: pkt['wlan.mgt'], None)
    if mgt is None:
        return 0
    tags = _all_field_values(mgt, 'wlan_tag_number')
    if not tags:
        return 0
    ie_order = ",".join(str(tag) for tag in tags)
    fingerprint = database_utils.getHash(ie_order.encode())[:32]
    # The probed SSID ('' for broadcast probe requests). The merged Probe row is
    # keyed by (mac, ssid), so the fingerprint attaches to the SSID seen in this
    # frame. Decoded defensively (hex like the other .cap parsers), defaulting
    # to '' on any failure.
    ssid = _safe(lambda: binascii.unhexlify(
        mgt.wlan_ssid.replace(':', '')).decode('ascii'))
    key = (mac.upper(), ssid, fingerprint)
    if key in seen:
        return 0
    seen.add(key)
    if verbose:
        print("Probe fingerprint " + str(mac) + ": " + ie_order)
    return database_utils.insertProbeFingerprint(
        cursor, verbose, mac, ssid, fingerprint, ie_order, file)


# Fingerprint clients by the ordered set of information elements (tags) they
# include in their probe requests; useful to identify device model/OS.
def parse_probe_fingerprint(name, database, verbose):
    errors = 0
    try:
        cursor = database.cursor()
        file = name
        cap = pyshark.FileCapture(
            file, display_filter="wlan.fc.type_subtype == 0x04")
        # cap.set_debug()

        seen = set()
        for pkt in cap:
            errors += _probe_fingerprint_for_pkt(cursor, verbose, pkt, seen,
                                                 file)

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
        database.commit()
        os.remove("test.22000")
        print(".cap hcxpcapngtool done, errors", errors)

    except Exception as error:
        errors += 1
        print("Error in exec_hcxpcapngtool (CAP): ", error)
        print(".cap hcxpcapngtool done, errors", errors)
