''' Parse .cap/.pcap capture files into the SQLite DB: EAPOL handshakes, MFP and
WPS. `parse_cap` dispatches to every .cap parser (including the EAP, certificate,
security, capability and hidden-SSID parsers that live in their own modules). '''
# -*- coding: utf-8 -*-
import binascii

from utils import database_utils
from utils.cap_common import _safe
from utils.cap_runner import run_cap_parse
from utils.cert_parsers import parse_certificates
from utils.beacon_parsers import parse_capabilities, parse_hidden_ssid
from utils.security_parsers import parse_security
from utils.eap_parsers import (parse_identities, parse_eap_md5,
                               parse_probe_fingerprint, exec_hcxpcapngtool)


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
    state = {'prev': ("", "", "")}

    def per_pkt(cursor, pkt):
        delta, state['prev'] = _handshake_for_pkt(
            cursor, verbose, pkt, state['prev'], name)
        return delta

    return run_cap_parse(database, name, verbose, "Handshake", "eapol",
                         per_pkt)


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
    # Filter only with mfpr or mfpc enable, on Beacons (0x0008).
    return run_cap_parse(
        database, name, verbose, "MFP",
        "((wlan.rsn.capabilities.mfpr == 1)||"
        "(wlan.rsn.capabilities.mfpc == 1))&&"
        "(wlan.fc.type_subtype == 0x0008)",
        lambda cursor, pkt: _insert_one_mfp(cursor, verbose, pkt))


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
    # A WPS-enabled AP re-advertises the same details in every Beacon and Probe
    # Response, so collapse them to one merged row per BSSID and run insertWPS
    # once per AP (in finalize) instead of once per frame.
    #
    # The rich WPS attributes (device/model name, model number, config methods)
    # only appear in AP-originated Beacons (0x08) and, in full form, Probe
    # Responses (0x05) that advertise the AP-only Wi-Fi Protected Setup State;
    # that attribute is absent from client Probe Requests, so they are excluded
    # and no client device lands in the AP table.
    wps_by_bssid = {}

    def per_pkt(_cursor, pkt):
        bssid, fields = _wps_fields_for_pkt(pkt)
        if bssid:
            wps_by_bssid[bssid] = _merge_wps_fields(
                wps_by_bssid.get(bssid), fields)
        return 0

    def finalize(cursor):
        errors = 0
        for bssid, fields in wps_by_bssid.items():
            if verbose:
                print('==============================')
                print(bssid, fields['wps_version'])
            errors += database_utils.insertWPS(
                cursor, verbose,
                database_utils.WPSRow(bssid=bssid, **fields))
        return errors

    return run_cap_parse(
        database, name, verbose, "WPS",
        "wps.wifi_protected_setup_state && "
        "(wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05)",
        per_pkt, catch_pkt_errors=False, finalize=finalize)
