''' .cap parsers for the EAP/802.1X exchanges: EAP identities and method types,
EAP-MD5 challenge/response pairs, probe-request fingerprints, and the
hcxpcapngtool 22000-hash extraction. Split out of cap_parsers to keep each
module small. '''
# -*- coding: utf-8 -*-
import binascii
import os
import subprocess  # nosec B404 - only used with a fixed, absolute-path command

from utils import database_utils
from utils.cap_common import _safe, _all_field_values, _to_int
from utils.cap_runner import run_cap_parse
from utils.wifi_constants import EAP_METHOD_TYPES


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
    # The information is: Identity, method, method... ,
    # Identity2, method2, method2...
    state = {'value': ("", "", "", "")}

    def per_pkt(cursor, pkt):
        delta, state['value'] = _identity_for_pkt(
            cursor, verbose, pkt, state['value'])
        return delta

    return run_cap_parse(database, name, verbose, "Identity", "eap", per_pkt)


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
    # Correlate the Request (challenge, from the AP) with the Response
    # (response, from the client) sharing the same EAP id.
    challenges = {}  # (ap, client, eap_id) -> challenge hex
    return run_cap_parse(
        database, name, verbose, "EAP-MD5", "eap.type == 4",
        lambda cursor, pkt: _eap_md5_for_pkt(
            cursor, verbose, pkt, challenges, name),
        catch_pkt_errors=False)


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
    seen = set()
    return run_cap_parse(
        database, name, verbose, "ProbeFingerprint",
        "wlan.fc.type_subtype == 0x04",
        lambda cursor, pkt: _probe_fingerprint_for_pkt(
            cursor, verbose, pkt, seen, name),
        catch_pkt_errors=False)


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
