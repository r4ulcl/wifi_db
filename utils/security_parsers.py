''' Parse AP-advertised RSN/WPA security details (AKM suites, ciphers, PMF)
from beacons / probe responses in a .cap file and store them per AP. '''
# -*- coding: utf-8 -*-
from utils import database_utils
from utils.cap_common import (
    _all_field_values, _suite_name, _dedupe, _to_int, _pkt_bssid_mgt,
    _field_value, _seen_or_invalid)
from utils.cap_runner import run_cap_parse
from utils.wifi_constants import (
    RSN_AKM_SUITES, RSN_ENTERPRISE_AKMS, RSN_CIPHERS)


def _flag(condition):
    '''Codebase boolean style: 'True'/'False' strings from a truthy value.

    Duplicated from utils.beacon_parsers to avoid a circular import (that
    module imports parse_security from here).'''
    return 'True' if condition else 'False'


def _rsn_pmf(mgt):
    '''Return (pmf, rsn_capabilities, mfpc, mfpr) from the RSN capabilities
    bitfield: bit 7 (0x80) = MFP Capable, bit 6 (0x40) = MFP Required.

    Duplicated from utils.beacon_parsers to avoid a circular import.'''
    rsn_capabilities = _field_value(mgt, 'wlan_rsn_capabilities')
    cap_int = _to_int(rsn_capabilities, 16) or 0
    mfpc = _flag(cap_int & 0x80)
    mfpr = _flag(cap_int & 0x40)
    pmf = ("Required" if mfpr == 'True'
           else "Capable" if mfpc == 'True'
           else "Disabled")
    return pmf, rsn_capabilities, mfpc, mfpr


def _classify_wpa(akm_ints):
    '''Map the numeric AKM set to a WPA version label.'''
    if akm_ints & {8, 9}:  # SAE / FT-SAE -> WPA3
        return "WPA2/WPA3" if akm_ints & {2, 4} else "WPA3"
    if 18 in akm_ints:  # OWE
        return "OWE"
    return "WPA2"


# Get RSN/WPA security details (AKM suites and ciphers) from beacons and
# probe responses.
def _akm_ints(akm_values):
    '''Parse AKM suite type strings into the set of their integer values.'''
    return {i for i in (_to_int(v) for v in akm_values) if i is not None}


def _security_row(mgt):
    '''Build the RSN/WPA security row for one mgt frame, or None when the frame
    carries no AKM suite (so the caller can skip it without marking it seen).'''
    akm_values = _all_field_values(mgt, 'wlan_rsn_akms_type')
    if not akm_values:
        return None
    pcs_values = _all_field_values(mgt, 'wlan_rsn_pcs_type')
    gcs_values = _all_field_values(mgt, 'wlan_rsn_gcs_type')
    akm_ints = _akm_ints(akm_values)
    pmf, rsn_capabilities, mfpc, mfpr = _rsn_pmf(mgt)
    return {
        'akm_suites': ", ".join(_dedupe(
            [_suite_name(a, RSN_AKM_SUITES) for a in akm_values])),
        'pairwise_ciphers': ", ".join(_dedupe(
            [_suite_name(p, RSN_CIPHERS) for p in pcs_values])),
        'group_cipher': ", ".join(_dedupe(
            [_suite_name(g, RSN_CIPHERS) for g in gcs_values])),
        'wpa_version': _classify_wpa(akm_ints),
        'enterprise': _flag(akm_ints & RSN_ENTERPRISE_AKMS),
        'pmf': pmf,
        'rsn_capabilities': rsn_capabilities,
        'mfpc': mfpc,
        'mfpr': mfpr,
    }


def _insert_one_security(cursor, verbose, file, bssid, mgt):
    '''Store RSN/WPA security (and MFP) for one AP. Returns the insert error
    count, or None when the frame has no AKM suite.'''
    row = _security_row(mgt)
    if row is None:
        return None
    if verbose:
        print("Security for AP " + str(bssid) + ": " + row['wpa_version'] +
              " [" + row['akm_suites'] + "] PMF=" + row['pmf'])
    errors = database_utils.insertSecurity(
        cursor, verbose, database_utils.SecurityRow(
            bssid=bssid, wpa_version=row['wpa_version'],
            akm_suites=row['akm_suites'],
            pairwise_ciphers=row['pairwise_ciphers'],
            group_cipher=row['group_cipher'], enterprise=row['enterprise'],
            pmf=row['pmf'], rsn_capabilities=row['rsn_capabilities'],
            file=file))
    # Beacons are far more common than the association frames parsed by
    # parse_MFP, so also update the AP mfpc/mfpr from here.
    if row['mfpc'] == 'True' or row['mfpr'] == 'True':
        errors += database_utils.insertMFP(
            cursor, verbose, bssid, row['mfpc'], row['mfpr'])
    return errors


def parse_security(name, database, verbose):
    seen = set()

    def per_pkt(cursor, pkt):
        bssid, mgt = _pkt_bssid_mgt(pkt)
        if _seen_or_invalid(bssid, mgt, seen):
            return 0
        result = _insert_one_security(cursor, verbose, name, bssid, mgt)
        if result is None:  # no AKM suite on this frame; try later ones
            return 0
        seen.add(bssid.upper())
        return result

    # Beacons (0x08) and probe responses (0x05) that carry an RSN IE. The
    # per-packet body has no inner try (a bad frame is fatal), so errors are
    # not caught per packet.
    return run_cap_parse(
        database, name, verbose, "Security",
        "(wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05) && "
        "wlan.rsn.akms.type",
        per_pkt, catch_pkt_errors=False)
