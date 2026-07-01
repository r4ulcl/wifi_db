''' Parse AP-advertised details from beacons / probe responses in a .cap file:
RSN/WPA security (AKM suites, ciphers, PMF), 802.11r/k/v + MBSSID/CSA
management capabilities, and recovered hidden (cloaked) SSIDs. '''
# -*- coding: utf-8 -*-
from utils import database_utils
from utils.cap_common import (
    _all_field_values, _suite_name, _dedupe, _to_int, _pkt_bssid_mgt,
    _field_value, _first_field_value, _field_is_set, _mgt_tag_numbers,
    _ssid_from_mgt, _seen_or_invalid)
from utils.cap_runner import run_cap_parse
from utils.wifi_constants import (
    RSN_AKM_SUITES, RSN_ENTERPRISE_AKMS, RSN_CIPHERS,
    TAG_MOBILITY_DOMAIN, TAG_RM_ENABLED_CAP, TAG_MULTIPLE_BSSID,
    TAG_CHANNEL_SWITCH, TAG_EXTENDED_CSA)


def _flag(condition):
    '''Codebase boolean style: 'True'/'False' strings from a truthy value.'''
    return 'True' if condition else 'False'


def _classify_wpa(akm_ints):
    '''Map the numeric AKM set to a WPA version label.'''
    if akm_ints & {8, 9}:  # SAE / FT-SAE -> WPA3
        return "WPA2/WPA3" if akm_ints & {2, 4} else "WPA3"
    if 18 in akm_ints:  # OWE
        return "OWE"
    return "WPA2"


def _rsn_pmf(mgt):
    '''Return (pmf, rsn_capabilities, mfpc, mfpr) from the RSN capabilities
    bitfield: bit 7 (0x80) = MFP Capable, bit 6 (0x40) = MFP Required.'''
    rsn_capabilities = _field_value(mgt, 'wlan_rsn_capabilities')
    cap_int = _to_int(rsn_capabilities, 16) or 0
    mfpc = _flag(cap_int & 0x80)
    mfpr = _flag(cap_int & 0x40)
    pmf = ("Required" if mfpr == 'True'
           else "Capable" if mfpc == 'True'
           else "Disabled")
    return pmf, rsn_capabilities, mfpc, mfpr


# Detect 802.11r/k/v fast-roaming, Multiple BSSID and Channel Switch
# Announcement advertisements from beacons and probe responses, storing the
# flags on the AP row.
def _capability_flags(mgt):
    '''Return the 802.11r/k/v + MBSSID/CSA capability flags for one mgt frame.'''
    tags = _mgt_tag_numbers(mgt)
    return {
        'ft': _flag(TAG_MOBILITY_DOMAIN in tags),
        'rrm': _flag(TAG_RM_ENABLED_CAP in tags),
        'mbssid': _flag(TAG_MULTIPLE_BSSID in tags),
        'csa': _flag(TAG_CHANNEL_SWITCH in tags or TAG_EXTENDED_CSA in tags),
        # 802.11v BSS Transition Management is a bit (b19) of the Extended
        # Capabilities element, not an element of its own.
        'bss_trans': _flag(_field_is_set(
            _field_value(mgt, 'wlan_extcap_b19'))),
        'mdid': _first_field_value(
            mgt, ['wlan_mobility_domain_mdid', 'wlan_ft_mdid']),
        # tshark exposes the Multiple BSSID element's "Max BSSID Indicator"
        # as wlan.multiple_bssid (the wlan_mbssid_* names never existed, so
        # this column was always empty even for MBSSID-advertising APs).
        'max_bssid_indicator': _to_int(_first_field_value(
            mgt, ['wlan_multiple_bssid', 'wlan_mbssid_max_bssid_indicator',
                  'wlan_mbssid_index'])),
        'csa_new_channel': _to_int(_first_field_value(
            mgt, ['wlan_csa_new_channel_number',
                  'wlan_ext_chansw_announce_new_chan'])),
    }


def _insert_one_capability(cursor, verbose, bssid, mgt):
    '''Store fast-roaming / MBSSID / CSA capabilities for one AP if any are
    advertised. Returns the number of insert errors (0/1).'''
    f = _capability_flags(mgt)
    if not any(f[k] == 'True'
               for k in ('ft', 'rrm', 'bss_trans', 'mbssid', 'csa')):
        return 0
    if verbose:
        print("Capabilities for AP " + str(bssid) + ": 11r=" + f['ft'] +
              " 11k=" + f['rrm'] + " 11v=" + f['bss_trans'] + " MBSSID=" +
              f['mbssid'] + " CSA=" + f['csa'])
    return database_utils.insertCapabilities(
        cursor, verbose, database_utils.CapabilitiesRow(
            bssid=bssid, ft_80211r=f['ft'], mobility_domain_id=f['mdid'],
            rrm_80211k=f['rrm'], bss_transition_80211v=f['bss_trans'],
            mbssid=f['mbssid'], max_bssid_indicator=f['max_bssid_indicator'],
            csa=f['csa'], csa_new_channel=f['csa_new_channel']))


def parse_capabilities(name, database, verbose):
    seen = set()

    def per_pkt(cursor, pkt):
        bssid, mgt = _pkt_bssid_mgt(pkt)
        if _seen_or_invalid(bssid, mgt, seen):
            return 0
        errors = _insert_one_capability(cursor, verbose, bssid, mgt)
        seen.add(bssid.upper())
        return errors

    # Beacons (0x08) and probe responses (0x05) carry the capability IEs.
    return run_cap_parse(
        database, name, verbose, "Capabilities",
        "wlan.fc.type_subtype == 0x08 || wlan.fc.type_subtype == 0x05",
        per_pkt)


# Recover cloaked (hidden) SSIDs from probe responses and (re)association
# requests, which carry the real SSID even when the beacon hides it.
def _hidden_ssid_for_pkt(cursor, verbose, pkt, seen):
    '''Recover and store one AP's cloaked SSID. Returns insert errors (0/1);
    `seen` tracks the BSSIDs already handled and is mutated in place.'''
    mgt = pkt['wlan.mgt']
    ssid = _ssid_from_mgt(mgt)
    if not ssid:
        return 0
    bssid = pkt.wlan.bssid
    if bssid is None or bssid.upper() in seen:
        return 0
    seen.add(bssid.upper())
    if verbose:
        print("Revealed SSID for AP " + str(bssid) + ": " + ssid)
    return database_utils.insertHiddenSSID(cursor, verbose, bssid, ssid)


def parse_hidden_ssid(name, database, verbose):
    seen = set()
    # Probe responses (0x05) and (re)association requests (0x00 / 0x02) carrying
    # a non-wildcard SSID element. wlan.bssid is the AP in all of them, so no
    # per-subtype address handling is needed.
    return run_cap_parse(
        database, name, verbose, "Hidden SSID",
        "(wlan.fc.type_subtype == 0x05 || wlan.fc.type_subtype == 0x00 || "
        "wlan.fc.type_subtype == 0x02) && wlan.ssid",
        lambda cursor, pkt: _hidden_ssid_for_pkt(cursor, verbose, pkt, seen))


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
