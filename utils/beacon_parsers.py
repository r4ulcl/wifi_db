''' Parse AP-advertised details from beacons / probe responses in a .cap file:
RSN/WPA security (AKM suites, ciphers, PMF), 802.11r/k/v + MBSSID/CSA
management capabilities, and recovered hidden (cloaked) SSIDs. '''
# -*- coding: utf-8 -*-
from utils import database_utils
from utils.cap_common import (
    _to_int, _pkt_bssid_mgt, _field_value, _first_field_value,
    _field_is_set, _mgt_tag_numbers, _ssid_from_mgt, _seen_or_invalid)
from utils.cap_runner import run_cap_parse
from utils.wifi_constants import (
    TAG_MOBILITY_DOMAIN, TAG_RM_ENABLED_CAP, TAG_MULTIPLE_BSSID,
    TAG_CHANNEL_SWITCH, TAG_EXTENDED_CSA)


def _flag(condition):
    '''Codebase boolean style: 'True'/'False' strings from a truthy value.'''
    return 'True' if condition else 'False'


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


# RSN/WPA security parsing lives in utils.security_parsers to keep this file's
# total cyclomatic complexity down. Re-imported here so existing callers (and
# tests) can still import these names from utils.beacon_parsers.
from utils.security_parsers import (  # noqa: E402,F401
    parse_security, _classify_wpa, _akm_ints, _security_row,
    _insert_one_security)
