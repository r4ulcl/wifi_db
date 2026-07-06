#!/bin/python3
'''Human-readable decoders for the raw hex/bitmask columns stored on AP rows.

Several 802.11 attributes are captured as their raw 16-bit hex bitfields
(e.g. wps_config_methods = '0x218c', rsn_capabilities = '0x00c0'). These
helpers turn each bitfield into the comma-separated list of flag names it
encodes, which is stored in the sibling `*_text` column so the database is
readable without a bit-by-bit lookup.'''
# -*- coding: utf-8 -*-


def _to_int(value):
    '''Parse a raw bitfield (e.g. '0x218c', '218c', 8588 or '') into an int.

    Returns None when the value is empty/None or cannot be parsed, so callers
    can store '' for unknown/absent bitfields.'''
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if text == '':
        return None
    try:
        # base 0 honours a leading '0x'; fall back to hex for a bare '218c'.
        return int(text, 0)
    except ValueError:
        try:
            return int(text, 16)
        except ValueError:
            return None


# WPS Config Methods bitmask (Wi-Fi Simple Configuration 2.0, Table 33).
# Order matters: names are emitted in ascending bit order.
WPS_CONFIG_METHODS = (
    (0x0001, 'USBA'),
    (0x0002, 'Ethernet'),
    (0x0004, 'Label'),
    (0x0008, 'Display'),
    (0x0010, 'External NFC Token'),
    (0x0020, 'Integrated NFC Token'),
    (0x0040, 'NFC Interface'),
    (0x0080, 'PushButton'),
    (0x0100, 'Keypad'),
    (0x0200, 'Virtual Push Button'),
    (0x0400, 'Physical Push Button'),
    (0x2000, 'Virtual Display PIN'),
    (0x4000, 'Physical Display PIN'),
)


def decode_wps_config_methods(value):
    '''Decode a WPS Config Methods bitmask into its flag names.

    The Display (0x0008) and PushButton (0x0080) base bits are the parents of
    the Display-PIN (0x2000/0x4000) and Push-Button (0x0200/0x0400) subtypes:
    when a subtype bit is set the base bit is suppressed so the more specific
    name is reported instead. Example: 0x218c -> 'Label, PushButton, Keypad,
    Virtual Display PIN'. Returns '' for an empty/zero/unparseable value.'''
    number = _to_int(value)
    if not number:
        return ''
    methods = []
    for bit, name in WPS_CONFIG_METHODS:
        if not number & bit:
            continue
        if bit == 0x0008 and number & (0x2000 | 0x4000):
            continue  # subsumed by a Display-PIN subtype
        if bit == 0x0080 and number & (0x0200 | 0x0400):
            continue  # subsumed by a Push-Button subtype
        methods.append(name)
    return ', '.join(methods)


# RSN Capabilities single-bit flags (IEEE 802.11, RSN Capabilities field).
RSN_CAPABILITY_FLAGS = (
    (0x0001, 'Pre-Auth'),
    (0x0002, 'No Pairwise'),
    (0x0040, 'MFPR'),
    (0x0080, 'MFPC'),
    (0x0100, 'Joint Multi-band RSNA'),
    (0x0200, 'PeerKey Enabled'),
    (0x0400, 'SPP A-MSDU Capable'),
    (0x0800, 'SPP A-MSDU Required'),
    (0x1000, 'PBAC'),
    (0x2000, 'Extended Key ID'),
)

# 2-bit replay-counter subfields decode to the number of replay counters.
_REPLAY_COUNTERS = {0: 1, 1: 2, 2: 4, 3: 16}


def decode_rsn_capabilities(value):
    '''Decode an RSN Capabilities bitfield into its flag names.

    Lists the named single-bit capabilities in ascending bit order, plus the
    PTKSA/GTKSA replay-counter counts (bits 2-3 and 4-5) when they request more
    than the default single counter. Example: 0x00c0 -> 'MFPR, MFPC'. Returns
    '' for an empty/zero/unparseable value.'''
    number = _to_int(value)
    if number is None:
        return ''
    caps = [name for bit, name in RSN_CAPABILITY_FLAGS if number & bit]
    ptksa = _REPLAY_COUNTERS[(number >> 2) & 0x3]
    gtksa = _REPLAY_COUNTERS[(number >> 4) & 0x3]
    if ptksa > 1:
        caps.append('PTKSA Replay Counters: %d' % ptksa)
    if gtksa > 1:
        caps.append('GTKSA Replay Counters: %d' % gtksa)
    return ', '.join(caps)
