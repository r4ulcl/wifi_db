''' Shared plumbing for the pyshark-based .cap parsers.

Owns the asyncio child-watcher shim and the single `import pyshark` (so the
shim always runs first), the tshark-crash unraisablehook, and the generic
pyshark field / suite helpers reused across the .cap parser modules.
'''
# -*- coding: utf-8 -*-
import binascii
import contextlib
import sys

# Install the asyncio child-watcher shim; must run before pyshark is imported
# below (see utils/asyncio_shim.py).
from utils import asyncio_shim
asyncio_shim.install()

import pyshark  # noqa: E402  (imported after the child-watcher shim above)


# pyshark's Capture.__del__ calls close(), which re-raises TSharkCrashException
# when tshark exited non-zero (e.g. a PCAP cut short in the middle of a packet).
# Because that happens during garbage collection, Python prints a noisy
# "Exception ignored in: <function Capture.__del__>" traceback even though every
# call site already catches the crash explicitly. Swallow only that specific
# unraisable and defer everything else to the default hook so real bugs still
# surface.
_default_unraisablehook = sys.unraisablehook


def _quiet_tshark_unraisablehook(unraisable):
    if isinstance(unraisable.exc_value,
                  pyshark.capture.capture.TSharkCrashException):
        return
    _default_unraisablehook(unraisable)


sys.unraisablehook = _quiet_tshark_unraisablehook


def _safe(func, default=""):
    '''Call func() and return its value, or `default` on any error. Keeps the
    per-field certificate extraction terse and resilient to malformed certs.'''
    try:
        return func()
    except Exception:
        return default


def _all_field_values(layer, field_name):
    '''Return every value of a (possibly repeated) pyshark layer field'''
    values = []
    try:
        field = layer.get_field(field_name)
    except Exception:
        field = None
    if field is None:
        return values
    try:
        for sub_field in field.all_fields:
            value = sub_field.get_default_value()
            if value not in (None, ''):
                values.append(value)
    except Exception:
        with contextlib.suppress(Exception):
            values.append(str(field))
    return values


def _suite_name(value, mapping):
    '''Map an RSN suite selector number to its readable name'''
    try:
        key = str(int(value))
    except Exception:
        key = str(value)
    return mapping.get(key, key)


def _dedupe(values):
    '''Deduplicate a list while preserving order'''
    return list(dict.fromkeys(values))


def _to_int(value, base=10):
    '''Parse an int, returning None instead of raising.'''
    try:
        return int(value, base) if isinstance(value, str) else int(value)
    except (TypeError, ValueError):
        return None


def _pkt_bssid_mgt(pkt):
    '''Return (bssid, wlan.mgt layer) for a packet, or (None, None).'''
    try:
        return pkt.wlan.sa, pkt['wlan.mgt']
    except Exception:
        return None, None


def _field_value(layer, field_name):
    '''Return a single field's value (or '') from a pyshark layer, never
    raising.'''
    try:
        field = layer.get_field(field_name)
    except Exception:
        return ''
    if field is None:
        return ''
    try:
        return field.get_default_value() or ''
    except Exception:
        return ''


def _first_field_value(layer, field_names):
    '''Return the first non-empty value among several candidate field names
    (dissector field names vary between tshark versions).'''
    for name in field_names:
        value = _field_value(layer, name)
        if value not in (None, ''):
            return value
    return ''


def _field_is_set(value):
    '''True when a tshark boolean/bit field reads as set.'''
    return str(value).strip().lower() in ('1', 'true', 'yes')


def _mgt_tag_numbers(mgt):
    '''Return the set of 802.11 element (tag) numbers present in a management
    frame, as ints.'''
    values = _all_field_values(mgt, 'wlan_tag_number')
    return {i for i in (_to_int(v) for v in values) if i is not None}


def _ssid_from_mgt(mgt):
    '''Decode the SSID element of a management frame, returning '' for a
    hidden/wildcard SSID (empty or NUL padding). tshark may expose wlan.ssid
    either already decoded or as colon-separated hex bytes.'''
    raw = _field_value(mgt, 'wlan_ssid')
    if not raw:
        return ''
    candidate = raw
    if ':' in raw:
        try:
            candidate = binascii.unhexlify(
                raw.replace(':', '')).decode('utf-8', 'replace')
        except Exception:
            candidate = raw
    return candidate.replace('\x00', '').strip()


def _seen_or_invalid(bssid, mgt, seen):
    '''True when a packet lacks a usable BSSID/mgt or its AP is already seen
    (one row per BSSID is enough; the config is stable per AP).'''
    return bssid is None or mgt is None or bssid.upper() in seen
