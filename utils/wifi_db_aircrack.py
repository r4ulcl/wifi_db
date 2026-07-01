#!/bin/python3
''' Parse Aircrack, Kismet and Wigle output to a SQLite DB.

Compatibility facade. The parsers were split into cohesive submodules to keep
each file small:

* :mod:`utils.wifi_constants` -- EAP/RSN/tag constant tables.
* :mod:`utils.cap_common`     -- asyncio child-watcher shim, the single pyshark
                                 import and the shared pyshark field helpers.
* :mod:`utils.text_parsers`   -- .kismet.netxml / .kismet.csv / airodump .csv /
                                 .log.csv parsers (no pyshark needed).
* :mod:`utils.cert_parsers`   -- X.509 certificate extraction.
* :mod:`utils.beacon_parsers` -- RSN/WPA security, 11r/k/v capabilities and
                                 hidden-SSID recovery from beacons.
* :mod:`utils.cap_parsers`    -- handshakes, MFP, WPS, identities, EAP-MD5,
                                 probe fingerprints, hcxpcapngtool and the
                                 ``parse_cap`` dispatcher.

The public ``parse_*`` entry points are re-exported here so existing callers
(``wifi_db.py`` and the tests) keep importing them from ``wifi_db_aircrack``.
'''
# -*- coding: utf-8 -*-
from utils.text_parsers import (parse_netxml, parse_kismet_csv, parse_csv,
                                parse_log_csv)
from utils.cert_parsers import parse_certificates
from utils.beacon_parsers import (parse_security, parse_capabilities,
                                  parse_hidden_ssid)
from utils.cap_parsers import (
    parse_cap, parse_handshakes, parse_MFP, parse_WPS, parse_identities,
    parse_eap_md5, parse_probe_fingerprint, exec_hcxpcapngtool)

__all__ = [
    "parse_netxml", "parse_kismet_csv", "parse_csv", "parse_log_csv",
    "parse_certificates", "parse_security", "parse_capabilities",
    "parse_hidden_ssid", "parse_cap", "parse_handshakes", "parse_MFP",
    "parse_WPS", "parse_identities", "parse_eap_md5",
    "parse_probe_fingerprint", "exec_hcxpcapngtool",
]
