''' Extract X.509 certificates from enterprise (802.1X) EAP-TLS/PEAP/TTLS
exchanges in a .cap file and store them in the Certificate table. The
per-certificate field extraction lives in cert_fields; this module drives
tshark, attributes each certificate to an AP/client and inserts it. '''
# -*- coding: utf-8 -*-
import binascii
import subprocess  # nosec B404 - only used with a fixed, absolute-path command

from utils import database_utils
# _extract_cert_fields is re-exported here so callers keep referring to it as
# cert_parsers._extract_cert_fields.
from utils.cert_fields import _extract_cert_fields


def _cert_attribution(columns):
    '''Resolve (cert_field, bssid, mac, cert_type) for one tshark line.

    Uses the EAP direction to know whose certificate this is: the authenticator
    (AP) sends EAP-Request packets (code 1) carrying the server certificate,
    while the supplicant sends EAP-Response packets (code 2) carrying the client
    certificate. Either way the BSSID stored is the AP and the MAC the client.'''
    cert_field = columns[0]
    src = columns[1] if len(columns) > 1 else ""
    dst = columns[2] if len(columns) > 2 else ""
    eap_code = columns[3] if len(columns) > 3 else ""
    if eap_code == '2':  # EAP-Response: certificate sent by the client
        return cert_field, dst, src, 'Client'
    if eap_code == '1':  # EAP-Request: certificate sent by the AP/server
        return cert_field, src, dst, 'AP'
    return cert_field, src, dst, 'Unknown'


def _insert_one_cert(cursor, verbose, file, addr, cert_hex, cert_index):
    '''Parse and store a single hex-encoded certificate. Returns errors (0/1).

    `addr` is the (bssid, mac, cert_type) tuple from `_cert_attribution`.'''
    bssid, mac, cert_type = addr
    try:
        der = binascii.unhexlify(cert_hex.replace(':', ''))
        cert = _extract_cert_fields(der, cert_index)
        if verbose:
            print("Certificate (" + cert_type + ") for AP " +
                  str(bssid) + ": " + str(cert.get('subject')))
        return database_utils.insertCertificate(
            cursor, verbose, bssid, mac, cert_type, file, cert)
    except Exception as error:
        if verbose:
            print("parse_certificates cert error: " + str(error))
        return 1


def _insert_cert_line(cursor, verbose, file, columns):
    '''Insert every certificate found on one `tshark -T fields` output line.

    `columns` is the tab-split line: the certificate column (a chain is joined
    with commas by tshark), wlan.sa, wlan.da and eap.code. Returns the number
    of errors hit while parsing/inserting.'''
    cert_field, bssid, mac, cert_type = _cert_attribution(columns)

    # Without an AP address there is nothing to key the certificate on; skip
    # it rather than create a phantom empty-BSSID AP row.
    if not bssid:
        if verbose:
            print("Certificate without wlan addresses, skip")
        return 0

    errors = 0
    addr = (bssid, mac, cert_type)
    # A single Certificate message can carry a full chain (server, CA, ...);
    # tshark joins those certificates with a comma.
    for cert_index, cert_hex in enumerate(cert_field.split(',')):
        cert_hex = cert_hex.strip()
        if cert_hex:
            errors += _insert_one_cert(cursor, verbose, file, addr,
                                       cert_hex, cert_index)
    return errors


# Get X.509 certificates from EAP-TLS/PEAP/TTLS in .cap
def parse_certificates(name, database, verbose):
    try:
        cursor = database.cursor()
        errors = 0
        file = name

        # EAP-TLS certificates are reassembled by tshark across several EAPOL
        # fragments. pyshark's per-packet display-filter iteration does not
        # surface that reassembled `tls.handshake.certificate` field, so it
        # never finds anything. Extract it straight from tshark in `-T fields`
        # mode instead (the approach of the standalone reference tool), pulling
        # the certificate together with the wlan addresses and EAP code needed
        # to attribute it. Fixed absolute-path binary, no shell; the file name
        # is a separate argv element, so it cannot be used for injection.
        completed = subprocess.run(  # nosec B603
            ["/usr/bin/tshark", "-r", file,
             "-Y", "tls.handshake.certificate and eapol",
             "-T", "fields",
             "-e", "tls.handshake.certificate",
             "-e", "wlan.sa", "-e", "wlan.da", "-e", "eap.code"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)

        output = completed.stdout.decode('utf-8', 'replace')
        for raw_line in output.splitlines():
            columns = raw_line.split('\t')
            if not columns[0]:  # no certificate on this line
                continue
            errors += _insert_cert_line(cursor, verbose, file, columns)

        database.commit()
        print(".cap Certificate done, errors", errors)
    except Exception as error:
        errors += 1
        print("Error in parse_certificates (CAP): ", error)
        print(".cap Certificate done, errors", errors)
