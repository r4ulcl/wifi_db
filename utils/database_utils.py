#!/bin/python3
''' Utils to SQLite DB '''
# -*- coding: utf-8 -*-
import sqlite3
import os
import secrets
import string
import datetime
import hashlib
# Row dataclasses (db_rows) and the wide insert helpers (db_inserts) were split
# out of this module; re-export them here so callers keep using
# `database_utils.<name>`. `__all__` lists the re-exports so they are not
# flagged as unused imports.
from utils.db_rows import (APRow, ClientRow, WPSRow, SecurityRow,
                           CapabilitiesRow, EAPMD5Row, SeenClientRow, SeenAPRow)
from utils.db_inserts import (
    isRandomizedMAC, insertAP, insertAPConstraint, insertClientConstraint,
    insertClients, insertWPS, insertSecurity, insertCapabilities,
    insertEAPMD5, insertSeenClient, insertSeenAP)

__all__ = [
    # re-exported from db_rows
    'APRow', 'ClientRow', 'WPSRow', 'SecurityRow', 'CapabilitiesRow',
    'EAPMD5Row', 'SeenClientRow', 'SeenAPRow',
    # re-exported from db_inserts
    'isRandomizedMAC', 'insertAP', 'insertAPConstraint',
    'insertClientConstraint', 'insertClients', 'insertWPS', 'insertSecurity',
    'insertCapabilities', 'insertEAPMD5', 'insertSeenClient', 'insertSeenAP',
    # defined in this module
    'connectDatabase', 'createDatabase', 'createViews', 'insertProbe',
    'insertCertificate', 'insertHiddenSSID', 'insertConnected', 'insertMFP',
    'insertHandshake', 'insertIdentity', 'insertProbeFingerprint',
    'setHashcat', 'insertFile', 'getHash', 'setFileProcessed',
    'checkFileProcessed', 'obfuscateDB', 'clearWhitelist',
]


def connectDatabase(name, verbose):
    '''Function to connect to the database'''
    try:
        database = sqlite3.connect(name)
        database.text_factory = str
        database.execute("PRAGMA foreign_keys = 1")
        if verbose:
            print("DB connected OK")
        return database
    except Exception as error:
        print("FATAL ERROR createDatabase: " + str(error))
        exit()


def createDatabase(database, verbose):
    '''Function to create the tables in the database'''
    script_path = os.path.dirname(os.path.abspath(__file__))
    path = script_path + '/wifi_db_database.sql'
    with open(path, 'r', encoding='utf-8') as db_file:
        schema = db_file.read()
    try:
        # The schema is a trusted, static .sql file shipped with the project.
        # executescript runs the whole file in one call, so no per-statement
        # string building is needed.
        database.executescript(schema)
        database.commit()
        if verbose:
            print("Database created")
    except sqlite3.IntegrityError as error:
        print("createDatabase" + str(error))


def createViews(database, verbose):
    '''Function to create the Views in the database'''
    script_path = os.path.dirname(os.path.abspath(__file__))
    path = script_path + '/view.sql'
    with open(path, 'r', encoding='utf-8') as views_file:
        views = views_file.read()
    try:
        # view.sql is a trusted, static file shipped with the project.
        database.executescript(views)
        database.commit()
        if verbose:
            print("Views created")
    except sqlite3.IntegrityError as error:
        print("createViews" + str(error))


def insertProbe(cursor, verbose, bssid, essid, time):
    ''''''
    try:
        # Explicit column list: Probe also carries the merged probe-request
        # fingerprint columns (filled by insertProbeFingerprint), which this
        # SSID-only insert leaves NULL.
        cursor.execute('''INSERT INTO Probe (mac, ssid, time) VALUES(?,?,?)''',
                       (bssid.upper(), essid, time))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertProbe" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertProbe Error " + str(error))
        return int(1)


def insertCertificate(cursor, verbose, bssid, mac, cert_type, file, cert):
    '''Function to insert an X.509 certificate seen for an AP BSSID.

    `bssid` is always the access point and `mac` the client, regardless of
    which side sent the certificate. `cert_type` tells whose certificate it
    is ('AP', 'Client' or 'Unknown'). `cert` is a dict with the parsed
    certificate fields (see wifi_db_aircrack._extract_cert_fields).'''
    try:
        # Insert AP CONSTRAINT (create the AP row if it does not exist yet)
        insertAPConstraint(cursor, verbose, bssid)

        mac = mac.upper() if mac else mac

        cursor.execute('''INSERT INTO Certificate VALUES
                          (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,
                           ?,?,?,?,?,?,?,?,?,?)''',
                       (bssid.upper(), mac, cert_type, file,
                        cert.get('cert_index'),
                        cert.get('version'),
                        cert.get('serial_number'),
                        cert.get('signature_algorithm'),
                        cert.get('issuer'),
                        cert.get('subject'),
                        cert.get('not_before'),
                        cert.get('not_after'),
                        cert.get('subject_cn'),
                        cert.get('subject_o'),
                        cert.get('subject_ou'),
                        cert.get('issuer_cn'),
                        cert.get('issuer_o'),
                        cert.get('issuer_ou'),
                        cert.get('public_key_algorithm'),
                        cert.get('public_key_size'),
                        cert.get('public_key_curve'),
                        cert.get('public_key_exponent'),
                        cert.get('subject_alt_names'),
                        cert.get('key_usage'),
                        cert.get('ext_key_usage'),
                        cert.get('is_ca'),
                        cert.get('path_length'),
                        cert.get('self_signed'),
                        cert.get('authority_key_id'),
                        cert.get('subject_key_id'),
                        cert.get('crl_urls'),
                        cert.get('ocsp_urls'),
                        cert.get('validity_days'),
                        cert.get('sha1_fingerprint'),
                        cert.get('sha256_fingerprint')))
        return int(0)
    except sqlite3.IntegrityError as error:
        # Certificate already stored for this BSSID (same fingerprint)
        if verbose:
            print("insertCertificate " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertCertificate Error " + str(error))
        return int(1)


def insertHiddenSSID(cursor, verbose, bssid, ssid):
    '''Recover a cloaked SSID seen in a probe response or (re)association
    request and store it on the AP row. The SSID is only written when the AP
    row has no SSID yet (empty/NULL), so a real beacon SSID is never
    overwritten, and `ssid_revealed` records that the name was learned from a
    non-beacon frame.'''
    try:
        if not ssid:
            return int(0)
        # Ensure the AP row exists, then fill the SSID only if still unknown.
        insertAPConstraint(cursor, verbose, bssid)

        cursor.execute(
            '''UPDATE AP SET ssid = (?), ssid_revealed = 'True'
               WHERE bssid = (?) AND (ssid IS NULL OR ssid = '')''',
            (ssid, bssid.upper()))
        return int(0)
    except sqlite3.IntegrityError as error:
        if verbose:
            print("insertHiddenSSID " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertHiddenSSID Error " + str(error))
        return int(1)


def insertConnected(cursor, verbose, bssid, mac):
    ''''''
    try:
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO connected VALUES(?,?)''',
            (bssid.upper(), mac.upper()))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertConnected" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertConnected Error " + str(error))
        return int(1)


def insertMFP(cursor, verbose, bssid, mfpc, mfpr):
    ''''''
    try:
        # Ensure the AP row exists, carrying through the MFP flags.
        insertAP(cursor, verbose, APRow(
            bssid=bssid, essid="", manuf="", channel="", freqmhz="",
            carrier="", encryption="", packets_total="", lat="0.0", lon="0.0",
            cloaked='False', mfpc=mfpc, mfpr=mfpr, firstTimeSeen=0))

        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertMFP" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertMFP Error " + str(error))

        return int(1)


def insertHandshake(cursor, verbose, bssid, mac, file):
    ''''''
    try:
        error = 0
        # Insert file
        error += insertFile(cursor, verbose, file)

        # Get file hash MD5
        with open(file, 'rb') as file_handle:
            file_hash = getHash(file_handle.read())

        # insertHandshake Client and AP CONSTRAINT
        error += insertClientConstraint(cursor, verbose, mac)
        error += insertAPConstraint(cursor, verbose, bssid)

        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO handshake VALUES(?,?,?,?,?)''',
            (bssid.upper(), mac.upper(), file, file_hash, ""))
        return int(error)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertHandshake" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertHandshake Error " + str(error))
        return int(1)


def insertIdentity(cursor, verbose, bssid, mac, identity, method):
    ''''''
    error = 0
    try:
        # Insert Identity Client and AP CONSTRAINT
        error += insertClientConstraint(cursor, verbose, mac)
        error += insertAPConstraint(cursor, verbose, bssid)

        # The realm is the part after '@' in a user@realm identity (the
        # anonymous outer identity often carries only the realm).
        realm = ""
        if identity and '@' in identity:
            realm = identity.rsplit('@', 1)[1]

        if verbose:
            print('output ' + bssid.upper(), mac.upper(), identity, method,
                  realm)
        # print(row[5].replace(' ', ''))
        cursor.execute(
            '''INSERT INTO identity VALUES(?,?,?,?,?)''',
            (bssid.upper(), mac.upper(), identity, method, realm))
        return int(0)
    except sqlite3.IntegrityError as error:
        # errors += 1
        if verbose:
            print("insertIdentity" + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertIdentity Error " + str(error))
        return int(1)


def insertProbeFingerprint(cursor, verbose, mac, ssid, fingerprint, ie_order,
                           file):
    '''Store a probe-request fingerprint (ordered list of information element
    IDs and its hash) for device identification.

    The fingerprint is a probe-request attribute, so it lives on the Probe row
    for the (mac, ssid) that was probed: the Client row is ensured to exist,
    then the fingerprint columns are merged into the matching Probe row
    (creating it if the SSID was not already seen). `ssid` is '' for broadcast
    probe requests.'''
    try:
        # Insert Client CONSTRAINT
        insertClientConstraint(cursor, verbose, mac)

        cursor.execute('''INSERT INTO Probe
                          (mac, ssid, time, fingerprint, ie_order, file)
                          VALUES (?,?,?,?,?,?)
                          ON CONFLICT(mac, ssid) DO UPDATE SET
                              fingerprint = excluded.fingerprint,
                              ie_order = excluded.ie_order,
                              file = excluded.file''',
                       (mac.upper(), ssid, 0, fingerprint, ie_order, file))
        return int(0)
    except sqlite3.IntegrityError as error:
        if verbose:
            print("insertProbeFingerprint " + str(error))
        return int(0)
    except sqlite3.Error as error:
        if verbose:
            print("insertProbeFingerprint Error " + str(error))
        return int(1)


def setHashcat(cursor, verbose, bssid, mac, file, hashcat):
    try:
        # Remove enter at the end
        hashcat = hashcat.strip()

        # Ensure the rows referenced by the Handshake foreign keys exist
        # before inserting. hcxpcapngtool --all extracts handshakes/PMKIDs
        # that the strict tshark 4-way parser may have skipped, so the AP,
        # Client and File rows are not guaranteed to already be present.
        # Without this the INSERT below fails with "FOREIGN KEY constraint
        # failed" and the hashcat hash is silently dropped, leaving the
        # handshake stored with an empty hash.
        insertFile(cursor, verbose, file)
        insertClientConstraint(cursor, verbose, mac)
        insertAPConstraint(cursor, verbose, bssid)

        with open(file, 'rb') as file_handle:
            file_hash = getHash(file_handle.read())
        if verbose:
            print("HASH: ", file_hash)
        cursor.execute('''INSERT OR REPLACE INTO Handshake
                          VALUES(?,?,?,?,?)''',
                       (bssid.upper(), mac.upper(), file, file_hash, hashcat))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("setHashcat" + str(error))
        return int(1)


def insertFile(cursor, verbose, file):
    try:
        # Get MD5
        with open(file, 'rb') as file_handle:
            file_hash = getHash(file_handle.read())
        if verbose:
            print("HASH: ", file_hash)
        # INSERT OR IGNORE, not OR REPLACE: the Files (file,hashSHA) row is the
        # parent of Handshake via an ON DELETE CASCADE foreign key. REPLACE
        # deletes the existing parent row (firing the cascade and wiping every
        # Handshake for this file) before re-inserting it, so callers that just
        # need to guarantee the row exists (insertHandshake, setHashcat during
        # the hcxpcapngtool pass) would silently destroy already-parsed
        # handshakes. IGNORE leaves the existing row untouched.
        # Store the timestamp as a formatted string instead of a datetime
        # object. Passing a datetime to sqlite3 relies on the default adapter,
        # deprecated since Python 3.12 (and slated for removal), which emitted
        # a DeprecationWarning on every insert. The "%Y-%m-%d %H:%M:%S" format
        # matches the firstTimeSeen timestamps stored elsewhere.
        cursor.execute('''INSERT OR IGNORE INTO Files VALUES(?,?,?,?)''',
                       (file, "False", file_hash,
                        datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("insertFile" + str(error))
        return int(1)


def getHash(file):
    return hashlib.sha256(file).hexdigest()


def setFileProcessed(cursor, verbose, file):
    try:
        if verbose:
            print("setFileProcessed", file)
        cursor.execute('''UPDATE Files SET processed = (?) where file = ?''',
                       ("True", file))
        return int(0)
    except sqlite3.IntegrityError as error:
        print("setFileProcessed" + str(error))
        return int(1)


def checkFileProcessed(cursor, verbose, file):
    if not os.path.exists(file):
        if verbose:
            print("File", file, "does not exist")
        return int(0)

    with open(file, 'rb') as file_handle:
        file_hash = getHash(file_handle.read())

    try:
        cursor.execute('''SELECT file FROM Files WHERE hashSHA = (?)
                          AND processed = "True"''', (file_hash,))

        output = cursor.fetchall()
        if len(output) > 0:
            return int(1)

        return int(0)
    except sqlite3.IntegrityError as error:
        print("checkFileProcessed" + str(error))
        return int(2)


# obfuscated the database AA:BB:CC:XX:XX:XX-DEFG,
# needs database and not cursos to commit
def _obfuscateColumn(database, verbose, label, select_sql, update_sql,
                     uppercase):
    '''Replace every address in one table column with AA:BB:CC:XX:XX:XX-<rand>.

    `select_sql`/`update_sql` are fixed literals supplied by the caller (no
    identifier interpolation, so the statements stay injection-safe). The 8
    random lowercase letters keep the obfuscated values unique.'''
    try:
        if verbose:
            print("obfuscated " + label)
        cursor = database.cursor()
        cursor.execute(select_sql)
        for row in cursor.fetchall():
            aux = ''.join(secrets.choice(string.ascii_lowercase)
                          for _ in range(8))
            new = row[0][0:9] + 'XX:XX:XX' + '-' + aux
            old = row[0]
            if uppercase:
                new, old = new.upper(), old.upper()
            cursor.execute(update_sql, (new, old))
        database.commit()
        return int(0)
    except sqlite3.IntegrityError as error:
        print("obfuscateDB" + str(error))
        return int(1)


def obfuscateDB(database, verbose):
    '''Obfuscate AP BSSIDs and Client MACs so the DB can be shared safely.'''
    _obfuscateColumn(database, verbose, "APs",
                     "SELECT bssid from AP; ",
                     "UPDATE AP set bssid = (?) where bssid = ?", False)
    return _obfuscateColumn(database, verbose, "clients",
                            "SELECT mac from Client; ",
                            "UPDATE Client set mac = (?) where mac = ?", True)

# exists = '11:22:33:44:55:77' in whitelist


def clearWhitelist(database, verbose, whitelist):
    with open(whitelist, encoding='utf-8') as f:
        whitelist = f.read().splitlines()
    cursor = database.cursor()
    for mac in whitelist:
        mac = mac.upper()
        if verbose:
            print("clearWhitelist", mac)
        try:
            cursor.execute(
                "DELETE from Handshake where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Identity where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from SeenAP where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from SeenClient where mac = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Probe where mac = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Connected where bssid = (?)  OR mac = (?) ",
                (mac.upper(), mac.upper(),))
            cursor.execute(
                "DELETE from AP where bssid = (?) ", (mac.upper(),))
            cursor.execute(
                "DELETE from Client where mac = (?) ", (mac.upper(),))

            database.commit()

        except sqlite3.IntegrityError as error:
            print("clearWhitelist" + str(error))
    print("CLEARED WHITELIST MACS")
