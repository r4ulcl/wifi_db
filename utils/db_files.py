#!/bin/python3
''' Capture-file tracking and hashing helpers for the SQLite DB.

These functions manage the Files table (recording processed capture files and
their SHA-256 hashes) and the shared hashing helper used across the inserts.
They were split out of database_utils.py; that module re-exports them so callers
keep using `database_utils.<name>`.
'''
# -*- coding: utf-8 -*-
import sqlite3
import os
import datetime
import hashlib


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
