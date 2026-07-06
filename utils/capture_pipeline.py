''' Capture ingestion pipeline for wifi_db.

Holds the per-run Context plus the file discovery, format dispatch and
insert/parse/mark-processed logic that turns a capture path (file or folder)
into database rows. Split out of wifi_db.py to keep that entry point small;
wifi_db.py re-imports Context and handle_capture from here. '''
# -*- coding: utf-8 -*-
import os
from os import path
from dataclasses import dataclass

from utils import wifi_db_aircrack
from utils import database_utils


@dataclass
class Context:
    '''Invariant per-run configuration threaded through the capture pipeline,
    so the parse functions take just this plus the (varying) capture path.'''
    ouiMap: dict
    database: object
    verbose: bool
    fake_lat: str
    fake_lon: str
    hcxpcapngtool: bool
    tshark: bool
    force: bool


# Substrings that mark a recognised capture file.
_CAPTURE_EXTENSIONS = ('.cap', '.csv', '.kismet.csv', 'kismet.netxml',
                       '.log.csv')


def _is_capture_file(file):
    '''Return True if `file` has one of the recognised capture extensions.'''
    return any(ext in file for ext in _CAPTURE_EXTENSIONS)


def collect_capture_files(dir_capture):
    '''Return the recognised capture files in `dir_capture`, sorted reverse so
    the .cap files are processed last (by name and extension).'''
    files = [file for file in os.listdir(dir_capture)
             if _is_capture_file(file)]
    # Sorted reverse to cap last by name and extension
    files.sort(key=os.path.splitext, reverse=True)
    return files


def process_folder(ctx, capture):
    '''Parse every recognised capture file inside a folder.'''
    print("Parsing folder:", capture)
    dirpath = os.getcwd()
    if os.path.isabs(capture):
        dir_capture = capture
    else:
        dir_capture = dirpath + "/" + capture
    if ctx.verbose:
        print(dir_capture)
        print("current directory is : " + dirpath)

    files = collect_capture_files(dir_capture)
    print(files)

    counter = 0
    # for each file with correct format of folder ...
    for f in files:
        counter += 1
        if counter > 1:
            print()
        print("File: " + str(counter) + " of " + str(len(files)))
        capture_aux = dir_capture + "/" + f
        print(capture_aux)
        process_capture(ctx, capture_aux)


def handle_capture(ctx, capture, source):
    '''Process a single capture path according to the selected source.'''
    if source == "aircrack-ng":
        # If it is a folder...
        if path.isdir(capture):
            process_folder(ctx, capture)
        else:  # it is a file
            print("Parsing file:", capture)
            process_capture(ctx, capture)
    elif source == "kismet":
        print("Parsing Kismet capture")
        # TO DO
    else:
        print("Parsing Wigle capture")
        # TO DO


# (extension substring, parser name). Order matters: most specific first.
CAPTURE_FORMATS = [
    (".cap", "cap"),
    (".kismet.netxml", "netxml"),
    (".kismet.csv", "kismet_csv"),
    (".log.csv", "log_csv"),
    (".csv", "csv"),
]

# Order tried when the given path has no recognised extension (a suffix is
# appended to the path for each one).
FALLBACK_FORMATS = [
    (".kismet.netxml", "netxml"),
    (".kismet.csv", "kismet_csv"),
    (".csv", "csv"),
    (".log.csv", "log_csv"),
    (".cap", "cap"),
]


# Parser name -> how to invoke it (the parsers differ in which Context fields
# they take, so each entry adapts `(ctx, capture)` to that call). Replaces the
# former if/elif ladder in run_parser.
_PARSER_DISPATCH = {
    "cap": lambda ctx, capture: wifi_db_aircrack.parse_cap(
        capture, ctx.database, ctx.verbose, ctx.hcxpcapngtool, ctx.tshark),
    "netxml": lambda ctx, capture: wifi_db_aircrack.parse_netxml(
        ctx.ouiMap, capture, ctx.database, ctx.verbose),
    "kismet_csv": lambda ctx, capture: wifi_db_aircrack.parse_kismet_csv(
        ctx.ouiMap, capture, ctx.database, ctx.verbose),
    "log_csv": lambda ctx, capture: wifi_db_aircrack.parse_log_csv(
        ctx.ouiMap, capture, ctx.database, ctx.verbose, ctx.fake_lat,
        ctx.fake_lon),
    "csv": lambda ctx, capture: wifi_db_aircrack.parse_csv(
        ctx.ouiMap, capture, ctx.database, ctx.verbose),
}


def run_parser(ctx, name, capture):
    '''Dispatch to the parser identified by `name`.'''
    parser = _PARSER_DISPATCH.get(name)
    if parser is not None:
        parser(ctx, capture)


def ingest_capture(ctx, name, capture, announce=False):
    '''Insert, parse and mark a single capture file as processed (skipping it
    if it was already processed and --force was not given).'''
    cursor = ctx.database.cursor()
    if announce:
        print("Parsing file:", capture)
    if (database_utils.checkFileProcessed(cursor, ctx.verbose, capture) == 1
            and not ctx.force):
        print("File", "already processed\n")
        return
    database_utils.insertFile(cursor, ctx.verbose, capture)
    run_parser(ctx, name, capture)
    database_utils.setFileProcessed(cursor, ctx.verbose, capture)


def process_capture(ctx, capture):
    cursor = ctx.database.cursor()

    if (database_utils.checkFileProcessed(cursor, ctx.verbose, capture) == 1
            and not ctx.force):
        print("File", "already processed\n")
        return

    for ext, name in CAPTURE_FORMATS:
        if ext in capture:
            ingest_capture(ctx, name, capture)
            return

    # No recognised extension: try every known format by appending its suffix.
    print("Not format found!")
    if capture.endswith('.'):
        capture = capture[:-1]
    for suffix, name in FALLBACK_FORMATS:
        ingest_capture(ctx, name, capture + suffix, announce=True)
