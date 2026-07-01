''' Shared driver for the pyshark-based .cap parsers.

Every parser used to repeat the same scaffolding: open a FileCapture with a
display filter, loop over the packets, commit, print a ".cap <label> done"
line, and wrap it all in the TShark-crash / generic error handling. This module
factors that out so each parser only supplies its filter and a per-packet
callback. '''
# -*- coding: utf-8 -*-
from utils.cap_common import pyshark


def run_cap_parse(database, name, verbose, label, display_filter, per_pkt,
                  catch_pkt_errors=True, finalize=None):
    '''Drive a pyshark FileCapture with the error handling shared by the .cap
    parsers.

    Opens `name` filtered by `display_filter`, calls `per_pkt(cursor, pkt)` for
    each packet and accumulates its returned error count, optionally runs
    `finalize(cursor)` after the loop, commits, and prints
    ".cap <label> done, errors N". With `catch_pkt_errors` a per-packet
    exception is counted and skipped (as the parsers with an inner try/except
    did); a TShark crash or any other fatal error is reported once. Returns the
    total error count.'''
    errors = 0
    try:
        cursor = database.cursor()
        cap = pyshark.FileCapture(name, display_filter=display_filter)
        # cap.set_debug()
        for pkt in cap:
            if catch_pkt_errors:
                try:
                    errors += per_pkt(cursor, pkt)
                except Exception as error:
                    errors += 1
                    if verbose:
                        print(error)
            else:
                errors += per_pkt(cursor, pkt)
        if finalize is not None:
            errors += finalize(cursor)
        database.commit()
    except pyshark.capture.capture.TSharkCrashException as error:
        errors += 1
        print("Error in " + label + " (CAP), probably PCAP cut in the "
              "middle of a packet: ", error)
    except Exception as error:
        errors += 1
        print("Error in " + label + " (CAP): ", error)
    print(".cap " + label + " done, errors", errors)
    return errors
