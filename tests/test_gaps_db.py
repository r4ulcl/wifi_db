'''Coverage for the database helpers' error handling and verbose branches:
the sqlite3 error paths that only fire on a constraint violation / driver
error (reached here with cursors and connections that raise on demand), the
`if verbose:` logging, and small edge cases (empty SSID, randomized-MAC
parse failure, the post-schema column migration).'''
import os
import sqlite3
import tempfile
import unittest
from unittest import mock

from utils import database_utils, db_inserts, db_files, db_maintenance
from utils.db_rows import APRow, ClientRow


def _mem_db():
    database = database_utils.connectDatabase(':memory:', False)
    database_utils.createDatabase(database, False)
    return database


class RaisingCursor:
    '''A cursor stand-in whose execute() always raises the given exception,
    driving the insert helpers' sqlite error branches.'''
    def __init__(self, exc):
        self._exc = exc

    def execute(self, *_args, **_kwargs):
        raise self._exc

    def fetchall(self):
        return []

    def fetchone(self):
        return None


class RaisingDB:
    '''A database stand-in handing out a RaisingCursor.'''
    def __init__(self, exc):
        self._exc = exc

    def cursor(self):
        return RaisingCursor(self._exc)

    def commit(self):
        pass


class ScriptRaisingDB:
    '''A database whose executescript raises (createDatabase/createViews).'''
    def executescript(self, _script):
        raise sqlite3.IntegrityError("schema clash")

    def commit(self):
        pass


def _integrity():
    return sqlite3.IntegrityError("UNIQUE constraint failed")


def _operational():
    return sqlite3.OperationalError("no such table")


class DBGapBase(unittest.TestCase):
    def setUp(self):
        self.database = _mem_db()
        self.cursor = self.database.cursor()
        handle = tempfile.NamedTemporaryFile(delete=False)
        handle.write(b'capture')
        handle.close()
        self.file = handle.name

    def tearDown(self):
        self.database.close()
        if os.path.exists(self.file):
            os.remove(self.file)


# --------------------------------------------------------------------------
# db_files
# --------------------------------------------------------------------------
class TestDbFiles(DBGapBase):
    def test_insert_file_verbose(self):
        self.assertEqual(db_files.insertFile(self.cursor, True, self.file), 0)

    def test_insert_file_integrity_error(self):
        self.assertEqual(
            db_files.insertFile(RaisingCursor(_integrity()), False, self.file),
            1)

    def test_set_file_processed_verbose_and_error(self):
        self.assertEqual(
            db_files.setFileProcessed(self.cursor, True, self.file), 0)
        self.assertEqual(
            db_files.setFileProcessed(RaisingCursor(_integrity()), False,
                                      self.file), 1)

    def test_check_file_processed_missing_verbose(self):
        self.assertEqual(
            db_files.checkFileProcessed(self.cursor, True, "/no/such/file"), 0)

    def test_check_file_processed_integrity_error(self):
        self.assertEqual(
            db_files.checkFileProcessed(RaisingCursor(_integrity()), False,
                                        self.file), 2)


# --------------------------------------------------------------------------
# db_inserts
# --------------------------------------------------------------------------
def _ap_row(bssid="AA:BB:CC:00:00:01", first=0):
    return APRow(bssid=bssid, essid="AP", manuf="M", channel="6",
                 freqmhz="2437", carrier="", encryption="WPA2",
                 packets_total="1", lat="0.0", lon="0.0", cloaked='False',
                 mfpc='False', mfpr='False', firstTimeSeen=first)


def _client_row(mac="55:44:33:22:11:00", first=0):
    return ClientRow(mac=mac, ssid="", manuf="M", client_type="1",
                     packets_total="1", device="Misc", firstTimeSeen=first)


class TestDbInserts(DBGapBase):
    def test_log_and_exec_verbose(self):
        db_inserts._log(True, "hello")
        db_inserts._exec(self.cursor, True, "SELECT 1", ())

    def test_randomized_mac_parse_failure(self):
        self.assertEqual(db_inserts.isRandomizedMAC(None), 'False')
        self.assertEqual(db_inserts.isRandomizedMAC(''), 'False')

    def test_insert_ap_generic_error(self):
        self.assertEqual(
            db_inserts.insertAP(RaisingCursor(_operational()), False,
                                _ap_row()), 1)

    def test_update_ap_integrity_error(self):
        # First INSERT raises IntegrityError (-> _updateAP), whose own UPDATEs
        # then raise IntegrityError too. firstTimeSeen != 0 exercises the
        # firstTimeSeen UPDATE before the loop.
        self.assertEqual(
            db_inserts.insertAP(RaisingCursor(_integrity()), True,
                                _ap_row(first="2024-01-01 00:00:00")), 0)

    def test_insert_clients_inner_update_integrity_error(self):
        self.assertEqual(
            db_inserts.insertClients(RaisingCursor(_integrity()), True,
                                     _client_row(first="2024-01-01 00:00:00")),
            1)

    def test_insert_clients_generic_error(self):
        self.assertEqual(
            db_inserts.insertClients(RaisingCursor(_operational()), False,
                                     _client_row()), 1)


# --------------------------------------------------------------------------
# db_maintenance
# --------------------------------------------------------------------------
class TestDbMaintenance(DBGapBase):
    def test_obfuscate_integrity_error(self):
        self.assertEqual(
            db_maintenance.obfuscateDB(RaisingDB(_integrity()), True), 1)

    def test_clear_whitelist_integrity_error(self):
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False,
                                         encoding='utf-8') as handle:
            handle.write("11:22:33:44:55:66\n")
            whitelist = handle.name
        try:
            # Must not raise: the per-mac IntegrityError is caught and logged.
            db_maintenance.clearWhitelist(RaisingDB(_integrity()), True,
                                          whitelist)
        finally:
            os.remove(whitelist)


# --------------------------------------------------------------------------
# database_utils
# --------------------------------------------------------------------------
class TestDatabaseUtils(DBGapBase):
    def test_connect_database_fatal_exit(self):
        with mock.patch.object(database_utils.sqlite3, 'connect',
                               side_effect=sqlite3.Error("cannot open")):
            with self.assertRaises(SystemExit):
                database_utils.connectDatabase("x.db", False)

    def test_migrate_columns_adds_and_logs(self):
        raw = sqlite3.connect(":memory:")
        raw.execute("CREATE TABLE AP (bssid TEXT)")
        database_utils._migrateColumns(raw, True)
        columns = [row[1] for row in
                   raw.execute("PRAGMA table_info(AP)").fetchall()]
        self.assertIn("wps_config_methods_text", columns)
        self.assertIn("rsn_capabilities_text", columns)
        raw.close()

    def test_create_database_integrity_error(self):
        # Must not raise: executescript's IntegrityError is caught.
        database_utils.createDatabase(ScriptRaisingDB(), False)

    def test_create_views_integrity_error(self):
        database_utils.createViews(ScriptRaisingDB(), False)

    def test_insert_hidden_ssid_empty(self):
        self.assertEqual(
            database_utils.insertHiddenSSID(self.cursor, False,
                                            "AA:BB:CC:00:00:09", ""), 0)

    def test_insert_identity_verbose(self):
        self.assertEqual(
            database_utils.insertIdentity(
                self.cursor, True, "AA:BB:CC:00:00:0A", "55:44:33:22:11:0A",
                "user@realm.example", "EAP-TLS"), 0)

    def test_set_hashcat_verbose(self):
        self.assertEqual(
            database_utils.setHashcat(
                self.cursor, True, "AA:BB:CC:00:00:0B", "55:44:33:22:11:0B",
                self.file, " WPA*02*hash "), 0)

    def test_set_hashcat_integrity_error(self):
        # A cursor that fails the final Handshake INSERT; the earlier
        # constraint inserts are no-ops.
        class _HandshakeFails:
            def execute(self, sql, *_a, **_k):
                if 'handshake' in sql.lower():
                    raise _integrity()

            def fetchall(self):
                return []

        self.assertEqual(
            database_utils.setHashcat(_HandshakeFails(), False,
                                      "AA:BB:CC:00:00:0C", "55:44:33:22:11:0C",
                                      self.file, "hash"), 1)


if __name__ == '__main__':
    unittest.main()
