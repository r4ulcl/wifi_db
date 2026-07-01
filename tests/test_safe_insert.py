import sqlite3
import unittest

from utils.db_inserts import safe_insert


class TestSafeInsert(unittest.TestCase):
    '''The shared safe_insert decorator's sqlite error handling.'''

    def test_passthrough_return_value(self):
        @safe_insert
        def ok(cursor, verbose, value):
            return value
        self.assertEqual(ok(None, False, 7), 7)

    def test_integrity_error_returns_0(self):
        # A duplicate row (IntegrityError) is a no-op success -> 0.
        @safe_insert
        def dup(cursor, verbose):
            raise sqlite3.IntegrityError("UNIQUE constraint failed")
        self.assertEqual(dup(None, False), 0)

    def test_other_sqlite_error_returns_1(self):
        # Any other sqlite3.Error is a failure -> 1.
        @safe_insert
        def bad(cursor, verbose):
            raise sqlite3.OperationalError("no such table")
        self.assertEqual(bad(None, False), 1)

    def test_non_sqlite_exception_propagates(self):
        # Non-sqlite bugs must not be swallowed.
        @safe_insert
        def boom(cursor, verbose):
            raise ValueError("real bug")
        with self.assertRaises(ValueError):
            boom(None, False)


if __name__ == '__main__':
    unittest.main()
