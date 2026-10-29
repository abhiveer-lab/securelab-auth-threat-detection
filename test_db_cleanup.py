
import sqlite3
import unittest
from unittest.mock import MagicMock, patch

from app import log_attempt


class TestDatabaseCleanup(unittest.TestCase):

    @patch("app.sqlite3.connect")
    def test_connection_closes_when_insert_fails(self, mock_connect):
        mock_con = MagicMock()
        mock_connect.return_value = mock_con

        mock_con.cursor.return_value.execute.side_effect = (
            sqlite3.OperationalError("Simulated database failure")
        )

        with self.assertRaises(sqlite3.OperationalError):
            log_attempt("testuser", "192.0.2.99", "FAILED")

        mock_con.rollback.assert_called_once()
        mock_con.close.assert_called_once()

    @patch("app.sqlite3.connect")
    def test_connection_closes_when_commit_fails(self, mock_connect):
        mock_con = MagicMock()
        mock_connect.return_value = mock_con
        mock_con.commit.side_effect = (
            sqlite3.OperationalError("Simulated commit failure")
        )

        with self.assertRaises(sqlite3.OperationalError):
            log_attempt("testuser", "192.0.2.99", "FAILED")

        mock_con.rollback.assert_called_once()
        mock_con.close.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
