from unittest.mock import MagicMock, patch

from src.storage import db


def _make_mock_connection(rows=None):
    """Creează o conexiune și un cursor MySQL simulate pentru teste."""
    mock_cursor = MagicMock()
    mock_cursor.fetchall.return_value = rows if rows is not None else []

    mock_conn = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_conn.is_connected.return_value = True
    return mock_conn, mock_cursor


def test_save_auth_attempt_uses_parameterized_query():
    mock_conn, mock_cursor = _make_mock_connection()

    with patch("src.storage.db.get_connection", return_value=mock_conn):
        result = db.save_auth_attempt(
            protocol="SSH",
            source_ip="192.168.1.10",
            source_port=54321,
            username="root",
            password="password123",
            status="REJECTED",
        )

    assert result is True
    query, values = mock_cursor.execute.call_args[0]
    assert "%s" in query
    assert values == ("SSH", "192.168.1.10", 54321, "root", "password123", "REJECTED")
    mock_conn.commit.assert_called_once()
    mock_conn.close.assert_called_once()


def test_save_auth_attempt_prevents_sql_injection():
    mock_conn, mock_cursor = _make_mock_connection()
    malicious_user = "admin' OR '1'='1"
    malicious_pass = "'; DROP TABLE auth_attempts; --"

    with patch("src.storage.db.get_connection", return_value=mock_conn):
        result = db.save_auth_attempt(
            protocol="TELNET",
            source_ip="10.0.0.5",
            source_port=40000,
            username=malicious_user,
            password=malicious_pass,
        )

    assert result is True
    query, values = mock_cursor.execute.call_args[0]
    assert "DROP TABLE" not in query
    assert "OR '1'='1" not in query
    assert malicious_user in values
    assert malicious_pass in values


def test_save_shell_command_uses_parameterized_query():
    mock_conn, mock_cursor = _make_mock_connection()

    with patch("src.storage.db.get_connection", return_value=mock_conn):
        result = db.save_shell_command("sess-123", "10.0.0.8", "uname -a")

    assert result is True
    query, values = mock_cursor.execute.call_args[0]
    assert "%s" in query
    assert values == ("sess-123", "10.0.0.8", "uname -a")
    mock_conn.commit.assert_called_once()


def test_get_recent_auth_attempts_returns_rows():
    sample_rows = [
        {"id": 1, "protocol": "SSH", "source_ip": "10.0.0.2", "username": "root"}
    ]
    mock_conn, mock_cursor = _make_mock_connection(rows=sample_rows)

    with patch("src.storage.db.get_connection", return_value=mock_conn):
        rows = db.get_recent_auth_attempts(limit=10)

    assert rows == sample_rows
    query, values = mock_cursor.execute.call_args[0]
    assert "LIMIT %s" in query
    assert values == (10,)
    mock_conn.cursor.assert_called_once_with(dictionary=True)


def test_get_recent_shell_commands_returns_rows():
    sample_rows = [{"id": 1, "session_id": "sess-1", "command": "whoami"}]
    mock_conn, mock_cursor = _make_mock_connection(rows=sample_rows)

    with patch("src.storage.db.get_connection", return_value=mock_conn):
        rows = db.get_recent_shell_commands(limit=5)

    assert rows == sample_rows
    query, values = mock_cursor.execute.call_args[0]
    assert "LIMIT %s" in query
    assert values == (5,)


def test_functions_handle_failed_db_connection():
    with patch("src.storage.db.get_connection", return_value=None):
        assert db.save_auth_attempt("SSH", "1.2.3.4", 22, "u", "p") is False
        assert db.save_shell_command("sess-1", "1.2.3.4", "ls") is False
        assert db.get_recent_auth_attempts() == []
        assert db.get_recent_shell_commands() == []