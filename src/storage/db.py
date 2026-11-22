import os

import mysql.connector
from mysql.connector import Error

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "honeypot_user")
DB_PASSWORD = os.getenv("DB_PASSWORD", "honeypot_pass")
DB_NAME = os.getenv("DB_NAME", "honeypot_db")


def get_connection():
    """Creează și returnează o conexiune la baza de date MySQL."""
    try:
        return mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
        )
    except Error as err:
        print(f"Eroare la conectarea la MySQL: {err}")
        return None


def save_auth_attempt(
    protocol: str,
    source_ip: str,
    source_port: int,
    username: str,
    password: str,
    status: str = "REJECTED",
) -> bool:
    """Salvează o tentativă de login (SSH/Telnet) folosind query parametrizat."""
    connection = get_connection()
    if not connection:
        return False

    query = (
        "INSERT INTO auth_attempts "
        "(protocol, source_ip, source_port, username, password, status) "
        "VALUES (%s, %s, %s, %s, %s, %s)"
    )
    values = (protocol, source_ip, source_port, username, password, status)

    try:
        cursor = connection.cursor()
        cursor.execute(query, values)
        connection.commit()
        cursor.close()
        return True
    except Error as err:
        print(f"Eroare la salvarea tentativei de login: {err}")
        return False
    finally:
        if connection.is_connected():
            connection.close()


def save_shell_command(session_id: str, source_ip: str, command: str) -> bool:
    """Salvează o comandă din shell-ul fals folosind query parametrizat."""
    connection = get_connection()
    if not connection:
        return False

    query = (
        "INSERT INTO shell_commands (session_id, source_ip, command) "
        "VALUES (%s, %s, %s)"
    )
    values = (session_id, source_ip, command)

    try:
        cursor = connection.cursor()
        cursor.execute(query, values)
        connection.commit()
        cursor.close()
        return True
    except Error as err:
        print(f"Eroare la salvarea comenzii din shell: {err}")
        return False
    finally:
        if connection.is_connected():
            connection.close()


def get_recent_auth_attempts(limit: int = 50) -> list[dict]:
    """Returnează cele mai recente tentative de autentificare din MySQL."""
    connection = get_connection()
    if not connection:
        return []

    query = (
        "SELECT id, timestamp, protocol, source_ip, source_port, "
        "username, password, status "
        "FROM auth_attempts "
        "ORDER BY timestamp DESC "
        "LIMIT %s"
    )

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as err:
        print(f"Eroare la citirea tentativelor de login: {err}")
        return []
    finally:
        if connection.is_connected():
            connection.close()


def get_recent_shell_commands(limit: int = 50) -> list[dict]:
    """Returnează cele mai recente comenzi tastate în shell-ul fals."""
    connection = get_connection()
    if not connection:
        return []

    query = (
        "SELECT id, session_id, timestamp, source_ip, command "
        "FROM shell_commands "
        "ORDER BY timestamp DESC "
        "LIMIT %s"
    )

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as err:
        print(f"Eroare la citirea comenzilor din shell: {err}")
        return []
    finally:
        if connection.is_connected():
            connection.close()