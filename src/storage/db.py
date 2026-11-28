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


def get_recent_auth_attempts(limit: int = 50, offset: int = 0) -> list[dict]:
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
    params: tuple[int, ...] = (limit,)
    if offset > 0:
        query += " OFFSET %s"
        params = (limit, offset)

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as err:
        print(f"Eroare la citirea tentativelor de login: {err}")
        return []
    finally:
        if connection.is_connected():
            connection.close()


def get_recent_shell_commands(limit: int = 50, offset: int = 0) -> list[dict]:
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
    params: tuple[int, ...] = (limit,)
    if offset > 0:
        query += " OFFSET %s"
        params = (limit, offset)

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, params)
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as err:
        print(f"Eroare la citirea comenzilor din shell: {err}")
        return []
    finally:
        if connection.is_connected():
            connection.close()


def get_top_passwords(limit: int = 10) -> list[dict]:
    """Returnează topul celor mai încercate parole (cerință de nota 10)."""
    connection = get_connection()
    if not connection:
        return []

    query = (
        "SELECT password, COUNT(*) as count "
        "FROM auth_attempts "
        "GROUP BY password "
        "ORDER BY count DESC "
        "LIMIT %s"
    )

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as err:
        print(f"Eroare la calculul top parole: {err}")
        return []
    finally:
        if connection.is_connected():
            connection.close()


def get_top_ips(limit: int = 10) -> list[dict]:
    """Returnează topul adreselor IP cele mai agresive (cerință de nota 10)."""
    connection = get_connection()
    if not connection:
        return []

    query = (
        "SELECT source_ip, COUNT(*) as count "
        "FROM auth_attempts "
        "GROUP BY source_ip "
        "ORDER BY count DESC "
        "LIMIT %s"
    )

    try:
        cursor = connection.cursor(dictionary=True)
        cursor.execute(query, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        return rows
    except Error as err:
        print(f"Eroare la calculul top IP-uri: {err}")
        return []
    finally:
        if connection.is_connected():
            connection.close()


def get_summary_stats() -> dict:
    """Returnează un sumar general al activității honeypot-ului."""
    connection = get_connection()
    if not connection:
        return {"total_attacks": 0, "ssh_attacks": 0, "telnet_attacks": 0, "shell_commands": 0}

    try:
        cursor = connection.cursor(dictionary=True)

        cursor.execute("SELECT COUNT(*) as total FROM auth_attempts")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM auth_attempts WHERE protocol = 'SSH'")
        ssh = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM auth_attempts WHERE protocol = 'TELNET'")
        telnet = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as total FROM shell_commands")
        commands = cursor.fetchone()["total"]

        cursor.close()
        return {
            "total_attacks": total,
            "ssh_attacks": ssh,
            "telnet_attacks": telnet,
            "shell_commands": commands,
        }
    except Error as err:
        print(f"Eroare la citirea statisticilor generale: {err}")
        return {"total_attacks": 0, "ssh_attacks": 0, "telnet_attacks": 0, "shell_commands": 0}
    finally:
        if connection.is_connected():
            connection.close()
            
