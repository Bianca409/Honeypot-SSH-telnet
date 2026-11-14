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
        connection = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME,
        )
        return connection
    except Error as e:
        print(f"Eroare la conectarea la MySQL: {e}")
        return None


def save_auth_attempt(
    protocol: str,
    source_ip: str,
    source_port: int,
    username: str,
    password: str,
    status: str = "REJECTED",
):
    """Salvează o tentativă de login (SSH sau Telnet) în MySQL.

    Folosește query parametrizat (%s) pentru a preveni SQL Injection.
    """
    connection = get_connection()
    if not connection:
        return False

    query = """
    INSERT INTO auth_attempts (protocol, source_ip, source_port, username, password, status)
    VALUES (%s, %s, %s, %s, %s, %s)
    """
    values = (protocol, source_ip, source_port, username, password, status)

    try:
        cursor = connection.cursor()
        cursor.execute(query, values)
        connection.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"Eroare la salvarea tentativei de login: {e}")
        return False
    finally:
        if connection.is_connected():
            connection.close()


def save_shell_command(session_id: str, source_ip: str, command: str):
    """Salvează o comandă tastată de un atacator în shell-ul fals.

    Folosește query parametrizat (%s) pentru a preveni SQL Injection.
    """
    connection = get_connection()
    if not connection:
        return False

    query = """
    INSERT INTO shell_commands (session_id, source_ip, command)
    VALUES (%s, %s, %s)
    """
    values = (session_id, source_ip, command)

    try:
        cursor = connection.cursor()
        cursor.execute(query, values)
        connection.commit()
        cursor.close()
        return True
    except Error as e:
        print(f"Eroare la salvarea comenzii din shell: {e}")
        return False
    finally:
        if connection.is_connected():
            connection.close()