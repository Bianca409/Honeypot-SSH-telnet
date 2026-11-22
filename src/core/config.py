from dataclasses import dataclass
from typing import Protocol


@dataclass
class HoneypotConfig:
    """Configurația de bază pentru serverele Honeypot (SSH și Telnet)."""

    host: str = "0.0.0.0"
    ssh_port: int = 2222
    telnet_port: int = 2323
    db_host: str = "honeypot_mysql"
    db_port: int = 3306


class EventLogger(Protocol):
    """Contractul (interfața) pentru logarea evenimentelor.

    Definește metodele pe care honeypot-ul le va apela pentru a trimite
    datele către stocarea din src/storage/db.py.
    """

    def log_auth_attempt(
        self,
        protocol: str,
        source_ip: str,
        source_port: int,
        username: str,
        password: str,
        status: str,
    ) -> None:
        ...

    def log_shell_command(
        self,
        session_id: str,
        source_ip: str,
        command: str,
    ) -> None:
        ...