import asyncio
import logging
import uuid
from enum import Enum

from src.core.config import EventLogger, HoneypotConfig

logger = logging.getLogger(__name__)

TELNET_BANNER = "\r\nUbuntu 22.04.3 LTS\r\n"
LOGIN_PROMPT = "login: "
PASSWORD_PROMPT = "Password: "
AUTH_FAILED_MSG = "\r\nLogin incorrect\r\n"
SHELL_PROMPT = "root@honeypot-srv:~# "
MAX_AUTH_ATTEMPTS = 3


class TelnetAuthState(str, Enum):
    """Stările mașinii de stări pentru autentificarea Telnet."""

    LOGIN_PROMPT = "LOGIN_PROMPT"
    PASSWORD_PROMPT = "PASSWORD_PROMPT"
    SHELL_SESSION = "SHELL_SESSION"


class TelnetHoneypotServer:
    """Server TCP asincron pentru serviciul Telnet cu mașină de stări de autentificare."""

    def __init__(
        self,
        config: HoneypotConfig,
        event_logger: EventLogger | None = None,
    ) -> None:
        self.config = config
        self.event_logger = event_logger
        self._server: asyncio.AbstractServer | None = None

    def _clean_input(self, raw_data: bytes) -> str:
        """Curăță bytes Telnet (inclusiv comenzi IAC 0xFF) și returnează textul."""
        filtered = bytearray()
        idx = 0
        length = len(raw_data)
        while idx < length:
            byte = raw_data[idx]
            if byte == 0xFF:  # IAC
                idx += 3 if idx + 2 < length else length
                continue
            filtered.append(byte)
            idx += 1
        return filtered.decode("utf-8", errors="ignore").strip("\r\n\x00")

    def _verify_credentials(self, username: str, password: str) -> bool:
        """Acceptă o listă realistă de credențiale de test/atacatori."""
        if not username:
            return False
        valid_pairs = {
            ("root", "root"),
            ("root", "123456"),
            ("root", "admin"),
            ("admin", "admin"),
            ("admin", "1234"),
            ("user", "user"),
        }
        return (username, password) in valid_pairs

    def _record_auth_attempt(
        self,
        source_ip: str,
        source_port: int,
        username: str,
        password: str,
        status: str,
    ) -> None:
        """Trimite tentativa de autentificare către EventLogger dacă este configurat."""
        if self.event_logger is None:
            return
        self.event_logger.log_auth_attempt(
            protocol="telnet",
            source_ip=source_ip,
            source_port=source_port,
            username=username,
            password=password,
            status=status,
        )

    async def _send_line(self, writer: asyncio.StreamWriter, text: str) -> None:
        writer.write(text.encode("utf-8"))
        await writer.drain()

    async def _read_line(self, reader: asyncio.StreamReader) -> str | None:
        raw = await reader.readline()
        if not raw:
            return None
        return self._clean_input(raw)

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        source_port = int(peer[1]) if peer and len(peer) > 1 else 0
        session_id = str(uuid.uuid4())

        logger.info(
            "Conexiune Telnet nouă (%s) de la %s:%s",
            session_id,
            source_ip,
            source_port,
        )

        state = TelnetAuthState.LOGIN_PROMPT
        current_username = ""
        attempts = 0

        try:
            await self._send_line(writer, TELNET_BANNER)

            while state != TelnetAuthState.SHELL_SESSION:
                if state == TelnetAuthState.LOGIN_PROMPT:
                    await self._send_line(writer, LOGIN_PROMPT)
                    line = await self._read_line(reader)
                    if line is None:
                        break
                    current_username = line
                    state = TelnetAuthState.PASSWORD_PROMPT

                elif state == TelnetAuthState.PASSWORD_PROMPT:
                    await self._send_line(writer, PASSWORD_PROMPT)
                    line = await self._read_line(reader)
                    if line is None:
                        break
                    password = line
                    attempts += 1

                    if self._verify_credentials(current_username, password):
                        self._record_auth_attempt(
                            source_ip=source_ip,
                            source_port=source_port,
                            username=current_username,
                            password=password,
                            status="SUCCESS",
                        )
                        state = TelnetAuthState.SHELL_SESSION
                    else:
                        self._record_auth_attempt(
                            source_ip=source_ip,
                            source_port=source_port,
                            username=current_username,
                            password=password,
                            status="FAILED",
                        )
                        if attempts >= MAX_AUTH_ATTEMPTS:
                            await self._send_line(writer, AUTH_FAILED_MSG)
                            break
                        await self._send_line(writer, AUTH_FAILED_MSG)
                        state = TelnetAuthState.LOGIN_PROMPT

            if state == TelnetAuthState.SHELL_SESSION:
                await self._handle_shell_session(
                    reader=reader,
                    writer=writer,
                    session_id=session_id,
                    source_ip=source_ip,
                    username=current_username,
                )

        except (ConnectionResetError, BrokenPipeError):
            logger.warning(
                "Conexiune întreruptă de clientul %s:%s",
                source_ip,
                source_port,
            )
        finally:
            writer.close()
            await writer.wait_closed()
            logger.info("Conexiune Telnet închisă de la %s:%s", source_ip, source_port)

    async def _handle_shell_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        session_id: str,
        source_ip: str,
        username: str,
    ) -> None:
        """Bucla sesiunii post-autentificare (shell-ul interactiv vine în Commit 6)."""
        logger.info(
            "Sesiune Telnet autentificată (%s) pentru '%s' de la %s",
            session_id,
            username,
            source_ip,
        )
        await self._send_line(writer, f"\r\nWelcome to Ubuntu 22.04.3 LTS\r\n{SHELL_PROMPT}")
        while True:
            cmd = await self._read_line(reader)
            if cmd is None or cmd == "exit":
                break
            await self._send_line(writer, SHELL_PROMPT)

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self.handle_client,
            host=self.config.host,
            port=self.config.telnet_port,
        )
        logger.info(
            "Serverul Telnet ascultă pe %s:%s",
            self.config.host,
            self.config.telnet_port,
        )
        async with self._server:
            await self._server.serve_forever()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    server = TelnetHoneypotServer(HoneypotConfig())
    asyncio.run(server.start())