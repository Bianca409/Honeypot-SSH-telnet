import asyncio

import pytest

from src.core.config import HoneypotConfig
from src.protocols.telnet_server import TelnetHoneypotServer


class DummyEventLogger:
    """Logger în memorie folosit pentru verificarea evenimentelor Telnet."""

    def __init__(self) -> None:
        self.auth_events: list[dict] = []
        self.shell_events: list[dict] = []

    def log_auth_attempt(
        self,
        protocol: str,
        source_ip: str,
        source_port: int,
        username: str,
        password: str,
        status: str,
    ) -> None:
        self.auth_events.append(
            {
                "protocol": protocol,
                "source_ip": source_ip,
                "source_port": source_port,
                "username": username,
                "password": password,
                "status": status,
            }
        )

    def log_shell_command(
        self,
        protocol: str,
        session_id: str,
        source_ip: str,
        username: str,
        command: str,
    ) -> None:
        self.shell_events.append(
            {
                "protocol": protocol,
                "session_id": session_id,
                "source_ip": source_ip,
                "username": username,
                "command": command,
            }
        )


@pytest.mark.asyncio
async def test_telnet_auth_and_shell_commands() -> None:
    logger = DummyEventLogger()
    config = HoneypotConfig(host="127.0.0.1", telnet_port=0)
    honeypot = TelnetHoneypotServer(config=config, event_logger=logger)

    server = await asyncio.start_server(
        honeypot.handle_client, host="127.0.0.1", port=0
    )
    port = server.sockets[0].getsockname()[1]

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        banner_and_login = await asyncio.wait_for(reader.readuntil(b"login: "), timeout=2)
        assert b"Ubuntu 22.04.3 LTS" in banner_and_login

        writer.write(b"root\r\n")
        await writer.drain()

        pass_prompt = await asyncio.wait_for(reader.readuntil(b"Password: "), timeout=2)
        assert b"Password: " in pass_prompt

        writer.write(b"123456\r\n")
        await writer.drain()

        prompt = await asyncio.wait_for(
            reader.readuntil(b"root@honeypot-srv:~# "), timeout=2
        )
        assert b"Welcome to Ubuntu" in prompt

        writer.write(b"whoami\r\n")
        await writer.drain()
        whoami_out = await asyncio.wait_for(
            reader.readuntil(b"root@honeypot-srv:~# "), timeout=2
        )
        assert b"root\r\n" in whoami_out

        writer.write(b"exit\r\n")
        await writer.drain()
        await asyncio.wait_for(reader.read(), timeout=2)

        writer.close()
        await writer.wait_closed()

    assert len(logger.auth_events) == 1
    assert logger.auth_events[0]["username"] == "root"
    assert logger.auth_events[0]["password"] == "123456"
    assert logger.auth_events[0]["status"] == "SUCCESS"

    commands = [ev["command"] for ev in logger.shell_events]
    assert commands == ["whoami", "exit"]


@pytest.mark.asyncio
async def test_telnet_failed_auth_logged() -> None:
    logger = DummyEventLogger()
    config = HoneypotConfig(host="127.0.0.1", telnet_port=0)
    honeypot = TelnetHoneypotServer(config=config, event_logger=logger)

    server = await asyncio.start_server(
        honeypot.handle_client, host="127.0.0.1", port=0
    )
    port = server.sockets[0].getsockname()[1]

    async with server:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        await asyncio.wait_for(reader.readuntil(b"login: "), timeout=2)
        writer.write(b"admin\r\n")
        await writer.drain()

        await asyncio.wait_for(reader.readuntil(b"Password: "), timeout=2)
        writer.write(b"wrongpass\r\n")
        await writer.drain()

        resp = await asyncio.wait_for(reader.readuntil(b"login: "), timeout=2)
        assert b"Login incorrect" in resp

        writer.close()
        await writer.wait_closed()

    assert len(logger.auth_events) == 1
    assert logger.auth_events[0]["status"] == "FAILED"
    assert logger.shell_events == []