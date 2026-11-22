import asyncio
import logging

from src.core.config import HoneypotConfig

logger = logging.getLogger(__name__)

TELNET_BANNER = (
    "\r\nUbuntu 22.04.3 LTS\r\n"
    "honeypot-srv ttyS0\r\n\r\n"
)


class TelnetHoneypotServer:
    """Server TCP asincron pentru serviciul Telnet pe portul 2323."""

    def __init__(self, config: HoneypotConfig) -> None:
        self.config = config
        self._server: asyncio.AbstractServer | None = None

    async def handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = writer.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        source_port = peer[1] if peer else 0
        logger.info("Conexiune Telnet nouă de la %s:%s", source_ip, source_port)

        try:
            writer.write(TELNET_BANNER.encode("utf-8"))
            await writer.drain()
        except ConnectionResetError:
            logger.warning(
                "Conexiune resetată de clientul %s:%s", source_ip, source_port
            )
        finally:
            writer.close()
            await writer.wait_closed()

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