import asyncio
import logging
import ssl
from typing import Optional

logger = logging.getLogger(__name__)


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def error_received(self, exc):
        logger.error("UDP syslog error: %s", exc)

    def connection_lost(self, exc):
        self.transport = None


class SyslogSender:
    def __init__(self):
        self._tcp_connections: dict[tuple[str, int, str], tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self._udp_transports: dict[tuple[str, int], asyncio.DatagramTransport] = {}

    async def send(
        self,
        host: str,
        port: int,
        protocol: str,
        message: str,
        tls_ca_cert: Optional[str] = None,
    ) -> None:
        encoded = message.encode("utf-8")
        if protocol == "udp":
            await self._send_udp(host, port, encoded)
        elif protocol == "tcp":
            await self._send_tcp(host, port, encoded)
        elif protocol == "tls":
            await self._send_tls(host, port, encoded, tls_ca_cert)
        else:
            raise ValueError(f"Unsupported syslog protocol: {protocol}")

    async def _send_udp(self, host: str, port: int, data: bytes) -> None:
        key = (host, port)
        transport = self._udp_transports.get(key)
        if transport is None or transport.is_closing():
            loop = asyncio.get_event_loop()
            transport, _ = await loop.create_datagram_endpoint(
                _UDPProtocol,
                remote_addr=(host, port),
            )
            self._udp_transports[key] = transport
        transport.sendto(data)

    async def _send_tcp(self, host: str, port: int, data: bytes) -> None:
        key = (host, port, "tcp")
        conn = self._tcp_connections.get(key)
        if conn is not None:
            reader, writer = conn
            if not writer.is_closing():
                try:
                    writer.write(data + b"\n")
                    await writer.drain()
                    return
                except Exception:
                    try:
                        writer.close()
                    except Exception:
                        pass

        reader, writer = await asyncio.open_connection(host, port)
        self._tcp_connections[key] = (reader, writer)
        writer.write(data + b"\n")
        await writer.drain()

    async def _send_tls(self, host: str, port: int, data: bytes, tls_ca_cert: Optional[str] = None) -> None:
        key = (host, port, "tls")
        conn = self._tcp_connections.get(key)
        if conn is not None:
            reader, writer = conn
            if not writer.is_closing():
                try:
                    writer.write(data + b"\n")
                    await writer.drain()
                    return
                except Exception:
                    try:
                        writer.close()
                    except Exception:
                        pass

        ssl_ctx = ssl.create_default_context()
        if tls_ca_cert:
            ssl_ctx.load_verify_locations(cadata=tls_ca_cert)

        reader, writer = await asyncio.open_connection(host, port, ssl=ssl_ctx)
        self._tcp_connections[key] = (reader, writer)
        writer.write(data + b"\n")
        await writer.drain()

    async def close(self) -> None:
        for transport in self._udp_transports.values():
            try:
                transport.close()
            except Exception:
                pass
        self._udp_transports.clear()

        for reader, writer in self._tcp_connections.values():
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
        self._tcp_connections.clear()


_sender: Optional[SyslogSender] = None


def _get_sender() -> SyslogSender:
    global _sender
    if _sender is None:
        _sender = SyslogSender()
    return _sender


async def send_syslog_message(
    host: str,
    port: int,
    protocol: str,
    message: str,
    tls_ca_cert: Optional[str] = None,
) -> None:
    sender = _get_sender()
    await sender.send(host, port, protocol, message, tls_ca_cert)
