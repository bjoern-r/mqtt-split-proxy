"""One device connection: relay bytes to the cloud and tap PUBLISHes."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import ssl
import time
from dataclasses import dataclass

from . import mqtt_codec as codec
from . import upstream
from .config import Config, UpstreamConfig
from .local_sink import LocalSink
from .routing import Router

log = logging.getLogger(__name__)

CHUNK = 65536


def _show(secret: bytes | None) -> str:
    """Render a binary password: quoted text if valid UTF-8, else hex."""
    if secret is None:
        return "<none>"
    try:
        return repr(secret.decode("utf-8"))
    except UnicodeDecodeError:
        return "hex:" + secret.hex()


@dataclass
class Stats:
    active: int = 0
    sessions: int = 0
    tapped: int = 0
    tap_errors: int = 0
    upstream_failures: int = 0
    unrouted: int = 0


class Proxy:
    def __init__(self, cfg: Config, sink: LocalSink,
                 upstream_ctxs: dict[str, ssl.SSLContext]):
        self.cfg = cfg
        self.sink = sink
        self.router = Router(cfg)
        self.upstream_ctxs = upstream_ctxs  # by upstream name
        self.stats = Stats()

    async def handle_client(self, reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter) -> None:
        self.stats.active += 1
        self.stats.sessions += 1
        try:
            await Session(self, reader, writer).run()
        except Exception:
            log.exception("session crashed")
        finally:
            self.stats.active -= 1


class Session:
    def __init__(self, proxy: Proxy, reader: asyncio.StreamReader,
                 writer: asyncio.StreamWriter):
        self.proxy = proxy
        self.cfg = proxy.cfg
        self.d_reader, self.d_writer = reader, writer
        self.u_writer: asyncio.StreamWriter | None = None
        peer = writer.get_extra_info("peername")
        self.peer = f"{peer[0]}:{peer[1]}" if peer else "?"
        sock = writer.get_extra_info("sockname")
        self.local_port: int | None = sock[1] if sock else None  # proxy port the device used
        self.info: codec.ConnectInfo | None = None
        self.route: UpstreamConfig | None = None
        # Set by the SNI callback in __main__.make_server_context.
        self.sni: str | None = getattr(writer.get_extra_info("ssl_object"), "sni", None)
        self.alias_map: dict[int, str] = {}
        self.bytes_up = 0
        self.bytes_down = 0
        self.publishes = 0
        self._tap_error_logged = False

    async def run(self) -> None:
        start = time.monotonic()
        try:
            await self._run()
        finally:
            await self._close(self.d_writer)
            if self.u_writer is not None:
                await self._close(self.u_writer)
            if self.info is not None:
                log.info("session %s client_id=%r vendor=%s closed after %.0fs: up=%dB down=%dB publishes=%d",
                         self.peer, self.info.client_id,
                         self.route.name if self.route else "-", time.monotonic() - start,
                         self.bytes_up, self.bytes_down, self.publishes)

    async def _run(self) -> None:
        try:
            pkt = await asyncio.wait_for(
                codec.read_packet(self.d_reader, max_len=64 * 1024),
                self.cfg.connect_timeout)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError,
                codec.ProtocolError, OSError) as e:
            log.info("%s: no valid CONNECT (%r), closing", self.peer, e)
            return
        if pkt.type != codec.CONNECT:
            log.info("%s: first packet is type %d, not CONNECT; closing", self.peer, pkt.type)
            return
        try:
            self.info = codec.parse_connect(pkt.body)
        except codec.ProtocolError as e:
            log.info("%s: undecodable CONNECT (%s), closing", self.peer, e)
            return
        log.info("%s: CONNECT client_id=%r mqtt_level=%d keepalive=%d port=%s sni=%s",
                 self.peer, self.info.client_id, self.info.version, self.info.keepalive,
                 self.local_port, self.sni or "-")
        if self.cfg.log_credentials:
            log.info("%s: CREDENTIALS client_id=%r username=%r password=%s", self.peer,
                     self.info.client_id, self.info.username, _show(self.info.password))
        else:
            log.debug("%s: username=%r", self.peer, self.info.username)

        self.route = self.proxy.router.select(self.sni, self.info.client_id,
                                              self.info.username, self.local_port)
        if self.route is None:
            self.proxy.stats.unrouted += 1
            log.warning("%s: no upstream matches port=%s sni=%s client_id=%r and no default; "
                        "closing", self.peer, self.local_port, self.sni or "-",
                        self.info.client_id)
            return
        log.info("%s: routing to %s (%s:%s%s)", self.peer, self.route.name, self.route.host,
                 self.route.port or self.local_port, "" if self.route.tls else ", plain")

        try:
            u_reader, self.u_writer = await upstream.connect(
                self.route, self.proxy.upstream_ctxs[self.route.name], self.local_port)
        except (upstream.UpstreamError, OSError) as e:
            self.proxy.stats.upstream_failures += 1
            log.warning("%s: upstream %s connect failed: %s", self.peer, self.route.name, e)
            return

        self.u_writer.write(pkt.raw)
        self.bytes_up += len(pkt.raw)
        await self.u_writer.drain()

        tasks = [asyncio.create_task(self._pump_up(), name="up"),
                 asyncio.create_task(self._pump_down(u_reader), name="down")]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
        for t in done:
            if not t.cancelled() and t.exception() is not None:
                e = t.exception()
                level = logging.INFO if isinstance(e, (OSError, asyncio.IncompleteReadError,
                                                       codec.ProtocolError)) else logging.ERROR
                log.log(level, "%s: %s pump ended: %r", self.peer, t.get_name(), e)

    async def _pump_up(self) -> None:
        """device -> cloud, packet-framed, with tap."""
        reader, writer = self.d_reader, self.u_writer
        assert writer is not None
        tap_max = self.cfg.tap_max_packet
        while True:
            try:
                hdr = await codec.read_header(reader)
            except asyncio.IncompleteReadError as e:
                if e.partial:
                    raise
                return  # clean EOF between packets
            n = hdr.remaining_length
            if hdr.type == codec.PUBLISH and n <= tap_max:
                body = await reader.readexactly(n)
                writer.write(hdr.raw + body)
                self.bytes_up += len(hdr.raw) + n
                await writer.drain()
                self._tap(hdr.flags, body, full=True)
                continue

            writer.write(hdr.raw)
            self.bytes_up += len(hdr.raw)
            first = True
            while n:
                chunk = await reader.readexactly(min(n, CHUNK))
                n -= len(chunk)
                writer.write(chunk)
                self.bytes_up += len(chunk)
                await writer.drain()
                if first and hdr.type == codec.PUBLISH:
                    # Oversized: not copied, but keep the v5 alias table in sync.
                    self._tap(hdr.flags, chunk, full=False)
                first = False
            await writer.drain()

    async def _pump_down(self, reader: asyncio.StreamReader) -> None:
        """cloud -> device, plain byte copy."""
        writer = self.d_writer
        while True:
            data = await reader.read(CHUNK)
            if not data:
                return
            writer.write(data)
            self.bytes_down += len(data)
            await writer.drain()

    def _tap(self, flags: int, body: bytes, full: bool) -> None:
        assert self.info is not None and self.route is not None
        try:
            pub = codec.parse_publish(flags, body, self.info.version, self.alias_map)
        except codec.ProtocolError as e:
            self.proxy.stats.tap_errors += 1
            if full and not self._tap_error_logged:
                self._tap_error_logged = True
                log.warning("%s: cannot decode PUBLISH for local copy (%s); relaying anyway",
                            self.peer, e)
            return
        if not full:
            return
        self.publishes += 1
        self.proxy.stats.tapped += 1
        self.proxy.sink.offer(self.route.name, self.info.client_id, self.info.username,
                              pub.topic, pub.payload, pub.retain)

    @staticmethod
    async def _close(writer: asyncio.StreamWriter) -> None:
        with contextlib.suppress(Exception):
            writer.close()
            await asyncio.wait_for(writer.wait_closed(), 2)
