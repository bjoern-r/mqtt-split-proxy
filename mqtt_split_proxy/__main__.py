"""Entry point: python -m mqtt_split_proxy -c config.yaml"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import ssl

from . import config as config_mod
from .config import Config
from .local_sink import LocalSink
from .session import Proxy
from .upstream import make_client_context

log = logging.getLogger("mqtt_split_proxy")


def make_server_context(cfg: Config) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cfg.listen.cert, cfg.listen.key)
    ctx.minimum_version = ssl.TLSVersion[cfg.listen.tls_min_version]
    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
        # Old devices often only offer legacy ciphers as well.
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


async def _stats_loop(proxy: Proxy, sink: LocalSink, interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        s = proxy.stats
        log.info("stats: active=%d sessions=%d tapped=%d tap_errors=%d local_ok=%d "
                 "local_dropped=%d local_queue=%d local_connected=%s upstream_failures=%d",
                 s.active, s.sessions, s.tapped, s.tap_errors, sink.ok, sink.dropped,
                 sink.queue.qsize(), sink.connected, s.upstream_failures)


async def serve(cfg: Config, stop: asyncio.Event,
                started: asyncio.Future | None = None) -> None:
    """Run the proxy until ``stop`` is set.

    ``started`` (tests) receives ``(proxy, sink, server)`` once listening.
    """
    sink = LocalSink(cfg.local_broker)
    proxy = Proxy(cfg, sink, make_client_context(cfg.upstream))
    server = await asyncio.start_server(
        proxy.handle_client, cfg.listen.host, cfg.listen.port,
        ssl=make_server_context(cfg), ssl_handshake_timeout=15)
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    log.info("listening on %s -> upstream %s:%d", addrs, cfg.upstream.host, cfg.upstream.port)

    bg = [asyncio.create_task(sink.run(), name="sink"),
          asyncio.create_task(_stats_loop(proxy, sink, cfg.stats_interval), name="stats")]
    if started is not None:
        started.set_result((proxy, sink, server))
    try:
        await stop.wait()
    finally:
        log.info("shutting down")
        server.close()
        if hasattr(server, "close_clients"):  # Python 3.13+
            server.close_clients()
        for t in bg:
            t.cancel()
        await asyncio.gather(*bg, return_exceptions=True)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(server.wait_closed(), 5)


async def _main(cfg: Config) -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await serve(cfg, stop)


def main() -> None:
    ap = argparse.ArgumentParser(prog="mqtt-split-proxy", description=__doc__)
    ap.add_argument("-c", "--config", default="config.yaml")
    ap.add_argument("-v", "--verbose", action="store_true", help="force DEBUG logging")
    args = ap.parse_args()
    cfg = config_mod.load(args.config)
    logging.basicConfig(
        level="DEBUG" if args.verbose else cfg.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    asyncio.run(_main(cfg))


if __name__ == "__main__":
    main()
