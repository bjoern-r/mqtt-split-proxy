"""Entry point: python -m mqtt_split_proxy -c config.yaml"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
import ssl

from . import config as config_mod
from .config import Config, ListenConfig
from .local_sink import LocalSink
from .routing import Router
from .session import Proxy
from .upstream import make_client_context

log = logging.getLogger("mqtt_split_proxy")


def _server_context(listen: ListenConfig, cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    ctx.minimum_version = ssl.TLSVersion[listen.tls_min_version]
    if ctx.minimum_version < ssl.TLSVersion.TLSv1_2:
        # Old devices often only offer legacy ciphers as well.
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    return ctx


def make_server_context(cfg: Config, listen: ListenConfig, router: Router) -> ssl.SSLContext:
    """Listener context; an SNI callback records the requested server name for
    routing and switches to an upstream's own certificate if it has one."""
    ctx = _server_context(listen, listen.cert, listen.key)
    per_upstream = {u.name: _server_context(listen, u.cert, u.key)
                    for u in cfg.upstreams if u.cert is not None}

    def on_sni(sslobj: ssl.SSLObject, server_name: str | None, _ctx: ssl.SSLContext) -> None:
        sslobj.sni = server_name  # read back in Session via get_extra_info("ssl_object")
        if server_name is not None:
            up = router.for_sni(server_name)
            if up is not None and up.name in per_upstream:
                sslobj.context = per_upstream[up.name]

    ctx.sni_callback = on_sni
    return ctx


async def _stats_loop(proxy: Proxy, sink: LocalSink, interval: float) -> None:
    while True:
        await asyncio.sleep(interval)
        s = proxy.stats
        log.info("stats: active=%d sessions=%d tapped=%d tap_errors=%d tapped_down=%d "
                 "tap_errors_down=%d local_ok=%d "
                 "local_dropped=%d local_queue=%d local_connected=%s upstream_failures=%d "
                 "unrouted=%d",
                 s.active, s.sessions, s.tapped, s.tap_errors, s.tapped_down,
                 s.tap_errors_down, sink.ok, sink.dropped,
                 sink.queue.qsize(), sink.connected, s.upstream_failures, s.unrouted)


async def serve(cfg: Config, stop: asyncio.Event,
                started: asyncio.Future | None = None) -> None:
    """Run the proxy until ``stop`` is set.

    ``started`` (tests) receives ``(proxy, sink, servers)`` once listening.
    """
    sink = LocalSink(cfg.local_broker)
    proxy = Proxy(cfg, sink, {u.name: make_client_context(u) for u in cfg.upstreams})
    servers = []
    try:
        for ln in cfg.listen:
            tls = make_server_context(cfg, ln, proxy.router) if ln.tls else None
            server = await asyncio.start_server(
                proxy.handle_client, ln.host, ln.port, ssl=tls,
                ssl_handshake_timeout=15 if tls else None)
            servers.append(server)
            addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
            log.info("listening on %s (%s)", addrs, "TLS" if tls else "plain MQTT")
    except BaseException:
        for s in servers:
            s.close()
        raise
    if cfg.log_credentials:
        log.warning("log_credentials is ON: device passwords will be written to the log")
    for u in cfg.upstreams:
        log.info("upstream %s: %s:%s%s%s", u.name, u.host, u.port or "<device port>",
                 "" if u.tls else " (plain)", " (default)" if u.name == cfg.default else "")

    bg = [asyncio.create_task(sink.run(), name="sink"),
          asyncio.create_task(_stats_loop(proxy, sink, cfg.stats_interval), name="stats")]
    if started is not None:
        started.set_result((proxy, sink, servers))
    try:
        await stop.wait()
    finally:
        log.info("shutting down")
        for server in servers:
            server.close()
            if hasattr(server, "close_clients"):  # Python 3.13+
                server.close_clients()
        for t in bg:
            t.cancel()
        await asyncio.gather(*bg, return_exceptions=True)
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.gather(*(s.wait_closed() for s in servers)), 5)


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
    ap.add_argument("--log-credentials", action="store_true",
                    help="log the username and password each device sends (debugging only)")
    args = ap.parse_args()
    cfg = config_mod.load(args.config)
    cfg.log_credentials |= args.log_credentials
    logging.basicConfig(
        level="DEBUG" if args.verbose else cfg.log_level.upper(),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s")
    asyncio.run(_main(cfg))


if __name__ == "__main__":
    main()
