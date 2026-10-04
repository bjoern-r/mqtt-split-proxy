"""Connect to the real cloud broker, bypassing the manipulated LAN DNS."""

from __future__ import annotations

import asyncio
import logging
import ssl

import dns.asyncresolver
import dns.exception

from .config import UpstreamConfig

log = logging.getLogger(__name__)


class UpstreamError(Exception):
    pass


def make_client_context(cfg: UpstreamConfig) -> ssl.SSLContext:
    if cfg.verify:
        return ssl.create_default_context(cafile=cfg.cafile)
    log.warning("upstream certificate verification is DISABLED")
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def resolve(cfg: UpstreamConfig) -> list[str]:
    if cfg.address:
        return [cfg.address]
    if not cfg.resolver:
        # System resolver. Only safe if this host does not use the LAN override.
        infos = await asyncio.get_running_loop().getaddrinfo(
            cfg.host, cfg.port, type=0, proto=0)
        return list(dict.fromkeys(i[4][0] for i in infos))
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [cfg.resolver] if isinstance(cfg.resolver, str) else list(cfg.resolver)
    try:
        answer = await resolver.resolve(cfg.host, "A", lifetime=5)
    except dns.exception.DNSException as e:
        raise UpstreamError(f"cannot resolve {cfg.host} via {resolver.nameservers}: {e}") from e
    return [r.address for r in answer]


async def connect(cfg: UpstreamConfig, ctx: ssl.SSLContext
                  ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    addresses = await resolve(cfg)
    errors = []
    for ip in addresses:
        try:
            return await asyncio.wait_for(
                asyncio.open_connection(ip, cfg.port, ssl=ctx, server_hostname=cfg.host),
                cfg.connect_timeout)
        except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
            errors.append(f"{ip}: {e!r}")
            log.debug("upstream %s:%d failed: %r", ip, cfg.port, e)
    raise UpstreamError(f"cannot connect to {cfg.host}:{cfg.port}: {'; '.join(errors) or 'no addresses'}")
