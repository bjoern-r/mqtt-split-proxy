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
    if not cfg.tls:
        return ssl.create_default_context()  # unused for plain upstreams
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
        infos = await asyncio.get_running_loop().getaddrinfo(cfg.host, None, type=0, proto=0)
        return list(dict.fromkeys(i[4][0] for i in infos))
    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [cfg.resolver] if isinstance(cfg.resolver, str) else list(cfg.resolver)
    try:
        answer = await resolver.resolve(cfg.host, "A", lifetime=5)
    except dns.exception.DNSException as e:
        raise UpstreamError(f"cannot resolve {cfg.host} via {resolver.nameservers}: {e}") from e
    return [r.address for r in answer]


async def connect(cfg: UpstreamConfig, ctx: ssl.SSLContext, port: int | None = None
                  ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to ``cfg.port``, or to ``port`` (the device's port) if that is unset."""
    port = cfg.port or port
    if not port:
        raise UpstreamError(f"no port for upstream {cfg.name or cfg.host}")
    addresses = await resolve(cfg)
    errors = []
    for ip in addresses:
        try:
            return await _connect_one(cfg, ctx, ip, port)
        except UpstreamError as e:
            errors.append(f"{ip}: {e}")
            log.debug("upstream %s:%d failed: %s", ip, port, e)
    raise UpstreamError(f"cannot connect to {cfg.host}:{port}: {'; '.join(errors) or 'no addresses'}")


async def _connect_one(cfg: UpstreamConfig, ctx: ssl.SSLContext, ip: str, port: int
                       ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    # TCP and TLS are done in two steps so a failure says which one broke.
    t = cfg.connect_timeout
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), t)
    except asyncio.TimeoutError:
        raise UpstreamError(f"TCP connect timed out after {t:g}s "
                            "(no answer: firewall, routing or wrong port?)") from None
    except OSError as e:
        raise UpstreamError(f"TCP connect failed: {e.strerror or e}") from None
    if not cfg.tls:
        return reader, writer
    try:
        await asyncio.wait_for(writer.start_tls(ctx, server_hostname=cfg.host), t)
        return reader, writer
    except asyncio.TimeoutError:
        reason = f"TLS handshake timed out after {t:g}s (TCP connected)"
    except ssl.SSLCertVerificationError as e:
        reason = f"certificate rejected: {e.verify_message}"
    except (ssl.SSLError, OSError) as e:
        reason = f"TLS handshake failed: {e}"
    writer.transport.abort()
    raise UpstreamError(reason)
