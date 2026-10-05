"""upstream.connect error reporting: each failure names the phase that broke."""

import asyncio
import shutil
import socket
import ssl
import subprocess
from pathlib import Path

import pytest

from mqtt_split_proxy import upstream
from mqtt_split_proxy.config import UpstreamConfig

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def selfsigned(tmp_path_factory) -> Path:
    if not shutil.which("openssl"):
        pytest.skip("needs openssl")
    d = tmp_path_factory.mktemp("upstream_cert")
    subprocess.run(["sh", str(ROOT / "certs" / "gen_selfsigned.sh"), "localhost", str(d), "1"],
                   check=True, capture_output=True)
    return d


def up(port: int, **kw) -> UpstreamConfig:
    return UpstreamConfig(host="localhost", port=port, address="127.0.0.1",
                          connect_timeout=0.5, **kw)


async def serve(handler, ssl_ctx=None):
    server = await asyncio.start_server(handler, "127.0.0.1", 0, ssl=ssl_ctx)
    return server, server.sockets[0].getsockname()[1]


async def test_tcp_refused():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]  # bound but not listening
        cfg = up(port)
        with pytest.raises(upstream.UpstreamError, match="TCP connect failed"):
            await upstream.connect(cfg, upstream.make_client_context(cfg))


async def test_tls_handshake_timeout():
    async def silent(r, w):
        await asyncio.sleep(5)  # accept TCP, never answer the ClientHello
    server, port = await serve(silent)
    async with server:
        cfg = up(port)
        with pytest.raises(upstream.UpstreamError,
                           match=r"TLS handshake timed out after 0.5s \(TCP connected\)"):
            await upstream.connect(cfg, upstream.make_client_context(cfg))


async def test_certificate_rejected_names_reason(selfsigned):
    sctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    sctx.load_cert_chain(selfsigned / "server.crt", selfsigned / "server.key")

    async def h(r, w):
        await r.read()
    server, port = await serve(h, sctx)
    async with server:
        cfg = up(port)
        with pytest.raises(upstream.UpstreamError, match="certificate rejected: self.signed"):
            await upstream.connect(cfg, upstream.make_client_context(cfg))
        # and with verification off the same server is accepted
        cfg = up(port, verify=False)
        reader, writer = await upstream.connect(cfg, upstream.make_client_context(cfg))
        assert writer.get_extra_info("ssl_object") is not None
        writer.close()
