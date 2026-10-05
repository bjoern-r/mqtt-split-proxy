"""End-to-end: fake cloud Mosquitto (TLS + auth) <- proxy -> local Mosquitto.

Needs a `mosquitto` binary on PATH or Docker (eclipse-mosquitto:2 image),
plus `mosquitto_pub` and `openssl`.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import time
from pathlib import Path

import aiomqtt
import pytest
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.properties import Properties

from mqtt_split_proxy.__main__ import serve
from mqtt_split_proxy.config import from_dict
from mqtt_split_proxy.mqtt_codec import encode_varint

ROOT = Path(__file__).resolve().parent.parent
USER, PASSWORD = "U", "P"
CLIENT_ID = "sensor-1"
DOCKER_IMAGE = "eclipse-mosquitto:2"


def _have_docker() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE],
                          capture_output=True).returncode == 0


USE_BINARY = shutil.which("mosquitto") is not None
pytestmark = pytest.mark.skipif(
    not (USE_BINARY or _have_docker()) or not shutil.which("mosquitto_pub")
    or not shutil.which("openssl"),
    reason="needs mosquitto (or docker + eclipse-mosquitto:2), mosquitto_pub and openssl")


# --- helpers ----------------------------------------------------------------

def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_port(port: int, timeout: float = 15) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with contextlib.suppress(OSError), socket.create_connection(("127.0.0.1", port), 0.5):
            return
        time.sleep(0.1)
    raise TimeoutError(f"port {port} not open")


def mosquitto_hash(password: str) -> str:
    """Mosquitto 2 password file format ($7$ = PBKDF2-SHA512)."""
    salt = secrets.token_bytes(12)
    digest = hashlib.pbkdf2_hmac("sha512", password.encode(), salt, 101, 64)
    return f"$7$101${base64.b64encode(salt).decode()}${base64.b64encode(digest).decode()}"


class Broker:
    def __init__(self, workdir: Path, conf: str, ports: list[int], mounts: tuple[Path, ...] = ()):
        self.workdir, self.ports = workdir, ports
        (workdir / "mosquitto.conf").write_text(conf)
        if USE_BINARY:
            self.proc = subprocess.Popen(
                ["mosquitto", "-c", str(workdir / "mosquitto.conf")], cwd=workdir,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.container = None
        else:
            self.proc = None
            self.container = subprocess.check_output([
                "docker", "run", "-d", "--network", "host",
                "--user", f"{os.getuid()}:{os.getgid()}",
                *(f"-v{m}:{m}:ro" for m in mounts),
                "-v", f"{workdir}:{workdir}", "-w", str(workdir),
                DOCKER_IMAGE, "mosquitto", "-c", str(workdir / "mosquitto.conf"),
            ], text=True).strip()
        try:
            for p in ports:
                wait_port(p)
        except TimeoutError as e:
            logs = (subprocess.run(["docker", "logs", self.container], capture_output=True,
                                   text=True).stderr if self.container else "")
            self.stop()
            raise RuntimeError(f"mosquitto did not start: {e}\n{logs}") from None

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            self.proc.wait(10)
        if self.container:
            subprocess.run(["docker", "rm", "-f", self.container], capture_output=True)
            self.container = None


async def wait_for(pred, timeout: float = 10, what: str = "condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"timeout waiting for {what}")


@contextlib.asynccontextmanager
async def collector(port: int, topic: str = "#", **kw):
    """Subscribe and collect (topic, payload, retain) tuples in a list."""
    got: list[tuple[str, bytes, bool]] = []
    async with aiomqtt.Client("127.0.0.1", port, **kw) as client:
        await client.subscribe(topic, qos=1)

        async def loop():
            async for m in client.messages:
                got.append((str(m.topic), bytes(m.payload), bool(m.retain)))

        task = asyncio.create_task(loop())
        try:
            yield got
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


# --- fixtures ---------------------------------------------------------------

@pytest.fixture(scope="session")
def certs(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("certs")

    def ossl(*args):
        subprocess.run(["openssl", *args], cwd=d, check=True, capture_output=True)

    ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj", "/CN=Test CA",
         "-addext", "basicConstraints=critical,CA:TRUE",
         "-addext", "keyUsage=critical,keyCertSign,cRLSign",
         "-keyout", "ca.key", "-out", "ca.crt")
    ossl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
         "-keyout", "cloud.key", "-out", "cloud.csr")
    (d / "ext.cnf").write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
        "authorityKeyIdentifier=keyid\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\n"
        "extendedKeyUsage=serverAuth\n")
    ossl("x509", "-req", "-in", "cloud.csr", "-CA", "ca.crt", "-CAkey", "ca.key",
         "-CAcreateserial", "-days", "2", "-extfile", "ext.cnf", "-out", "cloud.crt")
    # The proxy's own cert comes from the shipped script.
    subprocess.run(["sh", str(ROOT / "certs" / "gen_selfsigned.sh"), "localhost", str(d), "2"],
                   check=True, capture_output=True)
    for f in d.iterdir():
        f.chmod(0o644)
    return d


def make_cloud(certs: Path, d: Path) -> Broker:
    tls_port, plain_port = free_port(), free_port()
    (d / "passwd").write_text(f"{USER}:{mosquitto_hash(PASSWORD)}\n")
    (d / "passwd").chmod(0o600)
    conf = f"""
per_listener_settings false
allow_anonymous false
password_file {d}/passwd
persistence false
log_dest stderr
listener {tls_port} 127.0.0.1
certfile {certs}/cloud.crt
keyfile {certs}/cloud.key
listener {plain_port} 127.0.0.1
"""
    b = Broker(d, conf, [tls_port, plain_port], mounts=(certs,))
    b.tls_port, b.plain_port = tls_port, plain_port
    return b


@pytest.fixture(scope="session")
def cloud(certs, tmp_path_factory):
    b = make_cloud(certs, tmp_path_factory.mktemp("cloud"))
    yield b
    b.stop()


@pytest.fixture(scope="session")
def cloud_b(certs, tmp_path_factory):
    """Second fake vendor cloud for routing tests."""
    b = make_cloud(certs, tmp_path_factory.mktemp("cloud_b"))
    yield b
    b.stop()


@pytest.fixture
def local(tmp_path):
    port = free_port()
    b = Broker(tmp_path, f"allow_anonymous true\npersistence false\nlistener {port} 127.0.0.1\n",
               [port])
    b.port = port
    yield b
    b.stop()


def upstream_to(cloud: Broker, certs: Path, **extra) -> dict:
    return {"host": "localhost", "port": cloud.tls_port, "address": "127.0.0.1",
            "verify": True, "cafile": str(certs / "ca.crt"), **extra}


def tls_listener(certs: Path, port: int) -> dict:
    return {"host": "127.0.0.1", "port": port,
            "cert": str(certs / "server.crt"), "key": str(certs / "server.key")}


@contextlib.asynccontextmanager
async def running_proxy(certs: Path, local: Broker, **cfg_data):
    port = free_port()
    cfg = from_dict({
        "listen": tls_listener(certs, port),
        "local_broker": {"host": "127.0.0.1", "port": local.port,
                         **cfg_data.pop("local_broker", {})},
        "stats_interval": 3600,
        **cfg_data,
    })
    stop = asyncio.Event()
    started = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(serve(cfg, stop, started))
    p, sink, _server = await asyncio.wait_for(started, 5)
    await wait_for(lambda: sink.connected, 10, "local sink connected")
    p.port = cfg.listen[0].port
    try:
        yield p
    finally:
        stop.set()
        await asyncio.wait_for(task, 10)


@pytest.fixture
async def proxy(certs, cloud, local, request):
    overrides = getattr(request, "param", {})
    async with running_proxy(
            certs, local, upstream=upstream_to(cloud, certs),
            local_broker={"queue_size": overrides.get("queue_size", 1000)},
            log_credentials=overrides.get("log_credentials", False),
            tap_downstream=overrides.get("tap_downstream", False)) as p:
        yield p


def pub_args(certs: Path, *extra: str) -> list[str]:
    return ["--cafile", str(certs / "server.crt"), "-i", CLIENT_ID, "-u", USER, "-P", PASSWORD,
            *extra]


async def run_pub(proxy, certs, *extra, stdin=None):
    proc = await asyncio.create_subprocess_exec(
        "mosquitto_pub", "-h", "127.0.0.1", "-p", str(proxy.port), "--insecure",
        *pub_args(certs, *extra), stdin=subprocess.PIPE if stdin is not None else None,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out, _ = await asyncio.wait_for(proc.communicate(stdin), 20)
    return proc.returncode, out.decode(errors="replace")


# --- tests ------------------------------------------------------------------

@pytest.mark.parametrize("version", ["mqttv311", "mqttv5"])
@pytest.mark.parametrize("qos", ["0", "1", "2"])
async def test_publish_reaches_cloud_and_local(proxy, cloud, local, certs, version, qos):
    async with collector(cloud.plain_port, username=USER, password=PASSWORD) as at_cloud, \
            collector(local.port) as at_local:
        rc, out = await run_pub(proxy, certs, "-V", version, "-q", qos,
                                "-t", "sensor/temp", "-m", "21.5")
        assert rc == 0, out
        await wait_for(lambda: at_cloud and at_local, what="messages")
    assert at_cloud == [("sensor/temp", b"21.5", False)]
    assert at_local == [(f"vendor/{CLIENT_ID}/sensor/temp", b"21.5", False)]


async def test_retain_flag_preserved(proxy, cloud, local, certs):
    async with collector(local.port) as at_local:
        rc, out = await run_pub(proxy, certs, "-r", "-t", "sensor/hum", "-m", "55")
        assert rc == 0, out
        # retained on the local broker -> a fresh subscriber gets it too
    async with collector(local.port, f"vendor/{CLIENT_ID}/sensor/hum") as fresh:
        await wait_for(lambda: fresh, what="retained message")
    assert fresh == [(f"vendor/{CLIENT_ID}/sensor/hum", b"55", True)]
    # clean up retained message on the cloud
    async with aiomqtt.Client("127.0.0.1", cloud.plain_port, username=USER,
                              password=PASSWORD) as c:
        await c.publish("sensor/hum", b"", retain=True)


async def test_v5_topic_alias_and_large_payload(proxy, cloud, local, certs):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    big = os.urandom(300_000)

    def alias(n):
        p = Properties(PacketTypes.PUBLISH)
        p.TopicAlias = n
        return p

    async with collector(cloud.plain_port, username=USER, password=PASSWORD) as at_cloud, \
            collector(local.port) as at_local:
        async with aiomqtt.Client("127.0.0.1", proxy.port, username=USER, password=PASSWORD,
                                  identifier=CLIENT_ID, tls_context=ctx,
                                  protocol=aiomqtt.ProtocolVersion.V5) as dev:
            await dev.publish("a/b", b"1", qos=1, properties=alias(1))
            await dev.publish("", b"2", qos=1, properties=alias(1))
            await dev.publish("big", big, qos=1)
        await wait_for(lambda: len(at_cloud) == 3 and len(at_local) == 3, what="3 messages")
    assert [(t, p) for t, p, _ in at_cloud] == [("a/b", b"1"), ("a/b", b"2"), ("big", big)]
    pre = f"vendor/{CLIENT_ID}/"
    assert [(t, p) for t, p, _ in at_local] == [(pre + "a/b", b"1"), (pre + "a/b", b"2"),
                                                (pre + "big", big)]


async def test_wrong_password_connack_reaches_client(proxy, cloud, local, certs):
    proc = await asyncio.create_subprocess_exec(
        "mosquitto_pub", "-h", "127.0.0.1", "-p", str(proxy.port), "--insecure",
        "--cafile", str(certs / "server.crt"), "-i", CLIENT_ID, "-u", USER, "-P", "wrong",
        "-t", "x", "-m", "y", stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = (await asyncio.wait_for(proc.communicate(), 20))[0].decode()
    assert proc.returncode != 0
    assert "not authori" in out.lower(), out  # broker's CONNACK made it through


@pytest.mark.parametrize("proxy", [{"queue_size": 2}], indirect=True)
async def test_local_broker_down_does_not_affect_cloud(proxy, cloud, local, certs):
    sink = proxy.sink
    local.stop()
    await wait_for(lambda: not sink.connected or sink.dropped, 5, "sink noticed")
    n = 20
    async with collector(cloud.plain_port, "sensor/#", username=USER,
                         password=PASSWORD) as at_cloud:
        stdin = "".join(f"{i}\n" for i in range(n)).encode()
        rc, out = await run_pub(proxy, certs, "-q", "1", "-t", "sensor/seq", "-l", stdin=stdin)
        assert rc == 0, out
        await wait_for(lambda: len(at_cloud) == n, what=f"{n} cloud messages")
    assert [p for _, p, _ in at_cloud] == [str(i).encode() for i in range(n)]
    assert proxy.stats.tapped == n
    assert sink.dropped >= n - 4


@pytest.mark.parametrize("proxy,shown", [({"log_credentials": True}, True),
                                         ({}, False)], indirect=["proxy"])
async def test_log_credentials_option(proxy, cloud, local, certs, caplog, shown):
    caplog.set_level("DEBUG", logger="mqtt_split_proxy")
    rc, out = await run_pub(proxy, certs, "-t", "x", "-m", "y")
    assert rc == 0, out
    assert (f"username='{USER}' password='{PASSWORD}'" in caplog.text) is shown
    assert ("password=" in caplog.text) is shown


def _insecure_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def cloud_to_device(proxy, cloud, version, messages):
    """Device subscribes through the proxy; the cloud side publishes ``messages``."""
    got: list[tuple[str, bytes]] = []
    async with aiomqtt.Client("127.0.0.1", proxy.port, username=USER, password=PASSWORD,
                              identifier=CLIENT_ID, tls_context=_insecure_ctx(),
                              protocol=version) as dev:
        await dev.subscribe("cmd/#", qos=1)
        async with aiomqtt.Client("127.0.0.1", cloud.plain_port, username=USER,
                                  password=PASSWORD) as vendor:
            for topic, payload in messages:
                await vendor.publish(topic, payload, qos=1)
        async for m in dev.messages:
            got.append((str(m.topic), bytes(m.payload)))
            if len(got) == len(messages):
                break
    return got


@pytest.mark.parametrize("proxy", [{"tap_downstream": True}], indirect=True)
@pytest.mark.parametrize("version", [aiomqtt.ProtocolVersion.V311, aiomqtt.ProtocolVersion.V5])
async def test_cloud_to_device_publish_copied_locally(proxy, cloud, local, certs, version):
    big = os.urandom(300_000)
    messages = [("cmd/led", b"on"), ("cmd/fw", big)]
    async with collector(local.port) as at_local:
        got = await asyncio.wait_for(cloud_to_device(proxy, cloud, version, messages), 20)
        await wait_for(lambda: len(at_local) == 2, what="2 local copies")
    assert got == messages
    pre = f"vendor-down/{CLIENT_ID}/"
    assert [(t, p) for t, p, _ in at_local] == [(pre + "cmd/led", b"on"), (pre + "cmd/fw", big)]
    assert proxy.stats.tapped_down == 2
    assert proxy.stats.tapped == 0


async def test_cloud_to_device_not_copied_by_default(proxy, cloud, local, certs):
    async with collector(local.port) as at_local:
        got = await asyncio.wait_for(
            cloud_to_device(proxy, cloud, aiomqtt.ProtocolVersion.V311, [("cmd/led", b"on")]),
            20)
        await asyncio.sleep(0.5)
    assert got == [("cmd/led", b"on")]
    assert at_local == []
    assert proxy.stats.tapped_down == 0


# --- multi-vendor routing ---------------------------------------------------

def _str(s: str) -> bytes:
    b = s.encode()
    return len(b).to_bytes(2, "big") + b


def _pkt(first: int, body: bytes) -> bytes:
    return bytes([first]) + encode_varint(len(body)) + body


async def raw_publish(port: int, sni: str | None, client_id: str, topic: str, payload: bytes,
                      ctx: ssl.SSLContext | None = None) -> int | None:
    """Minimal MQTT 3.1.1 client with full control over the TLS SNI.

    Returns the CONNACK return code, or None if the proxy closed the connection.
    """
    if ctx is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    r, w = await asyncio.open_connection("127.0.0.1", port, ssl=ctx, server_hostname=sni)
    try:
        w.write(_pkt(0x10, _str("MQTT") + bytes([4, 0xC2]) + (30).to_bytes(2, "big")
                     + _str(client_id) + _str(USER) + _str(PASSWORD)))
        await w.drain()
        connack = await asyncio.wait_for(r.read(4), 10)
        if len(connack) < 4:
            return None
        if connack[3] == 0:
            w.write(_pkt(0x30, _str(topic) + payload) + b"\xe0\x00")  # PUBLISH, DISCONNECT
            await w.drain()
            await asyncio.wait_for(r.read(), 10)  # broker closes after DISCONNECT
        return connack[3]
    finally:
        w.close()
        with contextlib.suppress(Exception):
            await w.wait_closed()


@pytest.fixture(scope="session")
def vendor_b_cert(tmp_path_factory) -> Path:
    d = tmp_path_factory.mktemp("cert_b")
    subprocess.run(["sh", str(ROOT / "certs" / "gen_selfsigned.sh"), "broker.vendor-b.test",
                    str(d), "2"], check=True, capture_output=True)
    return d


@pytest.fixture
async def multi_proxy(certs, cloud, cloud_b, local, vendor_b_cert):
    async with running_proxy(
            certs, local,
            upstreams=[
                upstream_to(cloud, certs, name="vendor-a",
                            match={"sni": "*.vendor-a.test"}),
                upstream_to(cloud_b, certs, name="vendor-b",
                            match=[{"sni": "broker.vendor-b.test"}, {"client_id": "^VB-"}],
                            cert=str(vendor_b_cert / "server.crt"),
                            key=str(vendor_b_cert / "server.key")),
            ],
            local_broker={"topic_prefix": "{vendor}/{client_id}/"}) as p:
        yield p


@pytest.mark.parametrize("sni,client_id,vendor", [
    ("mqtt.vendor-a.test", "dev-a", "vendor-a"),
    ("broker.vendor-b.test", "dev-b", "vendor-b"),
    (None, "VB-0001", "vendor-b"),                  # no SNI: routed by client_id
])
async def test_routes_to_matching_vendor(multi_proxy, cloud, cloud_b, local,
                                         sni, client_id, vendor):
    kw = {"username": USER, "password": PASSWORD}
    async with collector(cloud.plain_port, "route/#", **kw) as at_a, \
            collector(cloud_b.plain_port, "route/#", **kw) as at_b, \
            collector(local.port, "+/+/route/#") as at_local:
        rc = await raw_publish(multi_proxy.port, sni, client_id, "route/t", b"hello")
        assert rc == 0
        target, other = (at_a, at_b) if vendor == "vendor-a" else (at_b, at_a)
        await wait_for(lambda: target and at_local, what="routed message")
        await asyncio.sleep(0.3)
    assert target == [("route/t", b"hello", False)]
    assert other == []
    assert at_local == [(f"{vendor}/{client_id}/route/t", b"hello", False)]


async def test_unmatched_device_is_rejected_without_default(multi_proxy, cloud, cloud_b):
    rc = await raw_publish(multi_proxy.port, "other.example", "dev-x", "route/t", b"x")
    assert rc is None
    assert multi_proxy.stats.unrouted == 1
    assert multi_proxy.stats.upstream_failures == 0


async def test_per_vendor_certificate_by_sni(multi_proxy, vendor_b_cert, certs):
    def verifying(cafile: Path) -> ssl.SSLContext:
        ctx = ssl.create_default_context(cafile=str(cafile))
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT  # self-signed leaf as trust anchor
        return ctx

    # vendor-b's SNI gets vendor-b's certificate ...
    assert await raw_publish(multi_proxy.port, "broker.vendor-b.test", "dev-b", "route/c", b"1",
                             ctx=verifying(vendor_b_cert / "server.crt")) == 0
    # ... while vendor-a has none configured and gets the listener default.
    with pytest.raises(ssl.SSLCertVerificationError):
        await raw_publish(multi_proxy.port, "mqtt.vendor-a.test", "dev-a", "route/c", b"1",
                          ctx=verifying(vendor_b_cert / "server.crt"))


# --- several listening ports ------------------------------------------------

async def test_listeners_on_several_ports_route_by_port(certs, cloud, cloud_b, local):
    """TLS listener -> vendor-a (TLS cloud); plain 1883-style listener -> vendor-b,
    relayed to vendor-b's plain MQTT port."""
    tls_port, plain_port = free_port(), free_port()
    async with running_proxy(
            certs, local,
            listen=[tls_listener(certs, tls_port),
                    {"host": "127.0.0.1", "port": plain_port, "tls": False}],
            upstreams=[
                upstream_to(cloud, certs, name="vendor-a", match={"port": tls_port}),
                {"name": "vendor-b", "host": "localhost", "address": "127.0.0.1",
                 "port": cloud_b.plain_port, "tls": False, "match": {"port": plain_port}},
            ],
            local_broker={"topic_prefix": "{vendor}/{client_id}/"}) as p:
        kw = {"username": USER, "password": PASSWORD}
        async with collector(cloud.plain_port, "ports/#", **kw) as at_a, \
                collector(cloud_b.plain_port, "ports/#", **kw) as at_b, \
                collector(local.port, "+/+/ports/#") as at_local:
            rc, out = await run_pub(p, certs, "-t", "ports/t", "-m", "via-tls")
            assert rc == 0, out
            proc = await asyncio.create_subprocess_exec(
                "mosquitto_pub", "-h", "127.0.0.1", "-p", str(plain_port), "-i", CLIENT_ID,
                "-u", USER, "-P", PASSWORD, "-t", "ports/t", "-m", "via-plain",
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            out = (await asyncio.wait_for(proc.communicate(), 20))[0].decode()
            assert proc.returncode == 0, out
            await wait_for(lambda: at_a and at_b and len(at_local) == 2, what="both messages")
            await asyncio.sleep(0.3)
    assert at_a == [("ports/t", b"via-tls", False)]
    assert at_b == [("ports/t", b"via-plain", False)]
    assert sorted(at_local) == [(f"vendor-a/{CLIENT_ID}/ports/t", b"via-tls", False),
                                (f"vendor-b/{CLIENT_ID}/ports/t", b"via-plain", False)]
