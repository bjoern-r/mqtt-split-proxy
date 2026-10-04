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


@pytest.fixture(scope="session")
def cloud(certs, tmp_path_factory):
    d = tmp_path_factory.mktemp("cloud")
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


@pytest.fixture
async def proxy(certs, cloud, local, request):
    overrides = getattr(request, "param", {})
    port = free_port()
    cfg = from_dict({
        "listen": {"host": "127.0.0.1", "port": port,
                   "cert": str(certs / "server.crt"), "key": str(certs / "server.key")},
        "upstream": {"host": "localhost", "port": cloud.tls_port, "address": "127.0.0.1",
                     "verify": True, "cafile": str(certs / "ca.crt")},
        "local_broker": {"host": "127.0.0.1", "port": local.port,
                         "queue_size": overrides.get("queue_size", 1000)},
        "stats_interval": 3600,
        "log_credentials": overrides.get("log_credentials", False),
    })
    stop = asyncio.Event()
    started = asyncio.get_running_loop().create_future()
    task = asyncio.create_task(serve(cfg, stop, started))
    p, sink, _server = await asyncio.wait_for(started, 5)
    await wait_for(lambda: sink.connected, 10, "local sink connected")
    p.port = port
    yield p
    stop.set()
    await asyncio.wait_for(task, 10)


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
