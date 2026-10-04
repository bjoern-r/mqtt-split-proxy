import asyncio

import pytest

from mqtt_split_proxy import mqtt_codec as c


# --- builders (test-only) ---------------------------------------------------

def s(text: str) -> bytes:
    b = text.encode()
    return len(b).to_bytes(2, "big") + b


def b(data: bytes) -> bytes:
    return len(data).to_bytes(2, "big") + data


def props(*items: bytes) -> bytes:
    body = b"".join(items)
    return c.encode_varint(len(body)) + body


def packet(ptype: int, flags: int, body: bytes) -> bytes:
    return bytes([(ptype << 4) | flags]) + c.encode_varint(len(body)) + body


def connect_body(version=4, client_id="dev-1", username="U", password=b"P",
                 will=None, keepalive=60, v5props=b""):
    flags = 0x02
    payload = s(client_id)
    if will:
        flags |= 0x04 | ((will.get("qos", 0)) << 3)
        if version == 5:
            payload += props()
        payload += s(will["topic"]) + b(will["payload"])
    if username is not None:
        flags |= 0x80
        payload += s(username)
    if password is not None:
        flags |= 0x40
        payload += b(password)
    name = "MQIsdp" if version == 3 else "MQTT"
    vh = s(name) + bytes([version, flags]) + keepalive.to_bytes(2, "big")
    if version == 5:
        vh += props(v5props)
    return vh + payload


def publish(topic, payload, qos=0, retain=False, version=4, pid=1, pprops=b""):
    flags = (qos << 1) | int(retain)
    body = s(topic)
    if qos:
        body += pid.to_bytes(2, "big")
    if version == 5:
        body += props(pprops)
    return flags, body + payload


def alias(n: int) -> bytes:
    return bytes([0x23]) + n.to_bytes(2, "big")


async def reader_for(data: bytes) -> asyncio.StreamReader:
    r = asyncio.StreamReader()
    r.feed_data(data)
    r.feed_eof()
    return r


# --- varint -----------------------------------------------------------------

@pytest.mark.parametrize("value,encoded", [
    (0, b"\x00"),
    (127, b"\x7f"),
    (128, b"\x80\x01"),
    (16383, b"\xff\x7f"),
    (16384, b"\x80\x80\x01"),
    (2097151, b"\xff\xff\x7f"),
    (2097152, b"\x80\x80\x80\x01"),
    (268435455, b"\xff\xff\xff\x7f"),
])
def test_varint_roundtrip(value, encoded):
    assert c.encode_varint(value) == encoded
    assert c.decode_varint(encoded + b"junk") == (value, len(encoded))


def test_varint_too_long():
    with pytest.raises(c.ProtocolError):
        c.decode_varint(b"\xff\xff\xff\xff\x01")
    with pytest.raises(c.ProtocolError):
        c.decode_varint(b"\x80")
    with pytest.raises(ValueError):
        c.encode_varint(268435456)


@pytest.mark.parametrize("length", [0, 127, 128, 16383, 16384, 200_000])
async def test_read_packet_framing(length):
    body = bytes(range(256)) * (length // 256) + bytes(length % 256)
    raw = packet(c.PUBLISH, 0, body)
    r = await reader_for(raw + packet(c.DISCONNECT, 0, b""))
    p = await c.read_packet(r)
    assert (p.type, p.flags, p.raw, p.body) == (c.PUBLISH, 0, raw, body)
    p2 = await c.read_packet(r)
    assert p2.type == c.DISCONNECT and p2.raw == b"\xe0\x00"
    with pytest.raises(asyncio.IncompleteReadError):
        await c.read_packet(r)


async def test_read_packet_limits():
    with pytest.raises(c.ProtocolError):
        await c.read_packet(await reader_for(b"\x30\xff\xff\xff\xff\x01"))
    with pytest.raises(c.ProtocolError):
        await c.read_packet(await reader_for(packet(3, 0, b"x" * 100)), max_len=99)
    with pytest.raises(asyncio.IncompleteReadError):
        await c.read_packet(await reader_for(b"\x30\x05abc"))


# --- CONNECT ----------------------------------------------------------------

@pytest.mark.parametrize("version", [3, 4, 5])
def test_parse_connect(version):
    body = connect_body(version=version, client_id="sensor-42", username="user",
                        password=b"secret", keepalive=30,
                        will={"topic": "lwt", "payload": b"gone", "qos": 1},
                        v5props=bytes([0x11]) + (60).to_bytes(4, "big")
                        + bytes([0x26]) + s("k") + s("v"))
    info = c.parse_connect(body)
    assert info == c.ConnectInfo(version, "sensor-42", "user", 30, True)
    assert "secret" not in repr(info)


def test_parse_connect_no_credentials():
    info = c.parse_connect(connect_body(client_id="", username=None, password=None))
    assert info.client_id == "" and info.username is None


def test_parse_connect_bad():
    with pytest.raises(c.ProtocolError):
        c.parse_connect(s("HTTP") + b"\x04\x02\x00\x3c")
    with pytest.raises(c.ProtocolError):
        c.parse_connect(connect_body()[:-3])


# --- PUBLISH ----------------------------------------------------------------

@pytest.mark.parametrize("version", [4, 5])
@pytest.mark.parametrize("qos", [0, 1, 2])
@pytest.mark.parametrize("retain", [False, True])
def test_parse_publish(version, qos, retain):
    flags, body = publish("sensor/temp", b"21.5", qos=qos, retain=retain, version=version,
                          pprops=bytes([0x01, 0x01]) + bytes([0x03]) + s("text/plain"))
    pub = c.parse_publish(flags, body, version, {})
    assert pub == c.PublishInfo("sensor/temp", b"21.5", qos, retain, False)


def test_parse_publish_empty_payload_and_dup():
    flags, body = publish("t", b"", qos=1)
    pub = c.parse_publish(flags | 0x08, body, 4)
    assert pub.payload == b"" and pub.dup


def test_parse_publish_v5_topic_alias():
    amap: dict[int, str] = {}
    f, body = publish("a/b", b"1", version=5, pprops=alias(3))
    assert c.parse_publish(f, body, 5, amap).topic == "a/b"
    assert amap == {3: "a/b"}
    f, body = publish("", b"2", qos=1, version=5, pprops=alias(3))
    pub = c.parse_publish(f, body, 5, amap)
    assert (pub.topic, pub.payload, pub.qos) == ("a/b", b"2", 1)
    # redefine alias
    f, body = publish("c/d", b"3", version=5, pprops=alias(3))
    c.parse_publish(f, body, 5, amap)
    f, body = publish("", b"4", version=5, pprops=alias(3))
    assert c.parse_publish(f, body, 5, amap).topic == "c/d"


def test_parse_publish_v5_alias_errors():
    f, body = publish("", b"x", version=5, pprops=alias(7))
    with pytest.raises(c.ProtocolError, match="unknown topic alias"):
        c.parse_publish(f, body, 5, {})
    f, body = publish("", b"x", version=5)
    with pytest.raises(c.ProtocolError, match="empty topic"):
        c.parse_publish(f, body, 5, {})
    f, body = publish("t", b"x", version=5, pprops=alias(0))
    with pytest.raises(c.ProtocolError):
        c.parse_publish(f, body, 5, {})


def test_parse_publish_v4_payload_not_mistaken_for_props():
    # In 3.1.1 there is no property block: payload starting with 0x23 stays payload.
    f, body = publish("t", b"\x03\x23\x00\x01", version=4)
    assert c.parse_publish(f, body, 4).payload == b"\x03\x23\x00\x01"


def test_parse_publish_bad():
    with pytest.raises(c.ProtocolError):
        c.parse_publish(0x06, s("t") + b"\x00\x01", 4)  # QoS 3
    with pytest.raises(c.ProtocolError):
        c.parse_publish(0, b"\x00\x05ab", 4)
    with pytest.raises(c.ProtocolError):
        c.parse_publish(0, b"\x00\x02\xff\xfe", 4)  # invalid UTF-8
    with pytest.raises(c.ProtocolError):
        c.parse_publish(0, s("t") + props(b"\x7f\x00"), 5, {})  # unknown property
