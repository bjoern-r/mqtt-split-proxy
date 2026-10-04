"""Minimal MQTT 3.1/3.1.1/5.0 framing and CONNECT/PUBLISH decoding.

Only what the proxy needs: split the byte stream into packets and look inside
CONNECT and PUBLISH. Everything here is read-only; packets are never rebuilt.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

CONNECT = 1
CONNACK = 2
PUBLISH = 3
DISCONNECT = 14

MAX_REMAINING_LENGTH = 268_435_455


class ProtocolError(Exception):
    pass


@dataclass(frozen=True)
class Header:
    type: int
    flags: int
    remaining_length: int
    raw: bytes  # fixed header bytes as received


@dataclass(frozen=True)
class Packet:
    type: int
    flags: int
    raw: bytes   # complete packet as received (fixed header + body)
    body: bytes  # variable header + payload


@dataclass(frozen=True)
class ConnectInfo:
    version: int  # protocol level: 3 = 3.1, 4 = 3.1.1, 5 = 5.0
    client_id: str
    username: str | None
    keepalive: int
    clean: bool
    # Kept out of repr() so it can't leak through casual logging.
    password: bytes | None = field(default=None, repr=False)


@dataclass(frozen=True)
class PublishInfo:
    topic: str
    payload: bytes
    qos: int
    retain: bool
    dup: bool


# --- varint -----------------------------------------------------------------

def encode_varint(value: int) -> bytes:
    if not 0 <= value <= MAX_REMAINING_LENGTH:
        raise ValueError(f"varint out of range: {value}")
    out = bytearray()
    while True:
        byte, value = value % 128, value // 128
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def decode_varint(buf: bytes, pos: int = 0) -> tuple[int, int]:
    """Return (value, new_pos)."""
    value = 0
    for i in range(4):
        if pos >= len(buf):
            raise ProtocolError("truncated varint")
        byte = buf[pos]
        pos += 1
        value += (byte & 0x7F) << (7 * i)
        if not byte & 0x80:
            return value, pos
    raise ProtocolError("varint longer than 4 bytes")


# --- stream framing ---------------------------------------------------------

async def read_header(reader: asyncio.StreamReader) -> Header:
    """Read one fixed header. Raises IncompleteReadError on EOF."""
    first = await reader.readexactly(1)
    raw = bytearray(first)
    value = 0
    for i in range(4):
        b = (await reader.readexactly(1))[0]
        raw.append(b)
        value += (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return Header(first[0] >> 4, first[0] & 0x0F, value, bytes(raw))
    raise ProtocolError("remaining length longer than 4 bytes")


async def read_packet(reader: asyncio.StreamReader,
                      max_len: int = MAX_REMAINING_LENGTH) -> Packet:
    hdr = await read_header(reader)
    if hdr.remaining_length > max_len:
        raise ProtocolError(f"packet too large: {hdr.remaining_length} > {max_len}")
    body = await reader.readexactly(hdr.remaining_length)
    return Packet(hdr.type, hdr.flags, hdr.raw + body, body)


# --- field helpers ----------------------------------------------------------

class _Buf:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0):
        self.data = data
        self.pos = pos

    def take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise ProtocolError("truncated packet")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int.from_bytes(self.take(2), "big")

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def varint(self) -> int:
        value, self.pos = decode_varint(self.data, self.pos)
        return value

    def binary(self) -> bytes:
        return self.take(self.u16())

    def string(self) -> str:
        try:
            return self.binary().decode("utf-8")
        except UnicodeDecodeError as e:
            raise ProtocolError("invalid UTF-8 string") from e

    def rest(self) -> bytes:
        chunk = self.data[self.pos:]
        self.pos = len(self.data)
        return chunk


# MQTT 5 property identifier -> value type
_BYTE, _U16, _U32, _VARINT, _STR, _BIN, _PAIR = range(7)
_PROPERTY_TYPES = {
    0x01: _BYTE, 0x02: _U32, 0x03: _STR, 0x08: _STR, 0x09: _BIN, 0x0B: _VARINT,
    0x11: _U32, 0x12: _STR, 0x13: _U16, 0x15: _STR, 0x16: _BIN, 0x17: _BYTE,
    0x18: _U32, 0x19: _BYTE, 0x1A: _STR, 0x1C: _STR, 0x1F: _STR, 0x21: _U16,
    0x22: _U16, 0x23: _U16, 0x24: _BYTE, 0x25: _BYTE, 0x26: _PAIR, 0x27: _U32,
    0x28: _BYTE, 0x29: _BYTE, 0x2A: _BYTE,
}
PROP_TOPIC_ALIAS = 0x23


def _read_properties(buf: _Buf) -> dict[int, object]:
    """Parse a v5 property block. Repeated properties keep the last value."""
    length = buf.varint()
    end = buf.pos + length
    if end > len(buf.data):
        raise ProtocolError("truncated properties")
    props: dict[int, object] = {}
    while buf.pos < end:
        pid = buf.varint()
        kind = _PROPERTY_TYPES.get(pid)
        if kind is None:
            raise ProtocolError(f"unknown property 0x{pid:02x}")
        if kind == _BYTE:
            props[pid] = buf.u8()
        elif kind == _U16:
            props[pid] = buf.u16()
        elif kind == _U32:
            props[pid] = buf.u32()
        elif kind == _VARINT:
            props[pid] = buf.varint()
        elif kind == _STR:
            props[pid] = buf.string()
        elif kind == _BIN:
            props[pid] = buf.binary()
        else:
            props[pid] = (buf.string(), buf.string())
    if buf.pos != end:
        raise ProtocolError("property block length mismatch")
    return props


# --- packet decoders --------------------------------------------------------

def parse_connect(body: bytes) -> ConnectInfo:
    buf = _Buf(body)
    name = buf.string()
    version = buf.u8()
    if (name, version) not in (("MQIsdp", 3), ("MQTT", 4), ("MQTT", 5)):
        raise ProtocolError(f"unsupported protocol {name!r} level {version}")
    flags = buf.u8()
    if flags & 0x01:
        raise ProtocolError("reserved CONNECT flag set")
    keepalive = buf.u16()
    if version == 5:
        _read_properties(buf)
    client_id = buf.string()
    if flags & 0x04:  # will flag
        if version == 5:
            _read_properties(buf)
        buf.string()   # will topic
        buf.binary()   # will payload
    username = buf.string() if flags & 0x80 else None
    password = buf.binary() if flags & 0x40 else None
    return ConnectInfo(version, client_id, username, keepalive, bool(flags & 0x02), password)


def parse_publish(flags: int, body: bytes, version: int,
                  alias_map: dict[int, str] | None = None) -> PublishInfo:
    """Decode a PUBLISH body.

    For MQTT 5, ``alias_map`` is the per-connection Topic Alias table for this
    direction; it is updated in place.
    """
    qos = (flags >> 1) & 0x03
    if qos == 3:
        raise ProtocolError("invalid QoS 3")
    buf = _Buf(body)
    topic = buf.string()
    if qos:
        buf.u16()  # packet identifier
    if version == 5:
        props = _read_properties(buf)
        alias = props.get(PROP_TOPIC_ALIAS)
        if alias is not None:
            if alias_map is None:
                raise ProtocolError("topic alias without alias map")
            if not isinstance(alias, int) or alias == 0:
                raise ProtocolError("invalid topic alias 0")
            if topic:
                alias_map[alias] = topic
            else:
                try:
                    topic = alias_map[alias]
                except KeyError:
                    raise ProtocolError(f"unknown topic alias {alias}") from None
    if not topic:
        raise ProtocolError("empty topic")
    return PublishInfo(topic, buf.rest(), qos, bool(flags & 0x01), bool(flags & 0x08))
