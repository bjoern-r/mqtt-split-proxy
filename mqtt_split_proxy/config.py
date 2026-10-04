"""Configuration dataclasses and YAML loader."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


class ConfigError(ValueError):
    pass


@dataclass
class ListenConfig:
    host: str | list[str] = "0.0.0.0"
    port: int = 8883
    cert: str = "certs/server.crt"
    key: str = "certs/server.key"
    tls_min_version: str = "TLSv1_2"


@dataclass
class UpstreamConfig:
    host: str = ""
    port: int = 8883
    resolver: str | list[str] | None = "1.1.1.1"
    address: str | None = None
    verify: bool = True
    cafile: str | None = None
    connect_timeout: float = 10.0


@dataclass
class LocalBrokerConfig:
    host: str = "127.0.0.1"
    port: int = 1883
    username: str | None = None
    password: str | None = None
    client_id: str = "mqtt-split-proxy"
    topic_prefix: str = "vendor/{client_id}/"
    qos: int = 0
    strip_retain: bool = False
    queue_size: int = 10000


@dataclass
class Config:
    listen: ListenConfig = field(default_factory=ListenConfig)
    upstream: UpstreamConfig = field(default_factory=UpstreamConfig)
    local_broker: LocalBrokerConfig = field(default_factory=LocalBrokerConfig)
    connect_timeout: float = 30.0
    tap_max_packet: int = 1024 * 1024
    stats_interval: float = 60.0
    log_level: str = "INFO"
    log_credentials: bool = False


def _build(cls: type, data: dict[str, Any] | None, where: str) -> Any:
    data = data or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: expected a mapping")
    known = {f.name: f for f in dataclasses.fields(cls)}
    unknown = set(data) - set(known)
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")
    kwargs = {}
    for name, value in data.items():
        sub = {"listen": ListenConfig, "upstream": UpstreamConfig,
               "local_broker": LocalBrokerConfig}.get(name) if cls is Config else None
        kwargs[name] = _build(sub, value, f"{where}.{name}") if sub else value
    return cls(**kwargs)


def _resolve_path(base: Path, p: str | None) -> str | None:
    if p is None:
        return None
    path = Path(p).expanduser()
    return str(path if path.is_absolute() else base / path)


def from_dict(data: dict[str, Any], base_dir: Path | None = None) -> Config:
    cfg: Config = _build(Config, data, "config")
    if not cfg.upstream.host:
        raise ConfigError("upstream.host is required")
    if cfg.local_broker.qos not in (0, 1, 2):
        raise ConfigError("local_broker.qos must be 0, 1 or 2")
    if base_dir is not None:
        cfg.listen.cert = _resolve_path(base_dir, cfg.listen.cert)
        cfg.listen.key = _resolve_path(base_dir, cfg.listen.key)
        cfg.upstream.cafile = _resolve_path(base_dir, cfg.upstream.cafile)
    return cfg


def load(path: str | Path) -> Config:
    path = Path(path)
    with path.open() as fh:
        data = yaml.safe_load(fh) or {}
    return from_dict(data, path.resolve().parent)
