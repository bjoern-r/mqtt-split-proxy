"""Configuration dataclasses and YAML loader."""

from __future__ import annotations

import dataclasses
import re
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
class MatchConfig:
    """All given conditions must hold. Unset conditions are ignored."""
    sni: str | list[str] | None = None  # glob(s) on the TLS server name, case-insensitive
    client_id: str | None = None        # regex, re.search
    username: str | None = None         # regex, re.search


@dataclass
class UpstreamConfig:
    name: str = ""                      # defaults to host; used as {vendor} in topic_prefix
    host: str = ""
    port: int = 8883
    resolver: str | list[str] | None = "1.1.1.1"
    address: str | None = None
    verify: bool = True
    cafile: str | None = None
    connect_timeout: float = 10.0
    # Any listed rule set selects this upstream.
    match: list[MatchConfig] = field(default_factory=list)
    # Certificate presented to devices whose SNI matches this upstream
    # (optional, falls back to listen.cert/key).
    cert: str | None = None
    key: str | None = None


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
    # Exactly one of `upstream` (single vendor) or `upstreams` may be given in
    # YAML; after loading, `upstreams` always holds the full list.
    upstream: UpstreamConfig | None = None
    upstreams: list[UpstreamConfig] = field(default_factory=list)
    default: str | None = None          # upstream name for devices no rule matches
    local_broker: LocalBrokerConfig = field(default_factory=LocalBrokerConfig)
    connect_timeout: float = 30.0
    tap_max_packet: int = 1024 * 1024
    stats_interval: float = 60.0
    log_level: str = "INFO"
    log_credentials: bool = False


# (dataclass, field) -> (nested dataclass, is_list)
_NESTED: dict[tuple[type, str], tuple[type, bool]] = {
    (Config, "listen"): (ListenConfig, False),
    (Config, "upstream"): (UpstreamConfig, False),
    (Config, "upstreams"): (UpstreamConfig, True),
    (Config, "local_broker"): (LocalBrokerConfig, False),
    (UpstreamConfig, "match"): (MatchConfig, True),
}


def _build(cls: type, data: Any, where: str) -> Any:
    data = data or {}
    if not isinstance(data, dict):
        raise ConfigError(f"{where}: expected a mapping")
    known = {f.name for f in dataclasses.fields(cls)}
    unknown = set(data) - known
    if unknown:
        raise ConfigError(f"{where}: unknown keys {sorted(unknown)}")
    kwargs = {}
    for name, value in data.items():
        nested = _NESTED.get((cls, name))
        if nested is None:
            kwargs[name] = value
            continue
        sub, is_list = nested
        if not is_list:
            kwargs[name] = _build(sub, value, f"{where}.{name}")
            continue
        if isinstance(value, dict):  # a single mapping is a one-element list
            value = [value]
        if not isinstance(value, list):
            raise ConfigError(f"{where}.{name}: expected a list")
        kwargs[name] = [_build(sub, v, f"{where}.{name}[{i}]") for i, v in enumerate(value)]
    return cls(**kwargs)


def _resolve_path(base: Path, p: str | None) -> str | None:
    if p is None:
        return None
    path = Path(p).expanduser()
    return str(path if path.is_absolute() else base / path)


def _check_upstream(up: UpstreamConfig, where: str) -> None:
    if not up.host:
        raise ConfigError(f"{where}.host is required")
    if (up.cert is None) != (up.key is None):
        raise ConfigError(f"{where}: cert and key must be given together")
    for i, m in enumerate(up.match):
        if m.sni is None and m.client_id is None and m.username is None:
            raise ConfigError(f"{where}.match[{i}]: empty rule (would match everything)")
        if isinstance(m.sni, str):
            m.sni = [m.sni]
        for key in ("client_id", "username"):
            pattern = getattr(m, key)
            if pattern is not None:
                try:
                    re.compile(pattern)
                except re.error as e:
                    raise ConfigError(f"{where}.match[{i}].{key}: bad regex: {e}") from None


def from_dict(data: dict[str, Any], base_dir: Path | None = None) -> Config:
    cfg: Config = _build(Config, data, "config")

    if cfg.upstream is not None and cfg.upstreams:
        raise ConfigError("give either `upstream` or `upstreams`, not both")
    if cfg.upstream is not None:
        cfg.upstreams = [cfg.upstream]
        cfg.upstream = None
    if not cfg.upstreams:
        raise ConfigError("no upstream configured")

    names = set()
    for i, up in enumerate(cfg.upstreams):
        where = f"config.upstreams[{i}]"
        _check_upstream(up, where)
        up.name = up.name or up.host
        if up.name in names:
            raise ConfigError(f"{where}: duplicate upstream name {up.name!r}")
        names.add(up.name)
    if cfg.default is None and len(cfg.upstreams) == 1:
        cfg.default = cfg.upstreams[0].name
    if cfg.default is not None and cfg.default not in names:
        raise ConfigError(f"default: unknown upstream {cfg.default!r}")

    if cfg.local_broker.qos not in (0, 1, 2):
        raise ConfigError("local_broker.qos must be 0, 1 or 2")
    try:
        cfg.local_broker.topic_prefix.format(vendor="v", client_id="c", username="u")
    except (KeyError, IndexError, ValueError) as e:
        raise ConfigError(f"local_broker.topic_prefix: bad placeholder {e} "
                          "(allowed: {vendor}, {client_id}, {username})") from None
    if base_dir is not None:
        cfg.listen.cert = _resolve_path(base_dir, cfg.listen.cert)
        cfg.listen.key = _resolve_path(base_dir, cfg.listen.key)
        for up in cfg.upstreams:
            up.cafile = _resolve_path(base_dir, up.cafile)
            up.cert = _resolve_path(base_dir, up.cert)
            up.key = _resolve_path(base_dir, up.key)
    return cfg


def load(path: str | Path) -> Config:
    path = Path(path)
    with path.open() as fh:
        data = yaml.safe_load(fh) or {}
    return from_dict(data, path.resolve().parent)
