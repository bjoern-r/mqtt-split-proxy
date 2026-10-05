"""Pick the upstream broker for a device from its SNI and CONNECT."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass

from .config import Config, MatchConfig, UpstreamConfig


@dataclass(frozen=True)
class _Rule:
    sni: tuple[str, ...] | None
    port: frozenset[int] | None
    client_id: re.Pattern[str] | None
    username: re.Pattern[str] | None

    @classmethod
    def compile(cls, m: MatchConfig) -> _Rule:
        sni = tuple(p.lower() for p in m.sni) if m.sni is not None else None
        port = frozenset(m.port) if m.port is not None else None
        return cls(sni, port,
                   re.compile(m.client_id) if m.client_id is not None else None,
                   re.compile(m.username) if m.username is not None else None)

    def matches_sni(self, sni: str | None) -> bool:
        if self.sni is None:
            return True
        return sni is not None and any(fnmatch.fnmatchcase(sni.lower(), p) for p in self.sni)

    def matches(self, sni: str | None, port: int | None, client_id: str,
                username: str | None) -> bool:
        if not self.matches_sni(sni):
            return False
        if self.port is not None and port not in self.port:
            return False
        if self.client_id is not None and not self.client_id.search(client_id):
            return False
        if self.username is not None and (username is None
                                          or not self.username.search(username)):
            return False
        return True


class Router:
    def __init__(self, cfg: Config):
        self.upstreams = cfg.upstreams
        self.default = next((u for u in cfg.upstreams if u.name == cfg.default), None)
        self._rules = [(u, [_Rule.compile(m) for m in u.match]) for u in cfg.upstreams]

    def select(self, sni: str | None, client_id: str, username: str | None,
               port: int | None = None) -> UpstreamConfig | None:
        """First upstream with a matching rule, else the default (may be None).

        ``port`` is the proxy port the device connected to.
        """
        for up, rules in self._rules:
            if any(r.matches(sni, port, client_id, username) for r in rules):
                return up
        return self.default

    def for_sni(self, sni: str) -> UpstreamConfig | None:
        """Upstream whose SNI-only conditions match; used to pick the server cert
        during the handshake, before the CONNECT is known."""
        for up, rules in self._rules:
            if any(r.sni is not None and r.matches_sni(sni) for r in rules):
                return up
        return None
