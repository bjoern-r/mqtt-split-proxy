"""Non-blocking copy of tapped PUBLISHes into the local broker."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import aiomqtt

from .config import LocalBrokerConfig

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class _Item:
    topic: str
    payload: bytes
    retain: bool


class LocalSink:
    def __init__(self, cfg: LocalBrokerConfig):
        self.cfg = cfg
        self.queue: asyncio.Queue[_Item] = asyncio.Queue(maxsize=cfg.queue_size)
        self.ok = 0
        self.dropped = 0
        self.connected = False
        self._pending: _Item | None = None

    @staticmethod
    def _clean(value: str) -> str:
        # Wildcards and separators from IDs must not leak into the topic.
        return value.replace("/", "_").replace("+", "_").replace("#", "_") or "_"

    def topic_for(self, vendor: str, client_id: str, username: str | None, topic: str,
                  down: bool = False) -> str:
        template = self.cfg.topic_prefix_down if down else self.cfg.topic_prefix
        prefix = template.format(
            vendor=self._clean(vendor), client_id=self._clean(client_id),
            username=self._clean(username or ""))
        return prefix + topic

    def offer(self, vendor: str, client_id: str, username: str | None,
              topic: str, payload: bytes, retain: bool, down: bool = False) -> bool:
        """Queue a message for the local broker. Never blocks.

        ``down`` marks a cloud->device message, filed under ``topic_prefix_down``.
        """
        item = _Item(self.topic_for(vendor, client_id, username, topic, down), payload,
                     retain and not self.cfg.strip_retain)
        try:
            self.queue.put_nowait(item)
            return True
        except asyncio.QueueFull:
            self.dropped += 1
            return False

    async def run(self) -> None:
        backoff = 1.0
        while True:
            try:
                async with aiomqtt.Client(
                    self.cfg.host, self.cfg.port,
                    username=self.cfg.username, password=self.cfg.password,
                    identifier=self.cfg.client_id, timeout=10,
                ) as client:
                    self.connected = True
                    backoff = 1.0
                    log.info("connected to local broker %s:%d", self.cfg.host, self.cfg.port)
                    async with asyncio.TaskGroup() as tg:
                        tg.create_task(self._watch(client))
                        tg.create_task(self._publish_loop(client))
            except* aiomqtt.MqttError as eg:
                e = eg.exceptions[0]
                if self.connected:
                    log.warning("local broker connection lost: %s", e)
                else:
                    log.warning("cannot connect to local broker %s:%d: %s",
                                self.cfg.host, self.cfg.port, e)
            finally:
                self.connected = False
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60.0)

    async def _publish_loop(self, client: aiomqtt.Client) -> None:
        while True:
            if self._pending is None:
                self._pending = await self.queue.get()
            item = self._pending
            await client.publish(item.topic, item.payload,
                                 qos=self.cfg.qos, retain=item.retain)
            self._pending = None
            self.ok += 1

    @staticmethod
    async def _watch(client: aiomqtt.Client) -> None:
        # Nothing is subscribed; this only raises MqttError on connection loss,
        # so an idle sink notices a dead broker instead of on the next publish.
        async for _ in client.messages:
            pass
