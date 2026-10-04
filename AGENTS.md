# Guidelines for coding agents

A transparent MQTT/TLS proxy. It terminates a device's TLS connection, relays the
MQTT stream unchanged to the real vendor broker, and copies device→cloud PUBLISHes
to a local Mosquitto. See `README.md` for what it does and how it is deployed.

## Layout

| File | Role |
|---|---|
| `mqtt_split_proxy/mqtt_codec.py` | Pure framing + CONNECT/PUBLISH decoding; raises `ProtocolError` |
| `mqtt_split_proxy/session.py` | One device connection: two pumps (up = packet-framed + tap, down = byte copy) |
| `mqtt_split_proxy/upstream.py` | Resolve the real broker via a clean resolver; verified TLS connect |
| `mqtt_split_proxy/local_sink.py` | Bounded queue + aiomqtt publisher with reconnect |
| `mqtt_split_proxy/config.py` | Dataclasses + YAML loader (unknown keys are errors) |
| `mqtt_split_proxy/__main__.py` | CLI, TLS listener, stats loop, signal handling |

## Invariants: do not break these

1. **The cloud path is never modified.** Bytes from the device go upstream exactly as
   received, and cloud→device is a plain byte copy. Never build, rewrite, reorder or
   drop packets on either path. Packet IDs, QoS handshakes, sessions and v5
   properties must stay end-to-end between the device and the cloud.
2. **The tap must not affect relaying.** Forward first, then parse. A decode error
   in the local copy is counted and logged, and relaying continues. Only a broken
   fixed header, which makes framing impossible, may close the session.
3. **The local sink never blocks.** `LocalSink.offer()` uses `put_nowait` and drops the
   message when the queue is full. Never `await` on Mosquitto from a session.
4. **Upstream TLS stays verified by default**, and upstream resolution must bypass the
   LAN DNS override. Otherwise the proxy connects to itself.
5. **Credentials:** never log or `repr()` the password. `ConnectInfo.password` has
   `repr=False`. The only exception is the explicit, off-by-default `log_credentials`
   option.
6. **v5 Topic Aliases** are per connection and per direction. Keep `alias_map` in
   sync even for PUBLISHes that are too large to copy.

## Development

```sh
uv venv && uv pip install -e '.[dev]'
.venv/bin/pytest -q tests/test_codec.py   # fast, pure
.venv/bin/pytest -q tests/                # full suite (~10 s)
```

- The E2E tests (`tests/test_e2e.py`) need `mosquitto_pub`, `openssl`, and either a
  `mosquitto` binary or Docker with `eclipse-mosquitto:2` pulled. Without them the
  tests are skipped, not failed, so check that they actually ran.
- Python ≥ 3.11 with asyncio only: no threads, and no blocking calls in the event loop.
- Codec functions stay pure (bytes in, dataclass out). Unit-test new parsing in
  `tests/test_codec.py`, and test behaviour that crosses the proxy in `tests/test_e2e.py`.
- New config keys: add them to the dataclass in `config.py`, to `config.example.yaml`
  with a comment, and to the README if users need to know about them.
- Match the existing style: type hints, small functions, short comments that explain why.
- Every change needs the tests to pass. Add a test for each bug fix.

## Commits

- Make small, focused commits with imperative subject lines.
- End every commit message with exactly this trailer and no model name:

  ```
  Co-Authored-By: AI coding agent <noreply@example.com>
  ```
- Never commit `config.yaml`, `certs/*.crt`/`*.key`, or real device credentials.
