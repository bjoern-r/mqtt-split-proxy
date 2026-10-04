# mqtt-split-proxy

Terminates the sensor's TLS connection, relays it byte-for-byte to the real
vendor broker (same CONNECT, same credentials), and copies every device→cloud
PUBLISH to a local Mosquitto under `vendor/<client_id>/<topic>`.

```
device ──TLS(self-signed)──► proxy ──TLS(verified)──► vendor cloud
                               │ copy PUBLISH (non-blocking)
                               ▼
                         local Mosquitto
```

Packets on the cloud path are never rebuilt or rewritten, so QoS handshakes, packet IDs,
keepalive, sessions and MQTT 5 properties stay end-to-end between device and cloud.
If the local broker is down or slow, copies are queued up to `queue_size` and then
dropped. The cloud path never waits on Mosquitto.

## Setup

```sh
uv venv && uv pip install -e '.[dev]'       # or: python -m venv .venv && .venv/bin/pip install -e '.[dev]'
certs/gen_selfsigned.sh mqtt.vendor.example  # CN/SAN = vendor hostname
cp config.example.yaml config.yaml           # set upstream.host, resolver/address
python -m mqtt_split_proxy -c config.yaml
```

1. **DNS override** on the LAN resolver, e.g. dnsmasq
   `address=/mqtt.vendor.example/192.168.x.y`, or a Pi-hole/router local DNS entry.
   The proxy itself must *not* use that override. Set `upstream.resolver` to a public
   resolver or pin `upstream.address`.
2. **Service:** `deploy/mqtt-split-proxy.service` (systemd, expects the project in
   `/opt/mqtt-split-proxy` and config in `/etc/mqtt-split-proxy/`), or `deploy/Dockerfile`.
3. **Consume:** `mosquitto_sub -t 'vendor/#' -v`, Home Assistant, Node-RED, …

## Several vendors

One instance can serve devices of different vendors. Point every vendor hostname at
the proxy in DNS and replace `upstream:` with an `upstreams:` list (see
`config.example.yaml`). Each device goes to the first upstream with a matching rule,
or else to `default`. If there's no default, unmatched devices are disconnected and
counted as `unrouted` in the stats.

Rules can match on:
- `sni`: the hostname the device asked for in the TLS handshake (glob)
- `client_id` and `username`: regexes on the device's CONNECT

All conditions in a rule must hold, and any rule in a `match` list selects the upstream.
Some devices send no SNI, so add a `client_id` or `username` rule for those.

Use `{vendor}` in `local_broker.topic_prefix` (e.g. `"{vendor}/{client_id}/"`) to keep
the local topics apart. An upstream can also set its own `cert`/`key`, which is shown
to devices whose SNI matches it.

The device's username and password pass through the proxy in cleartext. By default the
password is never logged and the username appears only at DEBUG level. For debugging,
`log_credentials: true` (or `--log-credentials`) logs both at INFO for every CONNECT;
turn it off again afterwards. Bind `listen.host` to the LAN interface,
and keep `upstream.verify: true`.

## Tests

```sh
pytest tests/test_codec.py tests/test_routing.py   # pure unit tests
pytest tests/test_e2e.py     # needs mosquitto (or Docker + eclipse-mosquitto:2), mosquitto_pub, openssl
```

The E2E suite starts a fake "cloud" Mosquitto (TLS + password auth, test CA), a "local"
Mosquitto, and the proxy in-process. It checks QoS 0/1/2 over 3.1.1 and 5.0, retain,
v5 topic aliases plus a 300 kB payload, that a bad-password CONNACK reaches the client,
that cloud delivery continues while the local broker is down, and routing between two
fake vendor clouds by SNI and by client_id, including per-vendor certificates.

## Known limits

- Only device→cloud PUBLISHes are copied. Cloud→device traffic is relayed but not tapped.
- QoS 1/2 retransmissions (DUP) are copied again, so local delivery is at-least-once.
- PUBLISHes larger than `tap_max_packet` are relayed but not copied.
