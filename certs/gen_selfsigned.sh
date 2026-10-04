#!/bin/sh
# Generate the self-signed certificate the proxy presents to the device.
# The device does not validate it, but CN/SAN match the vendor hostname anyway.
#
# usage: certs/gen_selfsigned.sh mqtt.vendor.example [output-dir] [days]
set -eu

HOST="${1:?usage: $0 <vendor-hostname> [output-dir] [days]}"
OUT="${2:-$(dirname "$0")}"
DAYS="${3:-3650}"

mkdir -p "$OUT"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "$DAYS" \
    -keyout "$OUT/server.key" -out "$OUT/server.crt" \
    -subj "/CN=$HOST" -addext "subjectAltName=DNS:$HOST" 2>/dev/null
chmod 600 "$OUT/server.key"
echo "wrote $OUT/server.crt and $OUT/server.key (CN/SAN=$HOST, ${DAYS}d)"
