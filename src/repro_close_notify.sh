#!/bin/bash
#
# Reproducer: native TLS stack ignores close_notify, causing transfer stall
#
# Expected: imgfetch completes with PASS
# Actual:   imgfetch hangs until timeout (45s), prints FAIL
#
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="/tmp/ipxe-close-notify-$$"
PORT=14433
GW="10.0.2.2"
SERVER_PID=""

cleanup() { kill "$SERVER_PID" 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

mkdir -p "$WORK"

# Certs + test file
openssl req -x509 -newkey rsa:2048 -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 1 -nodes -subj "/CN=$GW" -addext "subjectAltName=IP:$GW" 2>/dev/null
echo "HELLO" > "$WORK/hello.txt"
cat > "$WORK/boot.ipxe" <<EOF
#!ipxe
dhcp net0
imgfetch https://${GW}:${PORT}/hello.txt && echo PASS || echo FAIL
exit
EOF

# Build native iPXE
echo "=== Building iPXE (native TLS) ==="
rm -rf "$SCRIPT_DIR/bin-x86_64-linux"
make -C "$SCRIPT_DIR" -j"$(nproc)" bin-x86_64-linux/ipxe.linux \
    DEBUG=tls TRUST="$WORK/cert.pem" EMBED="$WORK/boot.ipxe" \
    > "$WORK/build.log" 2>&1

# Start TLS 1.2 server
cd "$WORK"
openssl s_server -accept "$PORT" -cert cert.pem -key key.pem -WWW -tls1_2 \
    > server.log 2>&1 &
SERVER_PID=$!
sleep 1

# Run iPXE (45s timeout — enough for handshake+fetch, exposes the stall)
echo "=== Running iPXE ==="
setsid timeout 45 "$SCRIPT_DIR/bin-x86_64-linux/ipxe.linux" --net slirp \
    < /dev/null > "$WORK/ipxe.log" 2>&1 || true

# Result
if grep -q "PASS" "$WORK/ipxe.log"; then
    echo "RESULT: PASS (transfer completed)"
else
    echo "RESULT: FAIL (transfer stalled — close_notify ignored)"
    grep -E 'TLS|alert|PASS|FAIL' "$WORK/ipxe.log" | tail -10
fi
