#!/bin/bash
#
# TLS smoke test -- real HTTPS servers, both mbedTLS and native stacks
#
# Builds iPXE with each TLS stack and tests handshake + data fetch
# against real public HTTPS servers via slirp networking.
# No TRUST= needed — both stacks use iPXE's built-in root CA with
# cross-certificate fetching.
#
# Usage: tls_smoke_test.sh [mbedtls|native]
# No argument runs both stacks.
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FILTER="${1:-}"
WORK="/tmp/ipxe-tls-smoke-$$"
TOTAL_PASS=0
TOTAL_FAIL=0

cleanup() { [ "$TOTAL_FAIL" -eq 0 ] && rm -rf "$WORK" || echo "Logs kept: $WORK"; }
trap cleanup EXIT
mkdir -p "$WORK"

# ---- Verify target supports TLS 1.3 ----
PROTO=$(echo | timeout 5 openssl s_client -connect www.google.com:443 -tls1_3 2>/dev/null | \
    grep 'New,' | awk -F', ' '{print $2}')
if [ "$PROTO" != "TLSv1.3" ]; then
    echo "SKIP: www.google.com does not support TLS 1.3 (got: $PROTO)"
    exit 0
fi

cat > "$WORK/boot.ipxe" << 'EOF'
#!ipxe
dhcp net0
imgfetch https://www.google.com/ && echo FETCH_OK || echo FETCH_FAIL
exit
EOF

check_result() {
    local stack="$1" expect_version="$2"
    cp "$WORK/ipxe.log" "$WORK/log-${stack}.txt" 2>/dev/null

    local ok=true
    if [ -n "$expect_version" ]; then
        if grep -q "handshake complete ($expect_version)" "$WORK/ipxe.log"; then
            echo "    Handshake: OK ($expect_version)"
        else
            echo "    Handshake: FAILED (expected $expect_version — see log-${stack}.txt)"
            ok=false
        fi
    else
        if grep -q "certificate validation succeeded\|handshake complete" "$WORK/ipxe.log"; then
            echo "    Handshake: OK"
        else
            echo "    Handshake: FAILED (see log-${stack}.txt)"
            ok=false
        fi
    fi
    if grep -q "FETCH_OK" "$WORK/ipxe.log"; then
        echo "    Fetch: OK"
    else
        echo "    Fetch: FAILED (see log-${stack}.txt)"
        ok=false
    fi
    if $ok; then
        TOTAL_PASS=$((TOTAL_PASS + 1))
    else
        TOTAL_FAIL=$((TOTAL_FAIL + 1))
    fi
}

# ---- mbedTLS stack ----
if [ -z "$FILTER" ] || [ "$FILTER" = "mbedtls" ]; then
echo "=== Building iPXE (CONFIG=mbedtls) ==="
rm -rf "$SCRIPT_DIR/bin-x86_64-linux"
if ! timeout 300 make -C "$SCRIPT_DIR" -j"$(nproc)" bin-x86_64-linux/ipxe.linux \
    CONFIG=mbedtls DEBUG=tls_mbedtls \
    EMBED="$WORK/boot.ipxe" \
    > "$WORK/build.log" 2>&1; then
    echo "FAIL: mbedtls build failed"
    tail -20 "$WORK/build.log"
    exit 1
fi
echo "Running (mbedtls):"
setsid timeout 45 "$SCRIPT_DIR/bin-x86_64-linux/ipxe.linux" \
    --net slirp < /dev/null > "$WORK/ipxe.log" 2>&1 || true
check_result "mbedtls" "TLSv1.3"
fi

# ---- Native stack ----
if [ -z "$FILTER" ] || [ "$FILTER" = "native" ]; then
echo ""
echo "=== Building iPXE (default/native) ==="
rm -rf "$SCRIPT_DIR/bin-x86_64-linux"
if ! timeout 300 make -C "$SCRIPT_DIR" -j"$(nproc)" bin-x86_64-linux/ipxe.linux \
    DEBUG=tls \
    EMBED="$WORK/boot.ipxe" \
    > "$WORK/build.log" 2>&1; then
    echo "FAIL: native build failed"
    tail -20 "$WORK/build.log"
    exit 1
fi
echo "Running (native):"
setsid timeout 45 "$SCRIPT_DIR/bin-x86_64-linux/ipxe.linux" \
    --net slirp < /dev/null > "$WORK/ipxe.log" 2>&1 || true
check_result "native" ""
fi

# ---- Summary ----
echo ""
echo "=== Results: $TOTAL_PASS passed, $TOTAL_FAIL failed ==="
[ "$TOTAL_FAIL" -gt 0 ] && echo "    Logs: $WORK/log-*.txt"
[ "$TOTAL_FAIL" -eq 0 ] && exit 0 || exit 1
