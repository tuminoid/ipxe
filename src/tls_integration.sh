#!/bin/bash
#
# TLS integration tests -- multi-scenario against local openssl s_server
#
# Runs the same scenarios against both CONFIG=mbedtls and default (native)
# TLS stacks. Builds once per stack, then cycles through server configs.
#
# Scenarios:
#   1. TLS 1.3 only server      (mbedtls: pass, native: reject)
#   2. TLS 1.2 only server      (both: pass)
#   3. TLS 1.2+1.3 server       (both: pass)
#   4. TLS 1.1 only server      (both: reject, skip if OS unsupported)
#   5. Untrusted cert            (both: reject)
#
# Usage: tls_integration.sh [mbedtls|native]
# No argument runs both stacks.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FILTER="${1:-}"
WORK="/tmp/ipxe-tls-test-$$"
PORT=14433
GATEWAY="10.0.2.2"
SERVER_PID=""
TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

cleanup() {
    kill "$SERVER_PID" 2>/dev/null || true
    [ "$TOTAL_FAIL" -eq 0 ] && rm -rf "$WORK" || echo "Logs kept: $WORK"
}
trap cleanup EXIT

mkdir -p "$WORK"

# ---- Generate certs ----
echo "=== Setup ==="
openssl req -x509 -newkey rsa:2048 \
    -keyout "$WORK/key.pem" -out "$WORK/cert.pem" \
    -days 1 -nodes -subj "/CN=$GATEWAY" \
    -addext "subjectAltName=IP:$GATEWAY" 2>/dev/null
openssl req -x509 -newkey rsa:2048 \
    -keyout "$WORK/key2.pem" -out "$WORK/cert2.pem" \
    -days 1 -nodes -subj "/CN=$GATEWAY" \
    -addext "subjectAltName=IP:$GATEWAY" 2>/dev/null
echo "HELLO TLS" > "$WORK/hello.txt"

cat > "$WORK/boot.ipxe" << EOF
#!ipxe
dhcp net0
imgfetch https://${GATEWAY}:${PORT}/hello.txt && echo PASS || echo FAIL
exit
EOF

# ---- Helpers ----
start_server() {
    local cert="$1" key="$2"
    shift 2
    cd "$WORK"
    nohup openssl s_server -accept "$PORT" \
        -cert "$cert" -key "$key" -WWW "$@" \
        > "$WORK/server.log" 2>&1 &
    SERVER_PID=$!
    sleep 1
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        SERVER_PID=""
        return 1
    fi
}

stop_server() {
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    SERVER_PID=""
}

run_ipxe() {
    setsid timeout 45 "$SCRIPT_DIR/bin-x86_64-linux/ipxe.linux" \
        --net slirp < /dev/null > "$WORK/ipxe.log" 2>&1 || true
}

# $1=name $2=expect_pass(yes/no) $3=version_grep(optional) $4=cert $5=key $6+=server flags
run_scenario() {
    local name="$1" expect_pass="$2" version_grep="$3" cert="$4" key="$5"
    shift 5
    echo "  $name ..."

    if ! start_server "$cert" "$key" "$@"; then
        echo "    SKIP (server can't start)"
        TOTAL_SKIP=$((TOTAL_SKIP + 1))
        return
    fi

    run_ipxe
    stop_server

    local got_pass=no
    grep -q "PASS" "$WORK/ipxe.log" && got_pass=yes

    local tag="${STACK}-$(echo "$name" | tr ' ' '_')"
    cp "$WORK/ipxe.log" "$WORK/log-${tag}.txt" 2>/dev/null

    if [ "$expect_pass" = "yes" ]; then
        if [ "$got_pass" = "yes" ]; then
            if [ -n "$version_grep" ] && ! grep -q "$version_grep" "$WORK/ipxe.log"; then
                echo "    FAILED (wrong TLS version — see log-${tag}.txt)"
                TOTAL_FAIL=$((TOTAL_FAIL + 1))
            else
                echo "    OK${version_grep:+ ($version_grep)}"
                TOTAL_PASS=$((TOTAL_PASS + 1))
            fi
        else
            echo "    FAILED (expected pass — see log-${tag}.txt)"
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
        fi
    else
        if [ "$got_pass" = "no" ]; then
            echo "    OK (correctly rejected)"
            TOTAL_PASS=$((TOTAL_PASS + 1))
        else
            echo "    FAILED (expected rejection — see log-${tag}.txt)"
            TOTAL_FAIL=$((TOTAL_FAIL + 1))
        fi
    fi
}

C="$WORK/cert.pem"
K="$WORK/key.pem"
C2="$WORK/cert2.pem"
K2="$WORK/key2.pem"

# ---- mbedTLS stack ----
if [ -z "$FILTER" ] || [ "$FILTER" = "mbedtls" ]; then
echo ""
echo "=== Building iPXE (CONFIG=mbedtls) ==="
rm -rf "$SCRIPT_DIR/bin-x86_64-linux"
if ! timeout 300 make -C "$SCRIPT_DIR" -j"$(nproc)" bin-x86_64-linux/ipxe.linux \
    CONFIG=mbedtls DEBUG=tls_mbedtls \
    TRUST="$WORK/cert.pem" EMBED="$WORK/boot.ipxe" \
    > "$WORK/build.log" 2>&1; then
    echo "FAIL: mbedtls build failed"
    tail -20 "$WORK/build.log"
    exit 1
fi

echo "Running scenarios (mbedtls):"
STACK=mbedtls
run_scenario "TLS 1.3 only"    yes "handshake complete (TLSv1.3)" "$C" "$K" -tls1_3
run_scenario "TLS 1.2 only"    yes "handshake complete (TLSv1.2)" "$C" "$K" -tls1_2
run_scenario "TLS 1.2+1.3"     yes "handshake complete (TLSv1.3)" "$C" "$K"
run_scenario "TLS 1.1 only"    no  ""                              "$C" "$K" -tls1_1
run_scenario "Untrusted cert"  no  ""                              "$C2" "$K2" -tls1_3
fi

# ---- Native stack ----
if [ -z "$FILTER" ] || [ "$FILTER" = "native" ]; then
echo ""
echo "=== Building iPXE (default/native) ==="
rm -rf "$SCRIPT_DIR/bin-x86_64-linux"
if ! timeout 300 make -C "$SCRIPT_DIR" -j"$(nproc)" bin-x86_64-linux/ipxe.linux \
    DEBUG=tls \
    TRUST="$WORK/cert.pem" EMBED="$WORK/boot.ipxe" \
    > "$WORK/build.log" 2>&1; then
    echo "FAIL: native build failed"
    tail -20 "$WORK/build.log"
    exit 1
fi

echo "Running scenarios (native):"
STACK=native
run_scenario "TLS 1.3 only"    no  ""  "$C" "$K" -tls1_3
run_scenario "TLS 1.2 only"    yes ""  "$C" "$K" -tls1_2       # known-fail: close_notify
run_scenario "TLS 1.2+1.3"     yes ""  "$C" "$K"               # known-fail: close_notify
run_scenario "TLS 1.1 only"    no  ""  "$C" "$K" -tls1_1
run_scenario "Untrusted cert"  no  ""  "$C2" "$K2" -tls1_2
fi

# ---- Summary ----
echo ""
echo "=== Results: $TOTAL_PASS passed, $TOTAL_FAIL failed, $TOTAL_SKIP skipped ==="
[ "$TOTAL_FAIL" -gt 0 ] && echo "    Logs: $WORK/log-*.txt"
[ "$TOTAL_FAIL" -eq 0 ] && exit 0 || exit 1
