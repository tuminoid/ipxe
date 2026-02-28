#!/bin/bash
#
# TLS unit tests -- both CONFIG=mbedtls and default builds
#
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "[1/2] Building and running tests (CONFIG=mbedtls)..."
rm -rf "$SCRIPT_DIR/bin-x86_64-linux" 2>/dev/null || true
if ! timeout 300 make -C "$SCRIPT_DIR" -j"$(nproc)" bin-x86_64-linux/tests.linux \
    CONFIG=mbedtls > /dev/null 2>&1; then
    echo "FAIL: mbedtls build failed"
    exit 1
fi
MBEDTLS=$("$SCRIPT_DIR/bin-x86_64-linux/tests.linux" 2>&1 | grep 'all.*tests')
echo "  $MBEDTLS"

echo "[2/2] Building and running tests (default)..."
rm -rf "$SCRIPT_DIR/bin-x86_64-linux" 2>/dev/null || true
if ! timeout 300 make -C "$SCRIPT_DIR" -j"$(nproc)" bin-x86_64-linux/tests.linux \
    > /dev/null 2>&1; then
    echo "FAIL: default build failed"
    exit 1
fi
DEFAULT=$("$SCRIPT_DIR/bin-x86_64-linux/tests.linux" 2>&1 | grep 'all.*tests')
echo "  $DEFAULT"

echo ""
if echo "$MBEDTLS" | grep -q "^OK" && echo "$DEFAULT" | grep -q "^OK"; then
    echo "=== ALL UNIT TESTS PASSED ==="
    exit 0
else
    echo "=== UNIT TESTS FAILED ==="
    exit 1
fi
