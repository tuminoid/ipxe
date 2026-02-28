# mbedTLS vendor for iPXE

mbedTLS 3.6.3 LTS, vendored for TLS 1.3 + 1.2 support.

## Regenerating pre-generated files

```sh
cd src/third_party/mbedtls
perl scripts/generate_errors.pl include/mbedtls \
    scripts/data_files library/error.c
python3 framework/scripts/generate_ssl_debug_helpers.py \
    --mbedtls-root . library/
python3 scripts/generate_driver_wrappers.py library/
```

## Basename collision wrappers

`ipxe/mbed_*.c` files include the corresponding `library/*.c` to
avoid `.o` basename collisions with iPXE's own source files.
