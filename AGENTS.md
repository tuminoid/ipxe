# Copilot Instructions for iPXE

---

iPXE is a network boot firmware written in C, targeting bare-metal and
firmware environments (BIOS, UEFI, Linux userspace). It is not a typical
userspace application — it runs without libc, implements its own standard
library, and links via custom linker scripts.

## Build commands

All builds run from the `src/` directory.

```sh
# BIOS ROM image for a specific NIC (by PCI vendor:device ID)
make bin/10ec8139.rom

# Generic BIOS bootable formats
make bin/ipxe.pxe bin/ipxe.lkrn bin/ipxe.usb bin/ipxe.iso bin/undionly.kpxe

# UEFI binary (x86_64)
make bin-x86_64-efi/ipxe.efi

# Linux userspace binary (for testing without hardware)
make bin-x86_64-linux/ipxe.linux

# Build test binary and run self-tests
make bin-x86_64-linux/tests.linux && bin-x86_64-linux/tests.linux

# Embed a custom iPXE script into the binary
make bin/ipxe.pxe EMBED=boot.ipxe

# Parallel build
make -j$(nproc) bin/ipxe.pxe

# Verbose build output
make V=1 bin/ipxe.pxe
```

The `bin/` prefix encodes architecture and platform:
`bin/` = i386-pcbios, `bin-x86_64-efi/` = x86_64-efi,
`bin-arm64-efi/` = arm64-efi, `bin-x86_64-linux/` = x86_64-linux, etc.

## Testing

Tests are self-test modules in `src/tests/`. They compile into a single
`tests.linux` binary via the Linux platform build. There is no way to
run a single test file in isolation — all tests registered in
`src/tests/tests.c` via `REQUIRE_OBJECT()` run together.

To add a new test:
1. Create `src/tests/foo_test.c`
2. Add `REQUIRE_OBJECT ( foo_test );` to `src/tests/tests.c`
3. Use the `ok()` / `okx()` macros from `<ipxe/test.h>` for assertions
4. Register the test set with `__self_test` from the linker table system

## Architecture

### Linker tables (the central design pattern)

iPXE avoids `#ifdef` for feature selection. Instead, features are implemented
in separate `.c` files that are always compiled. They register themselves into
**linker tables** — sorted arrays of structs placed in special linker sections.
At link time, only objects pulled in by config options end up in the binary.

Key macros (from `<ipxe/tables.h>`):
- `__table(type, name)` — declare a linker table
- `__table_entry(table, order)` — place a struct into a table
- `for_each_table_entry(ptr, table)` — iterate over all entries

This pattern is used for: init functions, startup/shutdown hooks,
network drivers, PCI device tables, console drivers, image types,
commands, self-tests, and more.

### Object interfaces

iPXE uses a dynamic dispatch system for data transfer (the "interface"
subsystem in `src/include/ipxe/interface.h`). Objects communicate through
typed interface operations (`INTF_OP`), enabling a pipeline architecture
for downloads where data flows through chains of objects (e.g.,
HTTP → TLS → TCP → IP → network device).

### Platform abstraction

The build targets multiple platforms (pcbios, efi, linux, sbi) and
architectures (i386, x86_64, arm32, arm64, riscv32, riscv64, loong64).
Platform-specific defaults live in `src/config/defaults/`. Architecture-
specific code lives under `src/arch/<arch>/`.

### Configuration

Build-time feature selection is controlled by headers in `src/config/`:
- `general.h` — protocols, commands, crypto
- `console.h`, `serial.h`, etc. — subsystem-specific options

Local overrides go in `src/config/local/` (gitignored).

## mbedTLS integration (TLS 1.3 project)

mbedTLS was chosen over wolfSSL, picotls, and hand-rolling for its
PSA Crypto driver interface and firmware pedigree (TF-A, TF-M, OP-TEE).

Key points:

### Goal

Replace iPXE's native TLS layer with mbedTLS 3.6 LTS behind a thin
shim, providing TLS 1.3 + TLS 1.2 client support. The switch is
opt-in (`CONFIG=mbedtls`); default builds remain byte-identical.
Only 2 existing files are touched (1 line each).

### Scope

- TLS 1.3 and 1.2 via mbedTLS, iPXE validator bridge for certificate
  verification (fingerprint roots, cross-cert fetch, OCSP, hostname
  check via `x509_check_name`).
- ~58 vendored mbedTLS source files, 11 basename-collision wrappers,
  a custom `mbedtls_config_ipxe.h`, and a ~700-line shim
  (`tls_mbedtls.c`) implementing three iPXE interfaces (plainstream,
  cipherstream, validator).
- Non-goals for MVP: 0-RTT, PSK/session tickets, ChaCha20-Poly1305,
  client certificates, server-side TLS.

### Phases

1. **Phase 1 — Working TLS 1.3:** COMPLETE. Vendor mbedTLS 3.6 LTS,
   shim, validator bridge, build integration. TLS 1.3 handshake +
   HTTPS fetch verified on Linux userspace.
2. **Phase 2 — PSA drivers + optimisation:** PSA transparent drivers
   for AES-GCM and SHA-256/384 to eliminate crypto duplication,
   disable error strings for production size. Optional — skip if
   binary size is not a concern.
3. **Phase 3 — Production hardening:** Client certificates, session
   tickets, ChaCha20-Poly1305, multi-arch verification, RFC 8449
   record size limit, memory profiling.

### mbedTLS build and test commands

```sh
# Build and run unit tests (mbedTLS config — 9823 tests)
make -j$(nproc) bin-x86_64-linux/tests.linux CONFIG=mbedtls
./bin-x86_64-linux/tests.linux

# Build Linux userspace binary with mbedTLS TLS 1.3
make -j$(nproc) bin-x86_64-linux/ipxe.linux CONFIG=mbedtls

# Run with slirp networking (requires libslirp-dev)
./bin-x86_64-linux/ipxe.linux --net slirp
```

### Test scripts (run from `src/`)

```sh
src/tls_unit.sh          # Unit tests — both CONFIG=mbedtls and default
src/tls_integration.sh   # Local openssl s_server, TLS 1.3, full fetch
src/tls_smoke_test.sh    # Real server (google.com), TLS 1.3 handshake
```

## Code conventions

### File boilerplate

Every `.c` and `.h` file must include a `FILE_LICENCE()` macro near the top
(typically `FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL )`). Header files use
`FILE_SECBOOT()` as well.

### Documentation style

Functions use Doxygen-style doc comments with `@v` for parameters and
`@ret` for return values:

```c
/**
 * Brief description
 *
 * @v param1    Description of param1
 * @v param2    Description of param2
 * @ret rc      Return status code
 */
```

### Error handling

Functions return `int rc` where 0 is success and negative errno values
indicate failure. Error file identifiers are registered in
`src/include/ipxe/errfile.h` — each source file gets a unique error
code prefix so that errno values encode the originating file.

### Debug output

Use `DBGC(object, fmt, ...)` (and `DBGC2`, `DBG`, etc.) rather than
`printf` for debug output. The first argument is a pointer used to
filter debug output by object identity.

### Naming

- Struct types: `struct foo_bar` (no typedefs for structs)
- Functions: `module_action` pattern (e.g., `skeleton_reset`, `tcp_open`)
- Constants/macros: `UPPER_CASE`
- Tabs for indentation, spaces for alignment

### Reference counting

Long-lived objects use `struct refcnt` (from `<ipxe/refcnt.h>`).
Objects are freed when the count drops below zero (not to zero),
so a freshly zeroed refcnt will free on the first `ref_put()`.

### Adding a new driver

Use `src/drivers/net/skeleton.c` and `skeleton.h` as the reference
template for new network drivers.
