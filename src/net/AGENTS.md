# Agents Instructions — src/net/

See the top-level `.github/copilot-instructions.md` for build commands,
project-wide conventions, and the linker table system. This file focuses
on the networking directory and especially `tls.c`.

## tls.c overview

`tls.c` (~4 000 lines) implements TLS 1.1/1.2 as a client. It is
inserted transparently into an iPXE data-transfer pipeline via
`add_tls()`, which plugs a TLS connection between a plaintext consumer
and a ciphertext transport (typically TCP).

### Object structure

```
┌──────────┐   plainstream   ┌────────────────┐  cipherstream  ┌─────┐
│  caller  │◄───────────────►│ tls_connection  │◄──────────────►│ TCP │
│ (HTTP…)  │                 │                 │                │     │
└──────────┘                 │  tx.process     │                └─────┘
                             │  server.validator ──► cert chain │
                             └────────────────┘      validator  │
```

`struct tls_connection` owns three interfaces:
- **plainstream** — faces the application (e.g. HTTP layer).
  Operations: `xfer_deliver`, `xfer_window`, `xfer_alloc_iob`,
  `job_progress`, `intf_close`.
- **cipherstream** — faces the underlying transport (TCP).
  Operations: `xfer_deliver`, `xfer_window`, `xfer_window_changed`,
  `intf_close`.
- **server.validator** — connects to the X.509 certificate chain
  validator; closed when validation completes.

Each interface pair is "crossed": plainstream's descriptor points to
`cipherstream` and vice-versa, so that `xfer_window()` queries
propagate through the TLS layer.

`add_tls()` (line ~3961) is the only public entry point. It allocates
the connection, initialises all interfaces/state, and calls
`intf_insert()` to splice itself into the existing data-transfer chain.

### Handshake state machine

**TX side** — driven by `tls_tx_step()` (line ~3775), a one-shot
process scheduled via `tls_tx_resume()`. It checks `tls->tx.pending`
flags in priority order:

```
TLS_TX_CLIENT_HELLO  →  tls_send_client_hello()
TLS_TX_CERTIFICATE   →  tls_send_certificate()
TLS_TX_CLIENT_KEY_EXCHANGE → tls_send_client_key_exchange()
TLS_TX_CERTIFICATE_VERIFY  → tls_send_certificate_verify()
TLS_TX_CHANGE_CIPHER →  tls_send_change_cipher()
TLS_TX_FINISHED      →  tls_send_finished()
```

After all flags are cleared, the connection is ready and application
data flows through `tls_plainstream_deliver()`.

**RX side** — `tls_cipherstream_deliver()` (line ~3623) reassembles
TLS records using a two-state machine (`TLS_RX_HEADER` / `TLS_RX_DATA`).
Complete records are decrypted and dispatched by `tls_new_record()`:

| Record type            | Handler                    |
|------------------------|----------------------------|
| `TLS_TYPE_CHANGE_CIPHER` | `tls_new_change_cipher()` |
| `TLS_TYPE_ALERT`       | `tls_new_alert()`          |
| `TLS_TYPE_HANDSHAKE`   | `tls_new_handshake()`      |
| `TLS_TYPE_DATA`        | `tls_new_data()`           |

`tls_new_handshake()` (line ~2695) further dispatches by handshake
message type (`TLS_SERVER_HELLO`, `TLS_CERTIFICATE`, etc.) in a switch
statement. Handshake messages support fragmentation across records.

### Key exchange algorithms

Key exchange is pluggable via `struct tls_key_exchange_algorithm`:

| Algorithm | Exchange function | Defined at |
|-----------|-------------------|------------|
| RSA       | `tls_send_client_key_exchange_pubkey()` | line ~1416 |
| DHE       | `tls_send_client_key_exchange_dhe()` | line ~1586 |
| ECDHE     | `tls_send_client_key_exchange_ecdhe()` | line ~1711 |

The Server Key Exchange record is parsed inline; the actual key
exchange method is stored in the selected cipher suite's `.exchange`
pointer.

### Cipher suites, named curves, and signature algorithms

These are **not defined in tls.c**. They live in separate files under
`src/crypto/mishmash/` and register themselves into linker tables:

- `TLS_CIPHER_SUITES` — `__tls_cipher_suite(pref)` — priority `01`
  (most preferred) through `26` (least preferred).
- `TLS_NAMED_CURVES` — `__tls_named_curve(pref)`.
- `TLS_SIG_HASH_ALGORITHMS` — `__tls_sig_hash_algorithm`.

`tls.c` iterates these tables with `for_each_table_entry()` during
Client Hello construction and server parameter negotiation. To add a
new cipher suite, create a new file in `src/crypto/mishmash/` — do not
modify `tls.c`.

### Encryption and decryption

- **TX path**: `tls_send_plaintext()` → `tls_send_record()` — splits
  data into ≤4 KB fragments, prepends record headers, adds
  MAC/padding, encrypts via the active TX cipher spec, and delivers
  to the cipherstream.
- **RX path**: `tls_cipherstream_deliver()` → `tls_new_ciphertext()`
  → `tls_new_record()` — decrypts, verifies MAC, and delivers to
  the appropriate handler.

Both paths support CBC and GCM modes. The cipher spec is held in
`tls_cipherspec_pair` (active + pending), swapped by
`tls_change_cipher()` when a ChangeCipherSpec message is processed.

### Session resumption

`struct tls_session` (separate from `tls_connection`) groups
connections to the same server. Sessions are tracked in
`tls_sessions` (a global list). Session IDs and tickets
(`TLS_SESSION_TICKET` extension) allow abbreviated handshakes on
reconnection.

### Error code pattern

File-specific error codes are defined at the top of `tls.c` using the
`__einfo_uniqify` macro pattern:

```c
#define EINVAL_CHANGE_CIPHER __einfo_error ( EINFO_EINVAL_CHANGE_CIPHER )
#define EINFO_EINVAL_CHANGE_CIPHER \
    __einfo_uniqify ( EINFO_EINVAL, 0x01, "Invalid Change Cipher record" )
```

Each sub-error gets a unique index (0x01, 0x02, …) within its errno
family. When adding new error cases, use the next unused index.

### PRF and key derivation

`tls_prf()` (line ~566) implements the TLS PRF using `tls_p_hash_va()`.
For TLS 1.2+ it uses the handshake digest (SHA-256 by default); for
TLS 1.1 it uses the split MD5/SHA-1 scheme via `md5_sha1_algorithm`.

`tls_generate_keys()` (line ~692) derives the key block from the
master secret, then partitions it into per-direction MAC secrets,
encryption keys, and fixed IVs.

## TLS support status

### Protocol versions

- **TLS 1.1** (0x0302) — supported
- **TLS 1.2** (0x0303) — supported, and is `TLS_VERSION_MAX`
- **TLS 1.3** — not implemented
- **TLS 1.0 / SSLv3** — not supported

### Key exchange (3 algorithms)

| Algorithm | Forward secrecy |
|-----------|:-:|
| RSA static | ✗ |
| DHE-RSA | ✓ |
| ECDHE (RSA + ECDSA) | ✓ |

### Cipher suites (24 total, by preference)

| Pref | Suites |
|------|--------|
| 01–02 | ECDHE_{RSA,ECDSA}_AES_{128,256}_GCM_SHA{256,384} |
| 03–06 | ECDHE_{RSA,ECDSA}_AES_{128,256}_CBC_SHA{256,384,1} |
| 11–16 | DHE_RSA_AES_{128,256}_{GCM,CBC}_SHA{256,384,1} |
| 21–26 | RSA_AES_{128,256}_{GCM,CBC}_SHA{256,384,1} |

ECDHE+GCM suites are most preferred; static-RSA+CBC is least.
Suites are registered in `src/crypto/mishmash/` via `__tls_cipher_suite(pref)`.

### Named curves (3)

secp256r1 (P-256), secp384r1 (P-384), X25519.
Registered in `src/crypto/mishmash/` via `__tls_named_curve(pref)`.

### Signature/hash algorithms (9)

- RSA: SHA-1, SHA-224, SHA-256, SHA-384, SHA-512
- ECDSA: SHA-224, SHA-256, SHA-384, SHA-512

### Extensions

- Server Name Indication (SNI)
- Max Fragment Length (4096)
- Supported Named Curves
- Signature Algorithms
- Extended Master Secret
- Session Tickets
- Secure Renegotiation Info

### Notable gaps

- **No TLS 1.3** — the biggest limitation; many modern servers prefer
  or require it
- **No ChaCha20-Poly1305** cipher suites
- **No HKDF** — required by TLS 1.3 (HMAC exists, so HKDF is buildable)
- **No post-quantum key exchange** (e.g. ML-KEM/Kyber)
- **Client-only** — no server-side TLS implementation

## Crypto implementation provenance

The entire crypto stack is **hand-rolled** — there is no dependency on
OpenSSL, mbedTLS, wolfSSL, or any external library. This is a
deliberate choice: iPXE runs as firmware without libc, so linking an
external crypto library is not straightforward.

Nearly all crypto code is authored by Michael Brown (2006–2025). Each
primitive is implemented from published specifications and academic
papers, not copied from another library:

| Primitive | Source spec / paper |
|-----------|---------------------|
| AES | NIST Cryptographic Toolkit |
| GCM | NIST SP 800-38D |
| DES | NIST SP 800-67 |
| X25519 | Kleppmann's Curve25519 tutorial, with redesigned modular arithmetic |
| Weierstrass (P-256, P-384) | Renes/Costello/Batina complete addition formulas |
| DRBG, Hash_df | ANS X9.82 / NIST SP 800-90 |
| SHA-*, HMAC, RSA, ECDSA, CMS, X.509 | Respective RFCs and FIPS specs |
| Deflate | RFC 1951 (partially derived from wimboot, also by Michael Brown) |

### Security properties

- **Constant-time operations** — explicit attention in bigint,
  X25519, and the Montgomery ladder code
- **NIST/RFC test vectors** — tests use official known-answer vectors
- **Coverity scanning** — the repository has continuous Coverity
  static analysis (see badge in README)
- **UEFI Secure Boot** — `FILE_SECBOOT ( PERMITTED )` annotations and
  the signing infrastructure indicate some level of review
- **~20 years of production use** in datacenter PXE boot environments

### Concerns

- **Single author** — virtually all crypto is one person's work with
  no evidence of a formal third-party security audit
- **No fuzzing infrastructure** visible in the repository
- **Novel optimizations** (Weierstrass bytecode encoding, custom
  bigint layout for X25519) are clever but harder for external review
- **Firmware attack surface** — a crypto bug could compromise boot
  integrity, not just a network session

### What TLS 1.3 would require

TLS 1.3 is a substantially different protocol from 1.2 — it is not an
incremental patch. Key areas of work:

**New crypto primitives:**
- **HKDF** — HMAC-based Extract-and-Expand; straightforward to build
  on the existing HMAC implementation (~200 lines)
- **ChaCha20-Poly1305** — completely absent; optional for TLS 1.3 but
  expected by most servers (~500+ lines)

**Protocol-level changes (all in tls.c):**
- **Reworked handshake** — 1-RTT (vs 2-RTT). Server encrypts
  immediately after ServerHello using handshake traffic keys. The
  TX flag-driven state machine (`tls_tx_step`) and RX dispatch switch
  (`tls_new_handshake`) need a parallel 1.3 path or major refactor.
- **HKDF-based key schedule** — replaces PRF/master-secret model.
  `tls_prf()`, `tls_generate_master_secret()`, and
  `tls_generate_keys()` do not apply to 1.3.
- **Mid-handshake encryption** — the current `tls_cipherspec_pair`
  (active/pending) model must support multiple key transitions within
  a single handshake (handshake keys → application keys).
- **No ChangeCipherSpec** — removed in 1.3 (a dummy may be sent for
  middlebox compatibility).
- **No static RSA key exchange** — only (EC)DHE is permitted.
- **New message types** — EncryptedExtensions, reworked
  CertificateVerify, post-handshake NewSessionTicket.
- **PSK resumption** — replaces session ID/ticket model; the
  `tls_session` management needs rework.
- **0-RTT early data** — optional but commonly expected.

**Existing primitives that can be reused:**
- AES-GCM, SHA-256, SHA-384, X25519, P-256, P-384, ECDSA, RSA
  signatures — all already present.

**Rough scope:** ~1500–2500 new/modified lines in tls.c plus ~700
lines of new crypto primitives (HKDF, optionally ChaCha20-Poly1305).
The existing TLS 1.2 code must coexist since version negotiation
happens at ServerHello.

## mbedTLS integration plan (TLS 1.3)

mbedTLS was chosen over wolfSSL, picotls, and hand-rolling for its
PSA Crypto driver interface and firmware pedigree (TF-A, TF-M, OP-TEE).

### Goal

Replace iPXE's native TLS layer with mbedTLS 3.6 LTS behind a thin
shim (`tls_mbedtls.c`, ~700 lines), providing TLS 1.3 + TLS 1.2
client support. The switch is opt-in (`CONFIG=mbedtls`); default
builds remain byte-identical. Only 2 existing files are touched
(1 line each: `Makefile` and `errfile.h`).

### Scope

- TLS 1.3 and 1.2 via mbedTLS, iPXE validator bridge for certificate
  verification (fingerprint roots, cross-cert fetch, OCSP, hostname
  check via `x509_check_name`).
- ~58 vendored mbedTLS source files in `src/third_party/mbedtls/`,
  11 basename-collision wrappers, a custom `mbedtls_config_ipxe.h`,
  and the shim implementing three iPXE interfaces (plainstream,
  cipherstream, validator).
- `NON_AUTO_SRCS += net/tls.c` in `Makefile.mbedtls` excludes the
  native TLS when `CONFIG=mbedtls` — no modification to `tls.c`.
- Non-goals for MVP: 0-RTT, PSK/session tickets, ChaCha20-Poly1305,
  client certificates, server-side TLS.

### Phases

1. **Phase 1 — Working TLS 1.3 (~3 weeks):** Vendor mbedTLS 3.6 LTS,
   write the shim with full interface contract, validator bridge, and
   build integration. Target: TLS 1.3 handshake + HTTPS fetch on
   Linux userspace.
2. **Phase 2 — PSA drivers + optimisation (~3 weeks):** PSA transparent
   drivers for AES-GCM and SHA-256/384 to eliminate crypto duplication,
   disable error strings for production size.
3. **Phase 3 — Production hardening (~2 weeks):** Client certificates,
   session tickets, ChaCha20-Poly1305, multi-arch verification,
   RFC 8449 record size limit, memory profiling.

### Key architecture decisions

- The shim uses a shared `mbedtls_ssl_config` singleton (not
  per-connection) to save memory.
- Ciphertext is queued in a `list_head` of `io_buffer`s (no fixed
  buffer), with natural backpressure via `xfer_alloc_iob`.
- Certificate verification is deferred to iPXE's `create_validator()`
  (mbedTLS set to `VERIFY_OPTIONAL`), followed by `x509_check_name()`
  for hostname matching.
- Entropy is provided via `MBEDTLS_ENTROPY_HARDWARE_ALT` backed by
  iPXE's `rbg_generate()`.

## Other files in src/net/

The remaining files in this directory implement network protocols and
sit alongside `tls.c` in the data-transfer pipeline. Key relationships:

- `tcp.c` — provides the ciphertext transport underneath TLS.
- `validator.c` — X.509 chain validation; TLS connects to it via
  `server.validator` interface during the handshake.
- `ipv4.c`, `ipv6.c` — IP layer.
- `ethernet.c`, `vlan.c` — link layer framing.
- `arp.c`, `ndp.c`, `neighbour.c` — address resolution.
- `retry.c` — generic retransmission timer used by TCP and others.
- `tcp/` and `udp/` subdirectories contain protocol-specific helpers.
