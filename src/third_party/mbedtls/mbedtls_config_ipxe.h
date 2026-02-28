/**
 * mbedTLS configuration for iPXE
 *
 * Minimal TLS 1.3 + 1.2 client for a freestanding environment.
 * No libc, no filesystem, no threads.
 */
#ifndef MBEDTLS_CONFIG_IPXE_H
#define MBEDTLS_CONFIG_IPXE_H

/* ---- Freestanding compat (must precede mbedTLS headers) ---- */
#include <stdint.h>
#include <stddef.h>
#ifndef _UINTPTR_T_DEFINED
#define _UINTPTR_T_DEFINED
typedef unsigned long uintptr_t;
#endif
typedef long long intmax_t;
typedef unsigned long long uintmax_t;
#ifndef SIZE_MAX
#define SIZE_MAX  __SIZE_MAX__
#endif
#ifndef UINT64_MAX
#define UINT64_MAX 0xffffffffffffffffULL
#endif
#ifndef UINT32_MAX
#define UINT32_MAX 0xffffffffU
#endif
#ifndef INT32_MAX
#define INT32_MAX  0x7fffffff
#endif
/* iPXE static_assert is 1-arg; bypass it for mbedTLS 2-arg usage.
 * We undef here; common.h will include <assert.h> which redefines it
 * as 1-arg, but we suppress that via CFLAGS in Makefile.mbedtls. */
#include <stdio.h>  /* snprintf, vsnprintf */

/* ---- Platform ---- */
#define MBEDTLS_PLATFORM_C
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO  snprintf
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO vsnprintf
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* ---- Disable unused / incompatible ---- */
#undef MBEDTLS_NET_C
#undef MBEDTLS_TIMING_C
#undef MBEDTLS_FS_IO
#undef MBEDTLS_HAVE_TIME
#undef MBEDTLS_HAVE_TIME_DATE
#undef MBEDTLS_SELF_TEST
#undef MBEDTLS_DEBUG_C
#undef MBEDTLS_SSL_SRV_C
#undef MBEDTLS_SSL_COOKIE_C
#undef MBEDTLS_SSL_TICKET_C
#undef MBEDTLS_PSA_ITS_FILE_C
#undef MBEDTLS_PSA_CRYPTO_STORAGE_C
#undef MBEDTLS_THREADING_C
#undef MBEDTLS_THREADING_PTHREAD
#undef MBEDTLS_VERSION_C
#undef MBEDTLS_ENTROPY_NV_SEED

/* Enable error strings for bringup (disable for production size) */
#define MBEDTLS_ERROR_C

/* Enable debug output for bringup (disable for production size) */
#define MBEDTLS_DEBUG_C

/* ---- TLS protocol ---- */
#define MBEDTLS_SSL_CLI_C
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_TLS_C
#define MBEDTLS_SSL_PROTO_TLS1_2
#define MBEDTLS_SSL_PROTO_TLS1_3
#define MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_EPHEMERAL_ENABLED
#define MBEDTLS_SSL_TLS1_3_COMPATIBILITY_MODE

/* ---- PSA Crypto (required for TLS 1.3) ---- */
#define MBEDTLS_PSA_CRYPTO_C

/* ---- Crypto: all builtin (Phase 1) ---- */
#define MBEDTLS_AES_C
#define MBEDTLS_GCM_C
#define MBEDTLS_SHA1_C
#define MBEDTLS_SHA224_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C
#define MBEDTLS_MD_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_RSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_HKDF_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ENTROPY_C

/* ---- ASN.1 / OID / PK ---- */
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C

/* ---- X.509 ---- */
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRL_PARSE_C
#define MBEDTLS_X509_RSASSA_PSS_SUPPORT
#define MBEDTLS_PEM_PARSE_C
#define MBEDTLS_BASE64_C

/* ---- ECC curves ---- */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED
#define MBEDTLS_ECP_DP_CURVE25519_ENABLED

/* ---- Key exchange (TLS 1.2) ---- */
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
#define MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* ---- TLS 1.3 requires keeping peer cert ---- */
#define MBEDTLS_SSL_KEEP_PEER_CERTIFICATE

/* ---- Restrict cipher suites ---- */
#define MBEDTLS_SSL_CIPHERSUITES                              \
    MBEDTLS_TLS1_3_AES_128_GCM_SHA256,                       \
    MBEDTLS_TLS1_3_AES_256_GCM_SHA384,                       \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,         \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,         \
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,           \
    MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

/* ---- Buffer sizes ---- */
#define MBEDTLS_SSL_IN_CONTENT_LEN   16384
#define MBEDTLS_SSL_OUT_CONTENT_LEN  4096

#endif /* MBEDTLS_CONFIG_IPXE_H */
