/*
 * Copyright (C) 2026 iPXE contributors
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** @file
 *
 * mbedTLS integration self-tests
 *
 * Tests the platform hooks, PSA crypto init, entropy source, and
 * SSL config — the components that must work before any TLS
 * handshake can succeed.
 */

/* Forcibly enable assertions */
#undef NDEBUG

#include <stdlib.h>
#include <string.h>
#include <ipxe/test.h>
#include <ipxe/rbg.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#include <psa/crypto.h>

/* Forward declaration */
struct self_test tls_mbedtls_test __self_test;

/* Declared in tls_mbedtls.c */
extern int mbedtls_hardware_poll ( void *data, unsigned char *output,
				   size_t len, size_t *olen );

/**
 * Test hardware entropy source
 */
static void tls_mb_test_entropy ( void ) {
	unsigned char buf[64];
	size_t olen = 0;
	int ret;

	memset ( buf, 0, sizeof ( buf ) );
	ret = mbedtls_hardware_poll ( NULL, buf, sizeof ( buf ), &olen );
	ok ( ret == 0 );
	ok ( olen == sizeof ( buf ) );

	/* Verify buffer was written (not still all zeros) */
	{
		unsigned char zero[64];
		memset ( zero, 0, sizeof ( zero ) );
		ok ( memcmp ( buf, zero, sizeof ( buf ) ) != 0 );
	}
}

/**
 * Test full init sequence (allocator → PSA → entropy → DRBG → config)
 *
 * This replicates what tls_mb_init() does. Before the init-order
 * fix, psa_crypto_init() will fail because the allocator isn't
 * set up yet.
 */
static void tls_mb_test_init ( void ) {
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ssl_config conf;
	psa_status_t psa_ret;
	int ret;

	/* Step 1: platform allocator (must be first) */
	mbedtls_platform_set_calloc_free ( calloc, free );

	/* Step 2: PSA crypto */
	psa_ret = psa_crypto_init();
	ok ( psa_ret == PSA_SUCCESS );
	if ( psa_ret != PSA_SUCCESS )
		return;

	/* Step 3: entropy + DRBG seed */
	mbedtls_entropy_init ( &entropy );
	mbedtls_ctr_drbg_init ( &ctr_drbg );
	ret = mbedtls_ctr_drbg_seed ( &ctr_drbg, mbedtls_entropy_func,
				      &entropy, NULL, 0 );
	ok ( ret == 0 );

	/* Step 4: SSL config defaults */
	mbedtls_ssl_config_init ( &conf );
	ret = mbedtls_ssl_config_defaults ( &conf,
					    MBEDTLS_SSL_IS_CLIENT,
					    MBEDTLS_SSL_TRANSPORT_STREAM,
					    MBEDTLS_SSL_PRESET_DEFAULT );
	ok ( ret == 0 );

	/* Cleanup */
	mbedtls_ssl_config_free ( &conf );
	mbedtls_ctr_drbg_free ( &ctr_drbg );
	mbedtls_entropy_free ( &entropy );
}

/**
 * Test PSA hash operation (verifies PSA subsystem is functional)
 */
static void tls_mb_test_psa_hash ( void ) {
	psa_status_t status;
	uint8_t hash[32];
	size_t hash_len = 0;
	const uint8_t msg[] = "iPXE";

	/* SHA-256("iPXE") — just verify it completes */
	status = psa_hash_compute ( PSA_ALG_SHA_256, msg, sizeof ( msg ) - 1,
				    hash, sizeof ( hash ), &hash_len );
	ok ( status == PSA_SUCCESS );
	ok ( hash_len == 32 );
}

/**
 * Execute mbedTLS integration tests
 */
static void tls_mb_test_exec ( void ) {
	tls_mb_test_entropy();
	tls_mb_test_init();
	tls_mb_test_psa_hash();
}

/** mbedTLS integration self-test */
struct self_test tls_mbedtls_test __self_test = {
	.name = "tls_mbedtls",
	.exec = tls_mb_test_exec,
};
