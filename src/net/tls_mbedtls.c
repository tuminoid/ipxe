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
FILE_SECBOOT ( PERMITTED );

/**
 * @file
 *
 * mbedTLS-backed TLS layer
 *
 * Replaces iPXE's native tls.c when CONFIG=mbedtls.  Provides
 * TLS 1.3 + 1.2 via mbedTLS 3.6 LTS behind a thin shim that
 * implements three iPXE interfaces (plainstream, cipherstream,
 * validator).
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ipxe/refcnt.h>
#include <ipxe/interface.h>
#include <ipxe/iobuf.h>
#include <ipxe/xfer.h>
#include <ipxe/process.h>
#include <ipxe/pending.h>
#include <ipxe/job.h>
#include <ipxe/x509.h>
#include <ipxe/privkey.h>
#include <ipxe/rootcert.h>
#include <ipxe/validator.h>
#include <ipxe/rbg.h>
#include <ipxe/tls_mbedtls.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/platform.h>
#include <mbedtls/debug.h>
#include <psa/crypto.h>

/** @file
 *
 * Error codes
 */
#define EPERM_HANDSHAKE \
	__einfo_error ( EINFO_EPERM_HANDSHAKE )
#define EINFO_EPERM_HANDSHAKE \
	__einfo_uniqify ( EINFO_EPERM, 0x01, "TLS handshake failed" )
#define EACCES_VERIFY \
	__einfo_error ( EINFO_EACCES_VERIFY )
#define EINFO_EACCES_VERIFY \
	__einfo_uniqify ( EINFO_EACCES, 0x01, "Certificate verification failed" )
#define EPROTO_TLS \
	__einfo_error ( EINFO_EPROTO_TLS )
#define EINFO_EPROTO_TLS \
	__einfo_uniqify ( EINFO_EPROTO, 0x01, "TLS protocol error" )

/** An mbedTLS TLS connection */
struct tls_mbedtls {
	/** Reference counter */
	struct refcnt refcnt;
	/** Plaintext interface (faces HTTP) */
	struct interface plainstream;
	/** Ciphertext interface (faces TCP) */
	struct interface cipherstream;
	/** Validator interface (faces iPXE cert validator) */
	struct interface validator;
	/** TX/handshake process */
	struct process process;
	/** Negotiation pending operation */
	struct pending_operation negotiation;
	/** Validation pending operation */
	struct pending_operation validation;
	/** mbedTLS SSL context */
	mbedtls_ssl_context ssl;
	/** Pointer to shared config singleton */
	mbedtls_ssl_config *conf;
	/** Ciphertext receive queue */
	struct list_head rx_data;
	/** Total bytes queued in rx_data.
	 *
	 *  Note: unbounded — matches native tls.c behaviour.  A cap
	 *  (e.g. TLS_MB_RX_MAX) could be added if memory-pressure
	 *  becomes a concern in constrained environments.
	 */
	size_t rx_pending;
	/** Server hostname */
	char *hostname;
	/** Pending TX iobuf (partial write resume) */
	struct io_buffer *tx_pending;
	/** Offset into tx_pending already sent */
	size_t tx_offset;
	/** Root certificate store */
	struct x509_root *root;
	/** Peer certificate chain */
	struct x509_chain *chain;
	/** Handshake + validation complete */
	unsigned int ready : 1;
	/** Connection closed */
	unsigned int closed : 1;
};

/* Forward declarations */
static void tls_mb_step ( struct tls_mbedtls *tls );
static void tls_mb_close ( struct tls_mbedtls *tls, int rc );
static void tls_mb_free ( struct refcnt *refcnt );
static int tls_mb_tx_drain ( struct tls_mbedtls *tls );

/*
 * Shared config singleton
 */
static mbedtls_ssl_config tls_mb_conf;
static mbedtls_entropy_context tls_mb_entropy;
static mbedtls_ctr_drbg_context tls_mb_ctr_drbg;
static int tls_mb_initialized;

/*
 * Error mapping
 */
static int tls_mb_error ( int ret ) {
	switch ( ret ) {
	case 0:
		return 0;
	case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
		return -ECONNRESET;
	case MBEDTLS_ERR_X509_CERT_VERIFY_FAILED:
		return -EACCES_VERIFY;
	case MBEDTLS_ERR_SSL_ALLOC_FAILED:
		return -ENOMEM;
	case MBEDTLS_ERR_SSL_WANT_READ:
	case MBEDTLS_ERR_SSL_WANT_WRITE:
		return -EAGAIN;
	case MBEDTLS_ERR_SSL_HANDSHAKE_FAILURE:
		return -EPERM_HANDSHAKE;
	case MBEDTLS_ERR_NET_SEND_FAILED:
		return -EIO;
	default:
		DBGC ( NULL, "TLSMB error: -%04x\n", (unsigned) -ret );
		return -EPROTO_TLS;
	}
}

/*
 * Platform abstraction
 */
static void * ipxe_calloc ( size_t n, size_t size ) {
	if ( size && n > ( ( size_t ) -1 ) / size )
		return NULL;
	return zalloc ( n * size );
}

static void ipxe_free ( void *ptr ) {
	free ( ptr );
}

/**
 * Hardware entropy source for mbedTLS
 */
int mbedtls_hardware_poll ( void *data __unused,
			    unsigned char *output, size_t len,
			    size_t *olen ) {
	int rc = rbg_generate ( NULL, 0, 0, output, len );
	if ( rc )
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	*olen = len;
	return 0;
}

/*
 * Verify callback — accept all from mbedTLS side; capture the full
 * certificate chain for iPXE's create_validator().
 *
 * mbedtls_ssl_get_peer_cert() only preserves the leaf after session
 * finalization, so we capture intermediates here.  The callback is
 * invoked root-first (highest depth first); we prepend each cert
 * so the chain ends up leaf-first as iPXE expects.
 */
static int tls_mb_verify_cb ( void *ctx,
			      mbedtls_x509_crt *crt,
			      int depth,
			      uint32_t *flags ) {
	struct tls_mbedtls *tls = ctx;
	struct x509_link *link;
	int rc;

	if ( ! tls->chain ) {
		tls->chain = x509_alloc_chain();
		if ( ! tls->chain ) {
			DBGC ( tls, "TLSMB %p chain alloc failed\n", tls );
			return MBEDTLS_ERR_X509_ALLOC_FAILED;
		}
	}
	rc = x509_append_raw ( tls->chain, crt->raw.p, crt->raw.len );
	if ( rc ) {
		DBGC ( tls, "TLSMB %p cert append failed (depth=%d "
		       "len=%zd): %s\n", tls, depth, crt->raw.len,
		       strerror ( rc ) );
		return MBEDTLS_ERR_X509_FATAL_ERROR;
	}
	/* Move appended entry to head (callback is root-first) */
	link = list_last_entry ( &tls->chain->links,
				 struct x509_link, list );
	list_del ( &link->list );
	list_add ( &link->list, &tls->chain->links );
	DBGC ( tls, "TLSMB %p captured cert depth=%d %s\n",
	       tls, depth,
	       x509_name ( x509_first ( tls->chain ) ) );
	*flags = 0;
	return 0;
}

/**
 * Initialise shared mbedTLS config singleton
 *
 * @ret rc		Return status code
 */
static int tls_mb_init ( void ) {
	int ret;

	if ( tls_mb_initialized )
		return 0;

	mbedtls_platform_set_calloc_free ( ipxe_calloc, ipxe_free );

	if ( psa_crypto_init() != PSA_SUCCESS )
		return -ENOTSUP;

	mbedtls_entropy_init ( &tls_mb_entropy );
	mbedtls_ctr_drbg_init ( &tls_mb_ctr_drbg );
	ret = mbedtls_ctr_drbg_seed ( &tls_mb_ctr_drbg,
				      mbedtls_entropy_func,
				      &tls_mb_entropy, NULL, 0 );
	if ( ret )
		return tls_mb_error ( ret );

	mbedtls_ssl_config_init ( &tls_mb_conf );
	ret = mbedtls_ssl_config_defaults ( &tls_mb_conf,
					    MBEDTLS_SSL_IS_CLIENT,
					    MBEDTLS_SSL_TRANSPORT_STREAM,
					    MBEDTLS_SSL_PRESET_DEFAULT );
	if ( ret )
		return tls_mb_error ( ret );

	mbedtls_ssl_conf_authmode ( &tls_mb_conf,
				    MBEDTLS_SSL_VERIFY_OPTIONAL );
	mbedtls_ssl_conf_verify ( &tls_mb_conf, tls_mb_verify_cb, NULL );
	mbedtls_ssl_conf_rng ( &tls_mb_conf, mbedtls_ctr_drbg_random,
			       &tls_mb_ctr_drbg );
	mbedtls_debug_set_threshold ( 0 );

	tls_mb_initialized = 1;
	return 0;
}

/*
 * I/O callbacks
 */

static int tls_mb_recv ( void *ctx, unsigned char *buf, size_t len ) {
	struct tls_mbedtls *tls = ctx;
	struct io_buffer *iobuf;
	size_t copy;

	if ( list_empty ( &tls->rx_data ) )
		return MBEDTLS_ERR_SSL_WANT_READ;

	iobuf = list_first_entry ( &tls->rx_data,
				   struct io_buffer, list );
	copy = iob_len ( iobuf );
	if ( copy > len )
		copy = len;
	memcpy ( buf, iobuf->data, copy );
	iob_pull ( iobuf, copy );
	tls->rx_pending -= copy;

	if ( ! iob_len ( iobuf ) ) {
		list_del ( &iobuf->list );
		free_iob ( iobuf );
	}
	return ( int ) copy;
}

static int tls_mb_send ( void *ctx, const unsigned char *buf,
			 size_t len ) {
	struct tls_mbedtls *tls = ctx;
	struct io_buffer *iobuf;
	int rc;

	if ( xfer_window ( &tls->cipherstream ) == 0 )
		return MBEDTLS_ERR_SSL_WANT_WRITE;

	iobuf = xfer_alloc_iob ( &tls->cipherstream, len );
	if ( ! iobuf )
		return MBEDTLS_ERR_SSL_ALLOC_FAILED;

	memcpy ( iob_put ( iobuf, len ), buf, len );
	rc = xfer_deliver_iob ( &tls->cipherstream,
				iob_disown ( iobuf ) );
	if ( rc ) {
		if ( rc == -ENOBUFS )
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	return ( int ) len;
}

/*
 * Validator bridge
 */

static int tls_mb_start_validation ( struct tls_mbedtls *tls ) {
	int rc;

	if ( ! tls->chain || ! x509_first ( tls->chain ) ) {
		DBGC ( tls, "TLSMB %p no peer certificate\n", tls );
		return -EACCES_VERIFY;
	}

	pending_get ( &tls->validation );
	rc = create_validator ( &tls->validator, tls->chain, tls->root );
	if ( rc ) {
		pending_put ( &tls->validation );
		x509_chain_put ( tls->chain );
		tls->chain = NULL;
		return rc;
	}

	return 0;
}

static void tls_mb_validator_done ( struct tls_mbedtls *tls, int rc ) {
	struct x509_certificate *cert;

	pending_put ( &tls->validation );
	intf_restart ( &tls->validator, rc );

	if ( rc ) {
		DBGC ( tls, "TLSMB %p validation failed: %s\n",
		       tls, strerror ( rc ) );
		goto err;
	}

	cert = x509_first ( tls->chain );
	if ( ( rc = x509_check_name ( cert, tls->hostname ) ) != 0 ) {
		DBGC ( tls, "TLSMB %p cert does not match %s: %s\n",
		       tls, tls->hostname, strerror ( rc ) );
		goto err;
	}

	DBGC ( tls, "TLSMB %p validated for %s\n", tls, tls->hostname );
	x509_chain_put ( tls->chain );
	tls->chain = NULL;
	tls->ready = 1;
	xfer_window_changed ( &tls->plainstream );
	process_add ( &tls->process );
	return;

 err:
	x509_chain_put ( tls->chain );
	tls->chain = NULL;
	tls_mb_close ( tls, rc );
}

/*
 * RX data pump — decrypts and delivers to plainstream
 */
static void tls_mb_rx_pump ( struct tls_mbedtls *tls ) {
	struct io_buffer *iobuf;
	int ret;
	int rc;

	while ( 1 ) {
		iobuf = xfer_alloc_iob ( &tls->plainstream, 4096 );
		if ( ! iobuf )
			break;

		ret = mbedtls_ssl_read ( &tls->ssl, iobuf->data,
					 iob_tailroom ( iobuf ) );

		if ( ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET ) {
			free_iob ( iobuf );
			process_add ( &tls->process );
			continue;
		}
		if ( ret == MBEDTLS_ERR_SSL_WANT_READ ||
		     ret == MBEDTLS_ERR_SSL_WANT_WRITE ) {
			free_iob ( iobuf );
			break;
		}
		if ( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ) {
			free_iob ( iobuf );
			tls_mb_close ( tls, 0 );
			return;
		}
		if ( ret < 0 ) {
			free_iob ( iobuf );
			tls_mb_close ( tls, tls_mb_error ( ret ) );
			return;
		}
		if ( ret == 0 ) {
			free_iob ( iobuf );
			tls_mb_close ( tls, 0 );
			return;
		}

		iob_put ( iobuf, ret );
		if ( ( rc = xfer_deliver_iob ( &tls->plainstream,
					       iob_disown ( iobuf ) ) ) ) {
			tls_mb_close ( tls, rc );
			return;
		}
	}
}

/*
 * Process step — drives handshake then pumps data
 */
static void tls_mb_step ( struct tls_mbedtls *tls ) {
	int ret;

	if ( tls->closed )
		return;

	/* Phase 1: drive handshake */
	if ( ! tls->ready && ! is_pending ( &tls->validation ) ) {
		ret = mbedtls_ssl_handshake ( &tls->ssl );
		if ( ret == MBEDTLS_ERR_SSL_WANT_READ ||
		     ret == MBEDTLS_ERR_SSL_WANT_WRITE )
			return;
		if ( ret ) {
			DBGC ( tls, "TLSMB %p handshake failed: -%04x\n",
			       tls, (unsigned) -ret );
			tls_mb_close ( tls, tls_mb_error ( ret ) );
			return;
		}
		DBGC ( tls, "TLSMB %p handshake complete (%s)\n",
		       tls, mbedtls_ssl_get_version ( &tls->ssl ) );
		pending_put ( &tls->negotiation );

		ret = tls_mb_start_validation ( tls );
		if ( ret ) {
			tls_mb_close ( tls, ret );
			return;
		}
		return;
	}

	/* Phase 2: pump decrypted data */
	if ( tls->ready ) {
		int rc = tls_mb_tx_drain ( tls );
		if ( rc == -EWOULDBLOCK )
			return; /* wait for xfer_window_changed */
		if ( rc && rc != -EAGAIN )
			return; /* hard error, already closed */
		/* rc==0 (drained) or -EAGAIN (WANT_READ): pump RX */
		tls_mb_rx_pump ( tls );
	}
}

/*
 * Teardown
 */
static void tls_mb_close ( struct tls_mbedtls *tls, int rc ) {
	if ( tls->closed )
		return;
	tls->closed = 1;

	if ( tls->ready && rc == 0 )
		mbedtls_ssl_close_notify ( &tls->ssl );

	pending_put ( &tls->negotiation );
	pending_put ( &tls->validation );
	process_del ( &tls->process );
	intf_shutdown ( &tls->validator, rc );
	intf_shutdown ( &tls->cipherstream, rc );
	intf_shutdown ( &tls->plainstream, rc );
}

static void tls_mb_free ( struct refcnt *refcnt ) {
	struct tls_mbedtls *tls = container_of (
		refcnt, struct tls_mbedtls, refcnt );
	struct io_buffer *iobuf, *tmp;

	mbedtls_ssl_free ( &tls->ssl );
	if ( tls->tx_pending )
		free_iob ( tls->tx_pending );
	list_for_each_entry_safe ( iobuf, tmp, &tls->rx_data, list ) {
		list_del ( &iobuf->list );
		free_iob ( iobuf );
	}
	if ( tls->chain )
		x509_chain_put ( tls->chain );
	x509_root_put ( tls->root );
	free ( tls->hostname );
	free ( tls );
}

/*
 * Flow control
 */
static size_t tls_mb_plain_window ( struct tls_mbedtls *tls ) {
	if ( ! tls->ready || tls->tx_pending )
		return 0;
	return xfer_window ( &tls->cipherstream );
}

static size_t tls_mb_cipher_window ( struct tls_mbedtls *tls ) {
	if ( ! tls->ready )
		return -1UL;
	return xfer_window ( &tls->plainstream );
}

static void tls_mb_tx_resume ( struct tls_mbedtls *tls ) {
	process_add ( &tls->process );
}

/*
 * IOB allocation passthrough
 */
static struct io_buffer *
tls_mb_alloc_iob ( struct tls_mbedtls *tls __unused, size_t len ) {
	return alloc_iob ( len );
}

/*
 * Job progress
 */
static int tls_mb_progress ( struct tls_mbedtls *tls,
			     struct job_progress *progress ) {
	if ( is_pending ( &tls->validation ) )
		return job_progress ( &tls->validator, progress );
	return job_progress ( &tls->cipherstream, progress );
}

/**
 * Drain pending TX data through mbedtls_ssl_write
 *
 * @v tls		TLS connection
 * @ret rc		0 if fully drained, -EWOULDBLOCK if WANT_WRITE,
 *			-EAGAIN if WANT_READ, or negative error
 */
static int tls_mb_tx_drain ( struct tls_mbedtls *tls ) {
	const unsigned char *buf;
	size_t remaining;
	int ret;

	while ( tls->tx_pending ) {
		buf = tls->tx_pending->data + tls->tx_offset;
		remaining = iob_len ( tls->tx_pending ) - tls->tx_offset;

		ret = mbedtls_ssl_write ( &tls->ssl, buf, remaining );
		if ( ret == MBEDTLS_ERR_SSL_WANT_WRITE )
			return -EWOULDBLOCK;
		if ( ret == MBEDTLS_ERR_SSL_WANT_READ )
			return -EAGAIN;
		if ( ret == MBEDTLS_ERR_SSL_RECEIVED_NEW_SESSION_TICKET ) {
			/* TLS 1.3 post-handshake ticket — retry */
			continue;
		}
		if ( ret < 0 ) {
			free_iob ( tls->tx_pending );
			tls->tx_pending = NULL;
			tls->tx_offset = 0;
			tls_mb_close ( tls, tls_mb_error ( ret ) );
			return tls_mb_error ( ret );
		}
		tls->tx_offset += ret;
		if ( tls->tx_offset >= iob_len ( tls->tx_pending ) ) {
			free_iob ( tls->tx_pending );
			tls->tx_pending = NULL;
			tls->tx_offset = 0;
		}
	}
	return 0;
}

/*
 * Plaintext delivery (HTTP → shim → mbedtls_ssl_write)
 */
static int tls_mb_plain_deliver ( struct tls_mbedtls *tls,
				  struct io_buffer *iobuf,
				  struct xfer_metadata *meta __unused ) {
	int rc;

	if ( ! tls->ready || tls->tx_pending ) {
		free_iob ( iobuf );
		return tls->ready ? -EBUSY : -ENOTCONN;
	}

	tls->tx_pending = iobuf;
	tls->tx_offset = 0;
	rc = tls_mb_tx_drain ( tls );
	if ( rc == -EWOULDBLOCK || rc == -EAGAIN ) {
		/* Partial send — data saved in tx_pending, will resume
		 * via process step. Return 0: caller must not retry. */
		process_add ( &tls->process );
		return 0;
	}
	return rc; /* 0 on full drain, negative on hard error */
}

/*
 * Ciphertext delivery (TCP → shim → rx_data queue)
 */
static int tls_mb_cipher_deliver ( struct tls_mbedtls *tls,
				   struct io_buffer *iobuf,
				   struct xfer_metadata *meta __unused ) {
	list_add_tail ( &iobuf->list, &tls->rx_data );
	tls->rx_pending += iob_len ( iobuf );
	process_add ( &tls->process );
	return 0;
}

/*
 * Interface operations and descriptors
 */

static struct interface_operation tls_mb_plain_ops[] = {
	INTF_OP ( xfer_alloc_iob, struct tls_mbedtls *,
		  tls_mb_alloc_iob ),
	INTF_OP ( xfer_deliver, struct tls_mbedtls *,
		  tls_mb_plain_deliver ),
	INTF_OP ( xfer_window, struct tls_mbedtls *,
		  tls_mb_plain_window ),
	INTF_OP ( job_progress, struct tls_mbedtls *,
		  tls_mb_progress ),
	INTF_OP ( intf_close, struct tls_mbedtls *,
		  tls_mb_close ),
};

static struct interface_descriptor tls_mb_plain_desc =
	INTF_DESC_PASSTHRU ( struct tls_mbedtls, plainstream,
			     tls_mb_plain_ops, cipherstream );

static struct interface_operation tls_mb_cipher_ops[] = {
	INTF_OP ( xfer_deliver, struct tls_mbedtls *,
		  tls_mb_cipher_deliver ),
	INTF_OP ( xfer_window, struct tls_mbedtls *,
		  tls_mb_cipher_window ),
	INTF_OP ( xfer_window_changed, struct tls_mbedtls *,
		  tls_mb_tx_resume ),
	INTF_OP ( intf_close, struct tls_mbedtls *,
		  tls_mb_close ),
};

static struct interface_descriptor tls_mb_cipher_desc =
	INTF_DESC_PASSTHRU ( struct tls_mbedtls, cipherstream,
			     tls_mb_cipher_ops, plainstream );

static struct interface_operation tls_mb_validator_ops[] = {
	INTF_OP ( intf_close, struct tls_mbedtls *,
		  tls_mb_validator_done ),
};

static struct interface_descriptor tls_mb_validator_desc =
	INTF_DESC ( struct tls_mbedtls, validator,
		    tls_mb_validator_ops );

static struct process_descriptor tls_mb_process_desc =
	PROC_DESC_ONCE ( struct tls_mbedtls, process, tls_mb_step );

/**
 * Add mbedTLS TLS connection
 *
 * @v xfer		Data transfer interface
 * @v name		Host name
 * @v root		Root certificate store, or NULL for default
 * @v key		Private key, or NULL for no client cert
 * @ret rc		Return status code
 */
int add_tls ( struct interface *xfer, const char *name,
	      struct x509_root *root, struct private_key *key ) {
	struct tls_mbedtls *tls;
	int ret;
	int rc;

	/* Client certs not supported in MVP */
	if ( key && privkey_cursor ( key )->len ) {
		DBGC ( key, "TLSMB client certs not yet supported\n" );
		return -ENOTSUP;
	}

	if ( ( rc = tls_mb_init() ) != 0 )
		return rc;

	tls = zalloc ( sizeof ( *tls ) );
	if ( ! tls )
		return -ENOMEM;

	ref_init ( &tls->refcnt, tls_mb_free );
	intf_init ( &tls->plainstream, &tls_mb_plain_desc,
		    &tls->refcnt );
	intf_init ( &tls->cipherstream, &tls_mb_cipher_desc,
		    &tls->refcnt );
	intf_init ( &tls->validator, &tls_mb_validator_desc,
		    &tls->refcnt );
	process_init_stopped ( &tls->process, &tls_mb_process_desc,
			       &tls->refcnt );
	INIT_LIST_HEAD ( &tls->rx_data );

	tls->root = x509_root_get ( root ? root : &root_certificates );
	tls->conf = &tls_mb_conf;
	tls->hostname = strdup ( name );
	if ( ! tls->hostname ) {
		rc = -ENOMEM;
		goto err;
	}

	mbedtls_ssl_init ( &tls->ssl );
	ret = mbedtls_ssl_setup ( &tls->ssl, tls->conf );
	if ( ret ) {
		rc = tls_mb_error ( ret );
		goto err;
	}
	mbedtls_ssl_set_bio ( &tls->ssl, tls,
			      tls_mb_send, tls_mb_recv, NULL );
	mbedtls_ssl_set_verify ( &tls->ssl, tls_mb_verify_cb, tls );
	ret = mbedtls_ssl_set_hostname ( &tls->ssl, name );
	if ( ret ) {
		rc = tls_mb_error ( ret );
		goto err;
	}

	pending_get ( &tls->negotiation );
	intf_insert ( xfer, &tls->plainstream, &tls->cipherstream );
	process_add ( &tls->process );
	ref_put ( &tls->refcnt );
	return 0;

 err:
	ref_put ( &tls->refcnt );
	return rc;
}

/* Drag in objects via add_tls() */
REQUIRING_SYMBOL ( add_tls );

/* Drag in crypto configuration */
REQUIRE_OBJECT ( config_crypto );
