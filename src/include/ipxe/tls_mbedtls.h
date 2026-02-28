#ifndef _IPXE_TLS_MBEDTLS_H
#define _IPXE_TLS_MBEDTLS_H

/**
 * @file
 *
 * mbedTLS-backed TLS layer
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( PERMITTED );

#include <ipxe/interface.h>
#include <ipxe/x509.h>
#include <ipxe/privkey.h>

extern int add_tls ( struct interface *xfer, const char *name,
		     struct x509_root *root, struct private_key *key );

#endif /* _IPXE_TLS_MBEDTLS_H */
