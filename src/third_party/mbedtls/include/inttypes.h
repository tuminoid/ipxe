/**
 * Minimal <inttypes.h> for mbedTLS on iPXE
 *
 * Shadows the system inttypes.h which conflicts with iPXE's types.
 * Provides only the PRI macros that mbedTLS actually uses.
 */
#ifndef _IPXE_INTTYPES_H
#define _IPXE_INTTYPES_H

#include <stdint.h>

/* LP64: long = 64-bit */
#define PRId8   "d"
#define PRId16  "d"
#define PRId32  "d"
#define PRId64  "lld"
#define PRIi64  "lli"
#define PRIu32  "u"
#define PRIu64  "llu"
#define PRIx32  "x"
#define PRIx64  "llx"
#define PRIX64  "llX"

#endif /* _IPXE_INTTYPES_H */
