/*
 * 128-bit unsigned division for mbedTLS bignum on x86_64
 */

#ifdef __SIZEOF_INT128__

#include "libgcc.h"

typedef unsigned __int128 uint128_t;
typedef signed __int128 int128_t;

__libgcc uint128_t __udivti3 ( uint128_t num, uint128_t den ) {
	uint128_t quot = 0, bit = 1;
	if ( den == 0 )
		return 1/((unsigned)den); /* Intentional divide by zero,
					     without triggering a compiler
					     warning about division by
					     zero. */
	while ( ( ( int128_t ) den ) >= 0 && den < num ) {
		den <<= 1;
		bit <<= 1;
	}
	while ( bit ) {
		if ( num >= den ) {
			num -= den;
			quot |= bit;
		}
		den >>= 1;
		bit >>= 1;
	}
	return quot;
}

#endif /* __SIZEOF_INT128__ */
