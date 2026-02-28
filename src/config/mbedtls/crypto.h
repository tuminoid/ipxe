FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );

/** Use mbedTLS as the TLS backend */
#define TLS_BACKEND_MBEDTLS

/*
 * mbedTLS handles cipher-suite negotiation internally.
 * Disable iPXE's native TLS key-exchange registrations so the
 * mishmash cipher-suite objects are not pulled in.
 */
#undef CRYPTO_EXCHANGE_PUBKEY
#undef CRYPTO_EXCHANGE_DHE
#undef CRYPTO_EXCHANGE_ECDHE
