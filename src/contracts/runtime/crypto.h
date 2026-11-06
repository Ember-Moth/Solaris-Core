#ifndef SOLARIS_CRYPTO_SOURCE_H
#define SOLARIS_CRYPTO_SOURCE_H
#include <stddef.h>
#include <stdint.h>
#include <solaris/error.h>
/* Optional deterministic providers for protocol tests. Null functions use
 * the crypto library CSPRNG and the system Unix clock. Context is borrowed
 * until all channels close; providers may be called concurrently. */
typedef struct solaris_crypto_source {
    void *context;
    solaris_status_t (*random)(void *, uint8_t *, size_t);
    uint64_t (*unix_seconds)(void *);
} solaris_crypto_source_t;
#endif
