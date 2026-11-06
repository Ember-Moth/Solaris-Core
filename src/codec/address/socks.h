#ifndef SOLARIS_SOCKS_ADDRESS_H
#define SOLARIS_SOCKS_ADDRESS_H
#include "contracts/io/address.h"
#include <stddef.h>
/* Wire serialization also permits port zero for protocol metadata. Ordinary
 * destination operations use write, which retains strict nonzero validation. */
solaris_status_t solaris_socks_address_encode(const solaris_address_t *address,
    uint8_t *out, size_t capacity, size_t *written);
solaris_status_t solaris_socks_address_write(const solaris_address_t *address,
    uint8_t *out, size_t capacity, size_t *written);
solaris_status_t solaris_socks_address_read(const uint8_t *data, size_t size,
    solaris_address_t *out, size_t *consumed);
#endif
