#ifndef SOLARIS_ADDRESS_H
#define SOLARIS_ADDRESS_H

#include <stddef.h>
#include <stdint.h>
#include <solaris/error.h>

enum { SOLARIS_ADDRESS_IPV4 = 4, SOLARIS_ADDRESS_IPV6 = 6, SOLARIS_ADDRESS_DOMAIN = 255 };
typedef struct solaris_address {
    uint32_t family;
    uint32_t scope_id;
    uint16_t port;
    uint8_t ip[16];
    char host[256];
} solaris_address_t;

struct sockaddr;
struct sockaddr_storage;
solaris_status_t solaris_address_parse(const char *host, uint16_t port, solaris_address_t *out);
solaris_status_t solaris_address_to_sockaddr(const solaris_address_t *address,
                                             struct sockaddr_storage *out);
solaris_status_t solaris_address_from_sockaddr(const struct sockaddr *address, solaris_address_t *out);
int solaris_address_equal(const solaris_address_t *a, const solaris_address_t *b);

#endif
