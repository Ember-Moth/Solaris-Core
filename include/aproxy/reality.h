#ifndef APROXY_REALITY_H
#define APROXY_REALITY_H

#include <stdint.h>

#include "aproxy/error.h"

#define APROXY_REALITY_PUBLIC_KEY_SIZE 32u
#define APROXY_REALITY_SHORT_ID_SIZE 8u

typedef struct aproxy_reality_config {
    uint8_t public_key[APROXY_REALITY_PUBLIC_KEY_SIZE];
    uint8_t short_id[APROXY_REALITY_SHORT_ID_SIZE];
    int enabled;
} aproxy_reality_config_t;

/* An empty short_id selects the all-zero server short ID. */
int aproxy_reality_config_parse(const char *public_key,
                                const char *short_id,
                                aproxy_reality_config_t *out);

#endif
