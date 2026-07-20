#ifndef APROXY_OUTBOUND_GROUP_H
#define APROXY_OUTBOUND_GROUP_H

#include <stddef.h>

#include "aproxy/outbound.h"

typedef enum aproxy_outbound_group_mode {
    APROXY_OUTBOUND_GROUP_ROUND_ROBIN = 0
} aproxy_outbound_group_mode_t;

typedef struct aproxy_outbound_group_config {
    const char *tag;
    /* Members must use the same UDP transport and UoT version. */
    aproxy_outbound_t **members;
    size_t member_count;
    aproxy_outbound_group_mode_t mode;
} aproxy_outbound_group_config_t;

int aproxy_outbound_group_new(const aproxy_outbound_group_config_t *config,
                              aproxy_outbound_t **out);

#endif
