#ifndef APROXY_INBOUND_H
#define APROXY_INBOUND_H

#include <uv.h>

#include "aproxy/address.h"
#include "aproxy/stream.h"

typedef struct aproxy_inbound aproxy_inbound_t;

typedef void (*aproxy_inbound_stream_cb)(aproxy_inbound_t *inbound,
                                         aproxy_stream_t *stream,
                                         const aproxy_addr_t *destination,
                                         void *user_data);

typedef struct aproxy_inbound_vtable {
    int (*start)(void *impl);
    void (*stop)(void *impl);
    void (*free)(void *impl);
} aproxy_inbound_vtable_t;

struct aproxy_inbound {
    const char *tag;
    const aproxy_inbound_vtable_t *vtable;
    void *impl;
};

int aproxy_inbound_start(aproxy_inbound_t *inbound);
void aproxy_inbound_stop(aproxy_inbound_t *inbound);
void aproxy_inbound_free(aproxy_inbound_t *inbound);

#endif
