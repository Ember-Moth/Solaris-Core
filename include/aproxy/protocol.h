#ifndef APROXY_PROTOCOL_H
#define APROXY_PROTOCOL_H

#include "aproxy/address.h"
#include "aproxy/stream.h"

typedef struct aproxy_protocol aproxy_protocol_t;

typedef struct aproxy_protocol_vtable {
    int (*start)(void *impl);
    int (*open_stream)(void *impl,
                       const aproxy_addr_t *destination,
                       aproxy_stream_data_cb on_data,
                       aproxy_stream_event_cb on_open,
                       aproxy_stream_event_cb on_close,
                       void *user_data,
                       aproxy_stream_t **out);
    void (*close)(void *impl);
    void (*free)(void *impl);
} aproxy_protocol_vtable_t;

struct aproxy_protocol {
    const char *name;
    const aproxy_protocol_vtable_t *vtable;
    void *impl;
};

int aproxy_protocol_start(aproxy_protocol_t *protocol);
int aproxy_protocol_open_stream(aproxy_protocol_t *protocol,
                                const aproxy_addr_t *destination,
                                aproxy_stream_data_cb on_data,
                                aproxy_stream_event_cb on_open,
                                aproxy_stream_event_cb on_close,
                                void *user_data,
                                aproxy_stream_t **out);
void aproxy_protocol_close(aproxy_protocol_t *protocol);
void aproxy_protocol_free(aproxy_protocol_t *protocol);

#endif
