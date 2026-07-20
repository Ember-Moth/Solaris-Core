#ifndef APROXY_STREAM_INTERNAL_H
#define APROXY_STREAM_INTERNAL_H

#include "aproxy/stream.h"

typedef struct aproxy_stream_vtable {
    int (*write)(void *impl, const uint8_t *data, size_t len);
    int (*close)(void *impl);
    uint32_t (*id)(const void *impl);
    void *(*native)(const void *impl);
    void (*free)(void *impl);
} aproxy_stream_vtable_t;

struct aproxy_stream {
    const aproxy_stream_vtable_t *vtable;
    void *impl;
};

int aproxy_stream_new(const aproxy_stream_vtable_t *vtable,
                      void *impl,
                      aproxy_stream_t **out);

#endif
