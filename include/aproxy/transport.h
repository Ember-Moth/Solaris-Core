#ifndef APROXY_TRANSPORT_H
#define APROXY_TRANSPORT_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

typedef struct aproxy_transport aproxy_transport_t;

typedef void (*aproxy_transport_ready_cb)(aproxy_transport_t *transport,
                                          int status,
                                          void *user_data);
typedef void (*aproxy_transport_data_cb)(aproxy_transport_t *transport,
                                         const uint8_t *data,
                                         size_t len,
                                         void *user_data);
typedef void (*aproxy_transport_close_cb)(aproxy_transport_t *transport,
                                          int status,
                                          void *user_data);

typedef struct aproxy_transport_vtable {
    int (*connect)(void *impl);
    int (*write)(void *impl, const uint8_t *data, size_t len);
    void (*close)(void *impl);
    void (*free)(void *impl);
} aproxy_transport_vtable_t;

struct aproxy_transport {
    const aproxy_transport_vtable_t *vtable;
    void *impl;
};

int aproxy_transport_connect(aproxy_transport_t *transport);
int aproxy_transport_write(aproxy_transport_t *transport,
                           const uint8_t *data,
                           size_t len);
void aproxy_transport_close(aproxy_transport_t *transport);
void aproxy_transport_free(aproxy_transport_t *transport);

#endif
