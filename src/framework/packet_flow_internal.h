#ifndef APROXY_PACKET_FLOW_INTERNAL_H
#define APROXY_PACKET_FLOW_INTERNAL_H

#include "aproxy/packet_flow.h"

typedef struct aproxy_packet_flow_vtable {
    int (*send)(void *impl,
                const aproxy_addr_t *destination,
                const uint8_t *data,
                size_t len);
    int (*send_batch)(void *impl,
                      const aproxy_packet_flow_datagram_t *datagrams,
                      size_t count,
                      size_t *accepted);
    int (*close)(void *impl);
    uint32_t (*id)(const void *impl);
    void *(*native)(const void *impl);
    void (*free)(void *impl);
} aproxy_packet_flow_vtable_t;

struct aproxy_packet_flow {
    const aproxy_packet_flow_vtable_t *vtable;
    void *impl;
};

int aproxy_packet_flow_new(const aproxy_packet_flow_vtable_t *vtable,
                           void *impl,
                           aproxy_packet_flow_t **out);

#endif
