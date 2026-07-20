#ifndef APROXY_PACKET_FLOW_H
#define APROXY_PACKET_FLOW_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"
#include "aproxy/error.h"

typedef struct aproxy_packet_flow aproxy_packet_flow_t;

typedef void (*aproxy_packet_flow_data_cb)(
    aproxy_packet_flow_t *flow,
    const aproxy_addr_t *source,
    const uint8_t *data,
    size_t len,
    void *user_data);

typedef void (*aproxy_packet_flow_event_cb)(
    aproxy_packet_flow_t *flow,
    int status,
    void *user_data);

typedef struct aproxy_packet_flow_datagram {
    const aproxy_addr_t *destination;
    const uint8_t *data;
    size_t len;
} aproxy_packet_flow_datagram_t;

int aproxy_packet_flow_send(aproxy_packet_flow_t *flow,
                            const aproxy_addr_t *destination,
                            const uint8_t *data,
                            size_t len);

/*
 * Accepts datagrams in order and reports how many are owned by the transport.
 * Implementations may send synchronously or copy unsent tails into a bounded
 * asynchronous queue before returning.
 */
int aproxy_packet_flow_send_batch(
    aproxy_packet_flow_t *flow,
    const aproxy_packet_flow_datagram_t *datagrams,
    size_t count,
    size_t *accepted);

int aproxy_packet_flow_supports_batch(const aproxy_packet_flow_t *flow);

int aproxy_packet_flow_close(aproxy_packet_flow_t *flow);

uint32_t aproxy_packet_flow_id(const aproxy_packet_flow_t *flow);

void *aproxy_packet_flow_native(const aproxy_packet_flow_t *flow);

void aproxy_packet_flow_free(aproxy_packet_flow_t *flow);

#endif
