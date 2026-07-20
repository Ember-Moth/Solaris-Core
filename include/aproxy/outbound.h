#ifndef APROXY_OUTBOUND_H
#define APROXY_OUTBOUND_H

#include <stdint.h>

#include "aproxy/address.h"
#include "aproxy/packet_flow.h"
#include "aproxy/stream.h"

typedef struct aproxy_outbound aproxy_outbound_t;

/* UDP framing is an outbound protocol capability, not a TUN property. */
typedef enum aproxy_outbound_udp_transport {
    APROXY_OUTBOUND_UDP_PACKET = 0,
    APROXY_OUTBOUND_UDP_UOT = 1
} aproxy_outbound_udp_transport_t;

typedef void (*aproxy_outbound_event_cb)(aproxy_outbound_t *outbound,
                                         int status,
                                         void *user_data);

typedef struct aproxy_outbound_vtable {
    int (*connect)(void *impl);
    int (*open_stream)(void *impl,
                       const aproxy_addr_t *destination,
                       aproxy_stream_data_cb on_data,
                       aproxy_stream_event_cb on_open,
                       aproxy_stream_event_cb on_close,
                       void *user_data,
                       aproxy_stream_t **out);
    int (*open_packet)(void *impl,
                       const aproxy_addr_t *initial_destination,
                       aproxy_packet_flow_data_cb on_data,
                       aproxy_packet_flow_event_cb on_open,
                       aproxy_packet_flow_event_cb on_close,
                       void *user_data,
                       aproxy_packet_flow_t **out);
    void (*close)(void *impl);
    void (*free)(void *impl);
} aproxy_outbound_vtable_t;

struct aproxy_outbound {
    const char *tag;
    const aproxy_outbound_vtable_t *vtable;
    void *impl;
    aproxy_outbound_udp_transport_t udp_transport;
    uint8_t uot_version;
};

int aproxy_outbound_connect(aproxy_outbound_t *outbound);

int aproxy_outbound_open_stream(aproxy_outbound_t *outbound,
                                const aproxy_addr_t *destination,
                                aproxy_stream_data_cb on_data,
                                aproxy_stream_event_cb on_open,
                                aproxy_stream_event_cb on_close,
                                void *user_data,
                                aproxy_stream_t **out);

int aproxy_outbound_open_packet(aproxy_outbound_t *outbound,
                                const aproxy_addr_t *initial_destination,
                                aproxy_packet_flow_data_cb on_data,
                                aproxy_packet_flow_event_cb on_open,
                                aproxy_packet_flow_event_cb on_close,
                                void *user_data,
                                aproxy_packet_flow_t **out);

void aproxy_outbound_close(aproxy_outbound_t *outbound);

void aproxy_outbound_free(aproxy_outbound_t *outbound);

#endif
