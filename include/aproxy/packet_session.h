#ifndef APROXY_PACKET_SESSION_H
#define APROXY_PACKET_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"
#include "aproxy/stream.h"

typedef struct aproxy_packet_session aproxy_packet_session_t;
typedef struct aproxy_packet_session_table aproxy_packet_session_table_t;

typedef enum aproxy_packet_family {
    APROXY_PACKET_FAMILY_IPV4 = 4,
    APROXY_PACKET_FAMILY_IPV6 = 6
} aproxy_packet_family_t;

typedef enum aproxy_packet_proto {
    APROXY_PACKET_PROTO_TCP = 6,
    APROXY_PACKET_PROTO_UDP = 17
} aproxy_packet_proto_t;

typedef struct aproxy_packet_flow_key {
    uint8_t family;
    uint8_t proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t src_addr[16];
    uint8_t dst_addr[16];
} aproxy_packet_flow_key_t;

typedef struct aproxy_packet_session_stats {
    uint64_t sessions_created;
    uint64_t sessions_active;
    uint64_t packets_classified;
    uint64_t packets_delivered;
    uint64_t packets_invalid;
    uint64_t packets_unsupported;
    uint64_t packets_fragmented;
    uint64_t packets_written;
    uint64_t bytes_delivered;
    uint64_t bytes_written;
    uint64_t write_errors;
} aproxy_packet_session_stats_t;

typedef void (*aproxy_packet_session_open_cb)(
    aproxy_packet_session_t *session,
    aproxy_stream_t *stream,
    const aproxy_packet_flow_key_t *key,
    void *user_data);

typedef void (*aproxy_packet_session_data_cb)(
    aproxy_packet_session_t *session,
    aproxy_stream_t *stream,
    const uint8_t *packet,
    size_t packet_len,
    void *user_data);

typedef int (*aproxy_packet_session_write_cb)(
    aproxy_packet_session_t *session,
    const uint8_t *packet,
    size_t packet_len,
    void *user_data);

typedef struct aproxy_packet_session_table_config {
    aproxy_packet_session_open_cb on_open;
    aproxy_packet_session_data_cb on_data;
    aproxy_packet_session_write_cb on_write;
    void *user_data;
} aproxy_packet_session_table_config_t;

int aproxy_packet_session_table_new(
    const aproxy_packet_session_table_config_t *config,
    aproxy_packet_session_table_t **out);

void aproxy_packet_session_table_free(aproxy_packet_session_table_t *table);

int aproxy_packet_session_table_dispatch_packet(
    aproxy_packet_session_table_t *table,
    const uint8_t *packet,
    size_t packet_len);

void aproxy_packet_session_table_get_stats(
    const aproxy_packet_session_table_t *table,
    aproxy_packet_session_stats_t *out_stats);

uint32_t aproxy_packet_session_id(const aproxy_packet_session_t *session);

const aproxy_packet_flow_key_t *aproxy_packet_session_key(
    const aproxy_packet_session_t *session);

uint64_t aproxy_packet_flow_key_hash(const aproxy_packet_flow_key_t *key);

#endif
