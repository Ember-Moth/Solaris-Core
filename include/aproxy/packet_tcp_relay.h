#ifndef APROXY_PACKET_TCP_RELAY_H
#define APROXY_PACKET_TCP_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include "aproxy/packet_session.h"
#include "aproxy/router.h"

typedef struct aproxy_packet_tcp_relay aproxy_packet_tcp_relay_t;

#define APROXY_PACKET_TCP_RELAY_DEFAULT_PENDING_LIMIT (1024u * 1024u)
#define APROXY_PACKET_TCP_RELAY_DEFAULT_IDLE_TIMEOUT_MS 300000u
#define APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_BYTES 16384u
#define APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_TIMEOUT_MS 100u

typedef struct aproxy_packet_tcp_relay_stats {
    uint64_t sessions_opened;
    uint64_t sessions_unsupported;
    uint64_t listeners_opened;
    uint64_t listeners_closed;
    uint64_t listeners_active;
    uint64_t accepts;
    uint64_t open_errors;
    uint64_t tcp_packets_in;
    uint64_t tcp_payload_bytes_in;
    uint64_t outbound_bytes_out;
    uint64_t outbound_bytes_in;
    uint64_t packets_written;
    uint64_t packet_bytes_written;
    uint64_t write_errors;
    uint64_t rx_errors;
    uint64_t queue_overflow_closes;
    uint64_t sessions_expired;
    uint64_t sessions_reaped;
    uint64_t sniff_attempts;
    uint64_t sniff_matches;
    uint64_t sniff_http_matches;
    uint64_t sniff_tls_matches;
    uint64_t sniff_fallbacks;
    uint64_t sniff_timeouts;
} aproxy_packet_tcp_relay_stats_t;

typedef struct aproxy_packet_tcp_relay_config {
    uv_loop_t *loop;
    aproxy_router_t *router;
    /* Zero selects APROXY_PACKET_TCP_RELAY_DEFAULT_PENDING_LIMIT. */
    size_t pending_to_outbound_limit;
    size_t pending_to_client_limit;
    /* Zero selects APROXY_PACKET_TCP_RELAY_DEFAULT_IDLE_TIMEOUT_MS. */
    uint64_t idle_timeout_ms;
    int sniffing_enabled;
    /* Zero selects APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_BYTES. */
    size_t sniffing_max_bytes;
    /* Zero selects APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_TIMEOUT_MS. */
    uint64_t sniffing_timeout_ms;
} aproxy_packet_tcp_relay_config_t;

int aproxy_packet_tcp_relay_new(
    const aproxy_packet_tcp_relay_config_t *config,
    aproxy_packet_tcp_relay_t **out);

void aproxy_packet_tcp_relay_free(aproxy_packet_tcp_relay_t *relay);

void aproxy_packet_tcp_relay_maintenance(
    aproxy_packet_tcp_relay_t *relay);

int aproxy_packet_tcp_relay_on_session(
    aproxy_packet_tcp_relay_t *relay,
    aproxy_packet_session_t *session,
    aproxy_stream_t *packet_stream,
    const aproxy_packet_flow_key_t *key);

int aproxy_packet_tcp_relay_on_packet(
    aproxy_packet_tcp_relay_t *relay,
    aproxy_packet_session_t *session,
    aproxy_stream_t *packet_stream,
    const uint8_t *packet,
    size_t packet_len);

void aproxy_packet_tcp_relay_get_stats(
    const aproxy_packet_tcp_relay_t *relay,
    aproxy_packet_tcp_relay_stats_t *out_stats);

#endif
