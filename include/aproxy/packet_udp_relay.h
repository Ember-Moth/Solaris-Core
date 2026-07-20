#ifndef APROXY_PACKET_UDP_RELAY_H
#define APROXY_PACKET_UDP_RELAY_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/packet_session.h"
#include "aproxy/router.h"

typedef struct aproxy_packet_udp_relay aproxy_packet_udp_relay_t;

#define APROXY_PACKET_UDP_RELAY_DEFAULT_PENDING_LIMIT (1024u * 1024u)
#define APROXY_PACKET_UDP_RELAY_DEFAULT_RX_LIMIT (1024u * 1024u)
#define APROXY_PACKET_UDP_RELAY_DEFAULT_IDLE_TIMEOUT_MS 60000u
#define APROXY_PACKET_UDP_RELAY_DEFAULT_SNIFF_BYTES 16384u
#define APROXY_PACKET_UDP_RELAY_DEFAULT_SNIFF_PACKETS 4u

typedef struct aproxy_packet_udp_relay_stats {
    uint64_t sessions_opened;
    uint64_t sessions_unsupported;
    uint64_t open_errors;
    uint64_t udp_packets_in;
    uint64_t udp_payload_bytes_in;
    uint64_t uot_packets_out;
    uint64_t uot_bytes_out;
    uint64_t uot_packets_in;
    uint64_t uot_payload_bytes_in;
    uint64_t packets_written;
    uint64_t packet_bytes_written;
    uint64_t write_errors;
    uint64_t rx_errors;
    /* Historical name: packet-flow path, including Direct, SS UDP and XUDP. */
    uint64_t native_packets_out;
    uint64_t native_payload_bytes_out;
    uint64_t native_send_batches;
    uint64_t native_send_batch_packets;
    uint64_t native_packets_in;
    uint64_t native_payload_bytes_in;
    uint64_t queue_limit_drops;
    uint64_t rx_limit_closes;
    uint64_t sessions_expired;
    uint64_t sessions_reaped;
    uint64_t sniff_attempts;
    uint64_t sniff_matches;
    uint64_t sniff_quic_matches;
    uint64_t sniff_fallbacks;
} aproxy_packet_udp_relay_stats_t;

typedef struct aproxy_packet_udp_relay_config {
    aproxy_router_t *router;
    /* Zero selects the corresponding APROXY_PACKET_UDP_RELAY_DEFAULT limit. */
    size_t pending_tx_limit;
    size_t rx_limit;
    /* Zero selects APROXY_PACKET_UDP_RELAY_DEFAULT_IDLE_TIMEOUT_MS. */
    uint64_t idle_timeout_ms;
    int sniffing_enabled;
    /* Zero selects the APROXY_PACKET_UDP_RELAY_DEFAULT values. */
    size_t sniffing_max_bytes;
    size_t sniffing_max_packets;
} aproxy_packet_udp_relay_config_t;

int aproxy_packet_udp_relay_new(
    const aproxy_packet_udp_relay_config_t *config,
    aproxy_packet_udp_relay_t **out);

void aproxy_packet_udp_relay_free(aproxy_packet_udp_relay_t *relay);

void aproxy_packet_udp_relay_maintenance(
    aproxy_packet_udp_relay_t *relay);

/*
 * Payloads submitted between begin/end remain borrowed until end returns.
 * The relay may use that lifetime to issue one native datagram batch without
 * copying payload bytes or waiting for a timer.
 */
void aproxy_packet_udp_relay_begin_packet_batch(
    aproxy_packet_udp_relay_t *relay);

int aproxy_packet_udp_relay_end_packet_batch(
    aproxy_packet_udp_relay_t *relay);

int aproxy_packet_udp_relay_on_session(
    aproxy_packet_udp_relay_t *relay,
    aproxy_packet_session_t *session,
    aproxy_stream_t *packet_stream,
    const aproxy_packet_flow_key_t *key);

int aproxy_packet_udp_relay_on_packet(
    aproxy_packet_udp_relay_t *relay,
    aproxy_packet_session_t *session,
    aproxy_stream_t *packet_stream,
    const uint8_t *packet,
    size_t packet_len);

void aproxy_packet_udp_relay_get_stats(
    const aproxy_packet_udp_relay_t *relay,
    aproxy_packet_udp_relay_stats_t *out_stats);

#endif
