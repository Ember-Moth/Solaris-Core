#ifndef APROXY_SOCKS5_INBOUND_H
#define APROXY_SOCKS5_INBOUND_H

#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include "aproxy/inbound.h"
#include "aproxy/dns.h"
#include "aproxy/router.h"

#define APROXY_SOCKS5_UDP_DEFAULT_PENDING_TX_LIMIT (1024u * 1024u)
#define APROXY_SOCKS5_UDP_DEFAULT_STREAM_RX_LIMIT (1024u * 1024u)

typedef struct aproxy_socks5_udp_stats {
    uint64_t packets_received;
    uint64_t packets_relayed;
    uint64_t packets_sent;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    uint64_t dropped_partial;
    uint64_t dropped_fragments;
    uint64_t dropped_invalid;
    uint64_t dropped_foreign_client;
    uint64_t dropped_pending_limit;
    uint64_t rx_limit_closes;
    uint64_t send_errors;
    uint64_t send_in_flight;
    uint64_t send_in_flight_peak;
} aproxy_socks5_udp_stats_t;

typedef struct aproxy_socks5_inbound_config {
    uv_loop_t *loop;
    const char *tag;
    const char *listen_host;
    uint16_t listen_port;
    int backlog;
    uint8_t udp_uot_version;
    /* Zero selects APROXY_DEFAULT_STREAM_PENDING_BYTES. */
    size_t stream_pending_limit;
    size_t udp_pending_tx_limit;
    size_t udp_stream_rx_limit;
    aproxy_router_t *router;
    /* Borrowed; required for FQDN evaluation against GeoIP/CIDR rules. */
    aproxy_dns_resolver_t *resolver;
} aproxy_socks5_inbound_config_t;

int aproxy_socks5_inbound_new(const aproxy_socks5_inbound_config_t *config,
                              aproxy_inbound_t **out);

int aproxy_socks5_inbound_get_bound_port(const aproxy_inbound_t *inbound,
                                         uint16_t *out_port);

int aproxy_socks5_inbound_get_udp_stats(
    const aproxy_inbound_t *inbound,
    aproxy_socks5_udp_stats_t *out_stats);

#endif
