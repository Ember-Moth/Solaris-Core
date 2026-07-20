#ifndef APROXY_TUN_INBOUND_H
#define APROXY_TUN_INBOUND_H

#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include "aproxy/inbound.h"
#include "aproxy/packet_session.h"

#define APROXY_TUN_DEFAULT_NAME "tun0"
#define APROXY_TUN_DEFAULT_MTU 8500u
#define APROXY_TUN_DEFAULT_IPV4 "198.18.0.1"
#define APROXY_TUN_DEFAULT_IPV4_PREFIX 15u
#define APROXY_TUN_DEFAULT_IPV6 "fc00::1"
#define APROXY_TUN_DEFAULT_IPV6_PREFIX 64u

typedef struct aproxy_tun_stats {
    uint64_t packets_read;
    uint64_t bytes_read;
    uint64_t packets_to_sessions;
    uint64_t packets_dropped_session;
    uint64_t packets_dropped_no_handler;
    uint64_t packets_written;
    uint64_t bytes_written;
    uint64_t packets_write_queued;
    uint64_t packets_write_dropped;
    uint64_t read_errors;
    uint64_t write_errors;
} aproxy_tun_stats_t;

typedef void (*aproxy_tun_session_cb)(
    aproxy_inbound_t *inbound,
    aproxy_packet_session_t *session,
    aproxy_stream_t *stream,
    const aproxy_packet_flow_key_t *key,
    void *user_data);

typedef void (*aproxy_tun_stream_data_cb)(
    aproxy_inbound_t *inbound,
    aproxy_packet_session_t *session,
    aproxy_stream_t *stream,
    const uint8_t *packet,
    size_t packet_len,
    void *user_data);

typedef void (*aproxy_tun_packet_batch_cb)(
    aproxy_inbound_t *inbound,
    void *user_data);

/* packet is borrowed only for the duration of the callback. */
typedef int (*aproxy_tun_write_packet_cb)(
    aproxy_inbound_t *inbound,
    const uint8_t *packet,
    size_t packet_len,
    void *user_data);

typedef struct aproxy_tun_inbound_config {
    uv_loop_t *loop;
    const char *tag;
    const char *name;
    uint32_t mtu;
    const char *ipv4;
    uint8_t ipv4_prefix;
    const char *ipv6;
    uint8_t ipv6_prefix;
    int use_fd;
    int fd;
    int close_fd;
    int configure_device;
    aproxy_tun_session_cb on_session;
    aproxy_tun_stream_data_cb on_stream_data;
    /* Optional owner-thread boundaries for one borrowed packet batch. */
    aproxy_tun_packet_batch_cb on_packet_batch_begin;
    aproxy_tun_packet_batch_cb on_packet_batch_end;
    void *user_data;
    /* Callback packet I/O for platforms such as iOS without a public TUN fd. */
    int use_packet_io;
    aproxy_tun_write_packet_cb on_write_packet;
} aproxy_tun_inbound_config_t;

int aproxy_tun_inbound_new(const aproxy_tun_inbound_config_t *config,
                           aproxy_inbound_t **out);

/* Owner-thread API. The packet is consumed before this function returns. */
int aproxy_tun_inbound_submit_packet(aproxy_inbound_t *inbound,
                                     const uint8_t *packet,
                                     size_t packet_len);

int aproxy_tun_inbound_get_stats(const aproxy_inbound_t *inbound,
                                 aproxy_tun_stats_t *out_stats);

int aproxy_tun_inbound_get_session_stats(
    const aproxy_inbound_t *inbound,
    aproxy_packet_session_stats_t *out_stats);

const char *aproxy_tun_inbound_get_name(const aproxy_inbound_t *inbound);

#endif
