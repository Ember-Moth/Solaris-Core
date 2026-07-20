#include "aproxy/packet_tcp_relay.h"

#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include <lwip/ip.h>
#include <lwip/ip_addr.h>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/opt.h>
#include <lwip/pbuf.h>
#include <lwip/tcp.h>
#include <lwip/tcpip.h>
#include <lwip/timeouts.h>

#include "aproxy/ring.h"
#include "aproxy/bufpool.h"
#include "sniffer.h"

typedef struct packet_tcp_session packet_tcp_session_t;
typedef struct packet_tcp_listener packet_tcp_listener_t;
typedef struct packet_tcp_sniff_timer packet_tcp_sniff_timer_t;

struct packet_tcp_sniff_timer {
    uv_timer_t handle;
    packet_tcp_session_t *session;
};

struct packet_tcp_listener {
    aproxy_packet_tcp_relay_t *relay;
    uint8_t family;
    uint8_t dst_addr[16];
    uint16_t dst_port;
    struct tcp_pcb *pcb;
    size_t references;
    packet_tcp_listener_t *next;
    packet_tcp_listener_t *hash_next;
};

struct packet_tcp_session {
    aproxy_packet_tcp_relay_t *relay;
    aproxy_packet_session_t *packet_session;
    aproxy_stream_t *packet_stream;
    aproxy_stream_t *outbound_stream;
    aproxy_outbound_t *selected_outbound;
    aproxy_packet_flow_key_t key;
    aproxy_addr_t destination;
    aproxy_ring_t pending_to_outbound;
    aproxy_ring_t pending_to_client;
    struct tcp_pcb *pcb;
    packet_tcp_listener_t *listener;
    int outbound_open;
    int outbound_opening;
    int outbound_close_pending;
    int closed;
    int owns_packet_stream;
    int sniff_pending;
    packet_tcp_sniff_timer_t *sniff_timer;
    uint64_t last_activity_ms;
    packet_tcp_session_t *next;
    packet_tcp_session_t *hash_next;
    int indexed;
};

struct aproxy_packet_tcp_relay {
    uv_loop_t *loop;
    aproxy_router_t *router;
    struct netif netif;
    int netif_added;
    packet_tcp_listener_t *listeners;
    packet_tcp_session_t *sessions;
    packet_tcp_session_t **buckets;
    packet_tcp_listener_t **listener_buckets;
    size_t bucket_count;
    size_t indexed_count;
    size_t listener_bucket_count;
    size_t listener_count;
    size_t pending_to_outbound_limit;
    size_t pending_to_client_limit;
    uint64_t idle_timeout_ms;
    size_t sniffing_max_bytes;
    uint64_t sniffing_timeout_ms;
    int sniffing_enabled;
    aproxy_bufpool_t packet_pool;
    packet_tcp_session_t *current_session;
    aproxy_packet_tcp_relay_stats_t stats;
};

#define PACKET_TCP_INITIAL_BUCKETS 64u

static uint64_t relay_now_ms(void)
{
    return uv_hrtime() / UINT64_C(1000000);
}

static void session_touch(packet_tcp_session_t *session)
{
    session->last_activity_ms = relay_now_ms();
}

static void release_listener(packet_tcp_listener_t *listener);
static void close_session(packet_tcp_session_t *session);
static int start_outbound(packet_tcp_session_t *session);

static void sniff_timer_close_cb(uv_handle_t *handle)
{
    free(handle == NULL ? NULL : handle->data);
}

static void cancel_sniff_timer(packet_tcp_session_t *session)
{
    if (session == NULL || session->sniff_timer == NULL) {
        return;
    }
    packet_tcp_sniff_timer_t *timer = session->sniff_timer;
    session->sniff_timer = NULL;
    timer->session = NULL;
    (void)uv_timer_stop(&timer->handle);
    if (!uv_is_closing((uv_handle_t *)&timer->handle)) {
        uv_close((uv_handle_t *)&timer->handle, sniff_timer_close_cb);
    }
}

static aproxy_outbound_t *sniff_route(packet_tcp_session_t *session,
                                      const aproxy_sniff_result_t *result)
{
    aproxy_addr_t domain;
    if (session == NULL || result == NULL || result->domain_len == 0u ||
        aproxy_addr_set_fqdn(&domain, result->domain,
                             session->destination.port) != APROXY_OK) {
        return NULL;
    }
    return aproxy_router_pick_resolved(session->relay->router, &domain,
                                       &session->destination, 1u);
}

static int finish_sniff(packet_tcp_session_t *session,
                        aproxy_sniff_status_t status,
                        const aproxy_sniff_result_t *result,
                        int timed_out)
{
    if (session == NULL || !session->sniff_pending) {
        return APROXY_OK;
    }
    session->sniff_pending = 0;
    cancel_sniff_timer(session);
    if (status == APROXY_SNIFF_MATCH) {
        session->selected_outbound = sniff_route(session, result);
        if (session->selected_outbound != NULL) {
            session->relay->stats.sniff_matches++;
            if (result->protocol == APROXY_SNIFF_PROTOCOL_HTTP) {
                session->relay->stats.sniff_http_matches++;
            } else if (result->protocol == APROXY_SNIFF_PROTOCOL_TLS) {
                session->relay->stats.sniff_tls_matches++;
            }
        }
    }
    if (session->selected_outbound == NULL) {
        session->relay->stats.sniff_fallbacks++;
    }
    if (timed_out) {
        session->relay->stats.sniff_timeouts++;
    }
    return start_outbound(session);
}

static void sniff_timer_cb(uv_timer_t *handle)
{
    packet_tcp_sniff_timer_t *timer =
        handle == NULL ? NULL : (packet_tcp_sniff_timer_t *)handle->data;
    packet_tcp_session_t *session = timer == NULL ? NULL : timer->session;
    if (session == NULL) {
        return;
    }
    timer->session = NULL;
    session->sniff_timer = NULL;
    (void)uv_timer_stop(handle);
    uv_close((uv_handle_t *)handle, sniff_timer_close_cb);
    if (session->closed || !session->sniff_pending) {
        return;
    }
    if (finish_sniff(session, APROXY_SNIFF_NO_MATCH, NULL, 1) !=
        APROXY_OK) {
        LOCK_TCPIP_CORE();
        close_session(session);
        UNLOCK_TCPIP_CORE();
    }
}

static int arm_sniff_timer(packet_tcp_session_t *session)
{
    if (session == NULL || session->relay->loop == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    packet_tcp_sniff_timer_t *timer =
        (packet_tcp_sniff_timer_t *)calloc(1u, sizeof(*timer));
    if (timer == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    int rc = uv_timer_init(session->relay->loop, &timer->handle);
    if (rc != 0) {
        free(timer);
        return APROXY_ERR_UNSUPPORTED;
    }
    timer->handle.data = timer;
    timer->session = session;
    session->sniff_timer = timer;
    rc = uv_timer_start(&timer->handle, sniff_timer_cb,
                        session->relay->sniffing_timeout_ms, 0u);
    if (rc != 0) {
        cancel_sniff_timer(session);
        return APROXY_ERR_UNSUPPORTED;
    }
    return APROXY_OK;
}

static int lwip_started;

#if !NO_SYS
static volatile int lwip_ready;

static void lwip_init_done(void *arg)
{
    (void)arg;
    lwip_ready = 1;
}
#endif

static int ensure_lwip_started(void)
{
    if (lwip_started) {
        return APROXY_OK;
    }
#if NO_SYS
    lwip_init();
#else
    lwip_ready = 0;
    tcpip_init(lwip_init_done, NULL);
    while (!lwip_ready) {
        uv_sleep(1u);
    }
#endif
    lwip_started = 1;
    return APROXY_OK;
}

static uint16_t get_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8u) | (uint16_t)in[1]);
}

static int key_destination(const aproxy_packet_flow_key_t *key,
                           aproxy_addr_t *out)
{
    if (key == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (key->family == APROXY_PACKET_FAMILY_IPV4) {
        aproxy_addr_set_ipv4(out, key->dst_addr, key->dst_port);
        return APROXY_OK;
    }
    if (key->family == APROXY_PACKET_FAMILY_IPV6) {
        aproxy_addr_set_ipv6(out, key->dst_addr, key->dst_port);
        return APROXY_OK;
    }
    return APROXY_ERR_UNSUPPORTED;
}

static uint32_t ip6_part_from_bytes(const uint8_t *addr, size_t offset)
{
    uint32_t part = 0u;
    memcpy(&part, addr + offset, sizeof(part));
    return part;
}

static void ip_addr_from_key_destination(const aproxy_packet_flow_key_t *key,
                                         ip_addr_t *out)
{
    if (key->family == APROXY_PACKET_FAMILY_IPV4) {
        IP_ADDR4(out, key->dst_addr[0], key->dst_addr[1],
                 key->dst_addr[2], key->dst_addr[3]);
        return;
    }
    IP_ADDR6(out, ip6_part_from_bytes(key->dst_addr, 0u),
             ip6_part_from_bytes(key->dst_addr, 4u),
             ip6_part_from_bytes(key->dst_addr, 8u),
             ip6_part_from_bytes(key->dst_addr, 12u));
}

static void ip6_addr_from_bytes(const uint8_t addr[16], ip6_addr_t *out)
{
    IP6_ADDR(out, ip6_part_from_bytes(addr, 0u),
             ip6_part_from_bytes(addr, 4u),
             ip6_part_from_bytes(addr, 8u),
             ip6_part_from_bytes(addr, 12u));
}

static packet_tcp_session_t *find_session_by_packet_session(
    aproxy_packet_tcp_relay_t *relay,
    aproxy_packet_session_t *packet_session)
{
    if (relay == NULL || packet_session == NULL) {
        return NULL;
    }
    const aproxy_packet_flow_key_t *key =
        aproxy_packet_session_key(packet_session);
    if (key == NULL) {
        return NULL;
    }
    const size_t bucket = (size_t)aproxy_packet_flow_key_hash(key) &
                          (relay->bucket_count - 1u);
    for (packet_tcp_session_t *cur = relay->buckets[bucket]; cur != NULL;
         cur = cur->hash_next) {
        if (!cur->closed && cur->packet_session == packet_session) {
            return cur;
        }
    }
    return NULL;
}

static packet_tcp_session_t *find_session_by_response_packet(
    aproxy_packet_tcp_relay_t *relay,
    const uint8_t *packet,
    size_t packet_len)
{
    if (relay == NULL || packet == NULL || packet_len < 1u) {
        return NULL;
    }
    uint8_t family = 0u;
    const uint8_t *src_addr = NULL;
    const uint8_t *dst_addr = NULL;
    size_t addr_len = 0u;
    size_t tcp_offset = 0u;
    const uint8_t version = (uint8_t)(packet[0] >> 4u);
    if (version == 4u) {
        if (packet_len < 40u || packet[9] != APROXY_PACKET_PROTO_TCP) {
            return NULL;
        }
        tcp_offset = (size_t)(packet[0] & 0x0fu) * 4u;
        if (tcp_offset < 20u || packet_len < tcp_offset + 20u) {
            return NULL;
        }
        family = APROXY_PACKET_FAMILY_IPV4;
        src_addr = packet + 12u;
        dst_addr = packet + 16u;
        addr_len = 4u;
    } else if (version == 6u) {
        if (packet_len < 60u || packet[6] != APROXY_PACKET_PROTO_TCP) {
            return NULL;
        }
        const size_t payload_len =
            ((size_t)packet[4] << 8u) | (size_t)packet[5];
        if (packet_len < 40u + payload_len || payload_len < 20u) {
            return NULL;
        }
        family = APROXY_PACKET_FAMILY_IPV6;
        src_addr = packet + 8u;
        dst_addr = packet + 24u;
        addr_len = 16u;
        tcp_offset = 40u;
    } else {
        return NULL;
    }
    aproxy_packet_flow_key_t key;
    memset(&key, 0, sizeof(key));
    key.family = family;
    key.proto = APROXY_PACKET_PROTO_TCP;
    key.src_port = get_u16(packet + tcp_offset + 2u);
    key.dst_port = get_u16(packet + tcp_offset);
    memcpy(key.src_addr, dst_addr, addr_len);
    memcpy(key.dst_addr, src_addr, addr_len);
    const size_t bucket = (size_t)aproxy_packet_flow_key_hash(&key) &
                          (relay->bucket_count - 1u);
    for (packet_tcp_session_t *cur = relay->buckets[bucket]; cur != NULL;
         cur = cur->hash_next) {
        if (!cur->closed && memcmp(&cur->key, &key, sizeof(key)) == 0) {
            return cur;
        }
    }
    return NULL;
}

static int resize_session_buckets(aproxy_packet_tcp_relay_t *relay,
                                  size_t next_count)
{
    packet_tcp_session_t **next =
        (packet_tcp_session_t **)calloc(next_count, sizeof(*next));
    if (next == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    free(relay->buckets);
    relay->buckets = next;
    relay->bucket_count = next_count;
    relay->indexed_count = 0u;
    for (packet_tcp_session_t *session = relay->sessions; session != NULL;
         session = session->next) {
        session->hash_next = NULL;
        session->indexed = 0;
        if (session->closed) {
            continue;
        }
        const size_t bucket =
            (size_t)aproxy_packet_flow_key_hash(&session->key) &
            (relay->bucket_count - 1u);
        session->hash_next = relay->buckets[bucket];
        relay->buckets[bucket] = session;
        session->indexed = 1;
        relay->indexed_count++;
    }
    return APROXY_OK;
}

static int index_session(packet_tcp_session_t *session)
{
    aproxy_packet_tcp_relay_t *relay = session->relay;
    if ((relay->indexed_count + 1u) * 4u >= relay->bucket_count * 3u) {
        if (relay->bucket_count > SIZE_MAX / 2u) {
            return APROXY_ERR_NO_MEMORY;
        }
        const int rc = resize_session_buckets(relay,
                                              relay->bucket_count * 2u);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    const size_t bucket =
        (size_t)aproxy_packet_flow_key_hash(&session->key) &
        (relay->bucket_count - 1u);
    session->hash_next = relay->buckets[bucket];
    relay->buckets[bucket] = session;
    session->indexed = 1;
    relay->indexed_count++;
    return APROXY_OK;
}

static void unindex_session(packet_tcp_session_t *session)
{
    if (session == NULL || !session->indexed) {
        return;
    }
    aproxy_packet_tcp_relay_t *relay = session->relay;
    const size_t bucket =
        (size_t)aproxy_packet_flow_key_hash(&session->key) &
        (relay->bucket_count - 1u);
    packet_tcp_session_t **cursor = &relay->buckets[bucket];
    while (*cursor != NULL && *cursor != session) {
        cursor = &(*cursor)->hash_next;
    }
    if (*cursor == session) {
        *cursor = session->hash_next;
    }
    session->hash_next = NULL;
    session->indexed = 0;
    if (relay->indexed_count > 0u) {
        relay->indexed_count--;
    }
}

static err_t tcp_netif_output(struct netif *netif,
                              struct pbuf *p,
                              const ip4_addr_t *ipaddr)
{
    (void)ipaddr;
    aproxy_packet_tcp_relay_t *relay =
        (aproxy_packet_tcp_relay_t *)netif->state;
    if (relay == NULL || p == NULL || p->tot_len == 0u) {
        return ERR_ARG;
    }

    size_t capacity = 0u;
    uint8_t *packet = aproxy_bufpool_acquire(&relay->packet_pool, p->tot_len,
                                             &capacity);
    if (packet == NULL) {
        relay->stats.write_errors++;
        return ERR_MEM;
    }
    if (pbuf_copy_partial(p, packet, p->tot_len, 0u) != p->tot_len) {
        aproxy_bufpool_release(&relay->packet_pool, packet, capacity);
        relay->stats.write_errors++;
        return ERR_BUF;
    }

    packet_tcp_session_t *session =
        find_session_by_response_packet(relay, packet, p->tot_len);
    if (session == NULL) {
        session = relay->current_session;
    }
    if (session == NULL || session->packet_stream == NULL) {
        aproxy_bufpool_release(&relay->packet_pool, packet, capacity);
        relay->stats.write_errors++;
        return ERR_RTE;
    }

    const int rc = aproxy_stream_write(session->packet_stream, packet,
                                       p->tot_len);
    aproxy_bufpool_release(&relay->packet_pool, packet, capacity);
    if (rc != APROXY_OK) {
        relay->stats.write_errors++;
        return ERR_IF;
    }
    relay->stats.packets_written++;
    relay->stats.packet_bytes_written += p->tot_len;
    return ERR_OK;
}

static err_t tcp_netif_output_ip6(struct netif *netif,
                                  struct pbuf *p,
                                  const ip6_addr_t *ipaddr)
{
    (void)ipaddr;
    return tcp_netif_output(netif, p, NULL);
}

static err_t tcp_netif_init(struct netif *netif)
{
    netif->name[0] = 't';
    netif->name[1] = 'p';
    netif->output = tcp_netif_output;
    netif->output_ip6 = tcp_netif_output_ip6;
    netif->mtu = 8500u;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}

static int set_netif_destination(aproxy_packet_tcp_relay_t *relay,
                                 const aproxy_packet_flow_key_t *key)
{
    if (relay == NULL || key == NULL || !relay->netif_added) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (key->family == APROXY_PACKET_FAMILY_IPV4) {
        ip4_addr_t ip;
        ip4_addr_t netmask;
        ip4_addr_t gateway;
        IP4_ADDR(&ip, key->dst_addr[0], key->dst_addr[1],
                 key->dst_addr[2], key->dst_addr[3]);
        IP4_ADDR(&netmask, 255, 255, 255, 255);
        IP4_ADDR(&gateway, 0, 0, 0, 0);
        netif_set_addr(&relay->netif, &ip, &netmask, &gateway);
        return APROXY_OK;
    }
    if (key->family == APROXY_PACKET_FAMILY_IPV6) {
        ip6_addr_t ip6;
        ip6_addr_from_bytes(key->dst_addr, &ip6);
        netif_ip6_addr_set(&relay->netif, 0, &ip6);
        netif_ip6_addr_set_state(&relay->netif, 0, IP6_ADDR_PREFERRED);
        return APROXY_OK;
    }
    return APROXY_ERR_UNSUPPORTED;
}

static int parse_tcp_payload(const uint8_t *packet,
                             size_t packet_len,
                             const uint8_t **payload,
                             size_t *payload_len)
{
    if (packet == NULL || payload == NULL || payload_len == NULL ||
        packet_len < 1u) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const uint8_t version = (uint8_t)(packet[0] >> 4u);
    size_t ip_header_len = 0u;
    size_t total_len = 0u;
    if (version == 4u) {
        if (packet_len < 40u || packet[9] != APROXY_PACKET_PROTO_TCP) {
            return APROXY_ERR_INVALID_FRAME;
        }
        ip_header_len = (size_t)(packet[0] & 0x0fu) * 4u;
        if (ip_header_len < 20u || packet_len < ip_header_len + 20u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        total_len = get_u16(packet + 2u);
    } else if (version == 6u) {
        if (packet_len < 60u || packet[6] != APROXY_PACKET_PROTO_TCP) {
            return APROXY_ERR_INVALID_FRAME;
        }
        const size_t ipv6_payload_len =
            ((size_t)packet[4] << 8u) | (size_t)packet[5];
        ip_header_len = 40u;
        total_len = ip_header_len + ipv6_payload_len;
    } else {
        return APROXY_ERR_INVALID_FRAME;
    }
    const size_t tcp_header_len =
        (size_t)(packet[ip_header_len + 12u] >> 4u) * 4u;
    if (tcp_header_len < 20u ||
        total_len < ip_header_len + tcp_header_len ||
        packet_len < total_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    *payload = packet + ip_header_len + tcp_header_len;
    *payload_len = total_len - ip_header_len - tcp_header_len;
    return APROXY_OK;
}

static int relay_ip_input(packet_tcp_session_t *session,
                          const uint8_t *packet,
                          size_t packet_len)
{
    if (session == NULL || packet == NULL || packet_len == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)packet_len, PBUF_RAM);
    if (p == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    if (pbuf_take(p, packet, (u16_t)packet_len) != ERR_OK) {
        pbuf_free(p);
        return APROXY_ERR_NO_MEMORY;
    }

    aproxy_packet_tcp_relay_t *relay = session->relay;
    packet_tcp_session_t *prev = relay->current_session;
    relay->current_session = session;
    err_t err = ip_input(p, &relay->netif);
    relay->current_session = prev;
    if (err != ERR_OK) {
        return APROXY_ERR_INVALID_FRAME;
    }
    return APROXY_OK;
}

static int flush_to_outbound(packet_tcp_session_t *session)
{
    if (session == NULL || session->outbound_stream == NULL ||
        !session->outbound_open) {
        return APROXY_OK;
    }
    while (aproxy_ring_size(&session->pending_to_outbound) > 0u) {
        aproxy_const_span_t spans[2];
        const size_t count = aproxy_ring_read_spans(
            &session->pending_to_outbound, spans);
        if (count == 0u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        size_t consumed = 0u;
        for (size_t i = 0u; i < count; i++) {
            const int rc = aproxy_stream_write(session->outbound_stream,
                                               spans[i].data,
                                               spans[i].len);
            if (rc != APROXY_OK) {
                session->relay->stats.write_errors++;
                return rc;
            }
            session->relay->stats.outbound_bytes_out += spans[i].len;
            consumed += spans[i].len;
        }
        aproxy_ring_consume(&session->pending_to_outbound, consumed);
    }
    return APROXY_OK;
}

static int flush_to_client(packet_tcp_session_t *session)
{
    if (session == NULL || session->pcb == NULL) {
        return APROXY_OK;
    }
    while (aproxy_ring_size(&session->pending_to_client) > 0u) {
        aproxy_const_span_t spans[2];
        const size_t count = aproxy_ring_read_spans(
            &session->pending_to_client, spans);
        if (count == 0u) {
            return APROXY_ERR_INVALID_FRAME;
        }
        size_t consumed = 0u;
        for (size_t i = 0u; i < count; i++) {
            size_t offset = 0u;
            while (offset < spans[i].len) {
                const u16_t sndbuf = tcp_sndbuf(session->pcb);
                if (sndbuf == 0u) {
                    if (tcp_output(session->pcb) != ERR_OK) {
                        return APROXY_ERR_UNSUPPORTED;
                    }
                    if (tcp_sndbuf(session->pcb) == 0u) {
                        aproxy_ring_consume(&session->pending_to_client,
                                            consumed);
                        return APROXY_OK;
                    }
                }
                size_t chunk = spans[i].len - offset;
                if (chunk > (size_t)tcp_sndbuf(session->pcb)) {
                    chunk = (size_t)tcp_sndbuf(session->pcb);
                }
                if (chunk > UINT16_MAX) {
                    chunk = UINT16_MAX;
                }
                const err_t err = tcp_write(session->pcb,
                                            spans[i].data + offset,
                                            (u16_t)chunk,
                                            TCP_WRITE_FLAG_COPY);
                if (err == ERR_MEM) {
                    aproxy_ring_consume(&session->pending_to_client,
                                        consumed);
                    return APROXY_OK;
                }
                if (err != ERR_OK) {
                    return APROXY_ERR_UNSUPPORTED;
                }
                offset += chunk;
                consumed += chunk;
            }
        }
        aproxy_ring_consume(&session->pending_to_client, consumed);
    }
    if (tcp_output(session->pcb) != ERR_OK) {
        return APROXY_ERR_UNSUPPORTED;
    }
    return APROXY_OK;
}

static void outbound_data_cb(aproxy_stream_t *stream,
                             const uint8_t *data,
                             size_t len,
                             void *user_data)
{
    (void)stream;
    packet_tcp_session_t *session = (packet_tcp_session_t *)user_data;
    if (session == NULL || session->closed ||
        (data == NULL && len > 0u)) {
        return;
    }
    aproxy_packet_tcp_relay_t *relay = session->relay;
    LOCK_TCPIP_CORE();
    session_touch(session);
    const size_t pending = aproxy_ring_size(&session->pending_to_client);
    if (len > relay->pending_to_client_limit ||
        pending > relay->pending_to_client_limit - len) {
        relay->stats.queue_overflow_closes++;
        close_session(session);
        UNLOCK_TCPIP_CORE();
        return;
    }
    int rc = aproxy_ring_write(&session->pending_to_client, data, len);
    if (rc == APROXY_OK) {
        relay->stats.outbound_bytes_in += len;
        rc = flush_to_client(session);
    }
    if (rc != APROXY_OK) {
        relay->stats.write_errors++;
    }
    UNLOCK_TCPIP_CORE();
}

static void close_session(packet_tcp_session_t *session)
{
    if (session == NULL || session->closed) {
        return;
    }
    unindex_session(session);
    session->closed = 1;
    session->sniff_pending = 0;
    cancel_sniff_timer(session);
    if (session->outbound_stream != NULL) {
        aproxy_stream_t *stream = session->outbound_stream;
        session->outbound_close_pending = 1;
        const int rc = aproxy_stream_close(stream);
        if (rc != APROXY_OK && session->outbound_stream == stream) {
            session->outbound_stream = NULL;
            session->outbound_close_pending = 0;
            aproxy_stream_free(stream);
        }
    }
    if (session->pcb != NULL) {
        struct tcp_pcb *pcb = session->pcb;
        session->pcb = NULL;
        tcp_arg(pcb, NULL);
        tcp_recv(pcb, NULL);
        tcp_sent(pcb, NULL);
        tcp_poll(pcb, NULL, 0u);
        tcp_err(pcb, NULL);
        if (tcp_close(pcb) != ERR_OK) {
            tcp_abort(pcb);
        }
    }
    if (session->listener != NULL) {
        packet_tcp_listener_t *listener = session->listener;
        session->listener = NULL;
        release_listener(listener);
    }
    if (session->owns_packet_stream && session->packet_stream != NULL) {
        aproxy_stream_t *stream = session->packet_stream;
        session->packet_stream = NULL;
        session->packet_session = NULL;
        session->owns_packet_stream = 0;
        (void)aproxy_stream_close(stream);
        aproxy_stream_free(stream);
    }
}

static void outbound_open_cb(aproxy_stream_t *stream,
                             int status,
                             void *user_data)
{
    packet_tcp_session_t *session = (packet_tcp_session_t *)user_data;
    if (session == NULL) {
        return;
    }
    session->outbound_opening = 0;
    if (session->closed) {
        return;
    }
    if (status != APROXY_OK) {
        session->relay->stats.open_errors++;
        LOCK_TCPIP_CORE();
        close_session(session);
        UNLOCK_TCPIP_CORE();
        return;
    }
    if (session->outbound_stream == NULL) {
        session->outbound_stream = stream;
    }
    session->outbound_open = 1;
    if (flush_to_outbound(session) != APROXY_OK) {
        session->relay->stats.write_errors++;
    }
}

static void outbound_close_cb(aproxy_stream_t *stream,
                              int status,
                              void *user_data)
{
    (void)status;
    packet_tcp_session_t *session = (packet_tcp_session_t *)user_data;
    if (session == NULL) {
        return;
    }
    const int release_stream = session->outbound_stream == stream;
    if (release_stream) {
        session->outbound_stream = NULL;
    }
    session->outbound_opening = 0;
    session->outbound_close_pending = 0;
    if (!session->closed) {
        LOCK_TCPIP_CORE();
        close_session(session);
        UNLOCK_TCPIP_CORE();
    }
    if (release_stream) {
        aproxy_stream_free(stream);
    }
}

static int start_outbound(packet_tcp_session_t *session)
{
    if (session == NULL || session->outbound_opening ||
        session->outbound_stream != NULL || session->closed) {
        return APROXY_OK;
    }
    aproxy_outbound_t *outbound = session->selected_outbound;
    if (outbound == NULL) {
        outbound = aproxy_router_pick(session->relay->router,
                                      &session->destination);
    }
    if (outbound == NULL) {
        session->relay->stats.open_errors++;
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    session->outbound_opening = 1;
    const int rc = aproxy_outbound_open_stream(
        outbound, &session->destination, outbound_data_cb, outbound_open_cb,
        outbound_close_cb, session, &session->outbound_stream);
    if (rc != APROXY_OK) {
        session->outbound_opening = 0;
        session->relay->stats.open_errors++;
    }
    return rc;
}

static err_t tcp_recv_cb(void *arg,
                         struct tcp_pcb *pcb,
                         struct pbuf *p,
                         err_t err)
{
    packet_tcp_session_t *session = (packet_tcp_session_t *)arg;
    if (session == NULL || pcb == NULL || session->closed) {
        if (p != NULL) {
            pbuf_free(p);
        }
        return ERR_OK;
    }
    if (err != ERR_OK) {
        if (p != NULL) {
            pbuf_free(p);
        }
        close_session(session);
        return ERR_OK;
    }
    session_touch(session);
    if (p == NULL) {
        close_session(session);
        return ERR_OK;
    }
    const size_t pending = aproxy_ring_size(&session->pending_to_outbound);
    if ((size_t)p->tot_len > session->relay->pending_to_outbound_limit ||
        pending > session->relay->pending_to_outbound_limit -
                      (size_t)p->tot_len) {
        session->relay->stats.queue_overflow_closes++;
        pbuf_free(p);
        close_session(session);
        return ERR_OK;
    }
    if (aproxy_ring_reserve(&session->pending_to_outbound,
                            pending + (size_t)p->tot_len) != APROXY_OK) {
        session->relay->stats.write_errors++;
        pbuf_free(p);
        close_session(session);
        return ERR_OK;
    }
    for (struct pbuf *q = p; q != NULL; q = q->next) {
        if (q->len > 0u) {
            const int rc = aproxy_ring_write(&session->pending_to_outbound,
                                             (const uint8_t *)q->payload,
                                             q->len);
            if (rc != APROXY_OK) {
                pbuf_free(p);
                session->relay->stats.write_errors++;
                close_session(session);
                return ERR_OK;
            }
        }
    }
    tcp_recved(pcb, p->tot_len);
    pbuf_free(p);
    if (session->sniff_pending) {
        const size_t available =
            aproxy_ring_size(&session->pending_to_outbound);
        const size_t sniff_len =
            available < session->relay->sniffing_max_bytes
                ? available
                : session->relay->sniffing_max_bytes;
        aproxy_const_span_t spans[2];
        const size_t span_count = aproxy_ring_read_spans_at(
            &session->pending_to_outbound, 0u, sniff_len, spans);
        aproxy_sniff_result_t result;
        aproxy_sniff_status_t status = aproxy_sniff_tcp(
            spans, span_count, session->relay->sniffing_max_bytes,
            &result);
        if (status == APROXY_SNIFF_NEED_MORE &&
            available < session->relay->sniffing_max_bytes) {
            return ERR_OK;
        }
        if (status == APROXY_SNIFF_NEED_MORE) {
            status = APROXY_SNIFF_NO_MATCH;
        }
        if (finish_sniff(session, status, &result, 0) != APROXY_OK) {
            session->relay->stats.write_errors++;
            close_session(session);
            return ERR_OK;
        }
    }
    if (flush_to_outbound(session) != APROXY_OK) {
        session->relay->stats.write_errors++;
    }
    return ERR_OK;
}

static err_t tcp_sent_cb(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    (void)pcb;
    (void)len;
    packet_tcp_session_t *session = (packet_tcp_session_t *)arg;
    if (flush_to_client(session) != APROXY_OK && session != NULL) {
        session->relay->stats.write_errors++;
    }
    return ERR_OK;
}

static err_t tcp_poll_cb(void *arg, struct tcp_pcb *pcb)
{
    (void)pcb;
    packet_tcp_session_t *session = (packet_tcp_session_t *)arg;
    if (flush_to_client(session) != APROXY_OK && session != NULL) {
        session->relay->stats.write_errors++;
    }
    return ERR_OK;
}

static void tcp_err_cb(void *arg, err_t err)
{
    (void)err;
    packet_tcp_session_t *session = (packet_tcp_session_t *)arg;
    if (session == NULL) {
        return;
    }
    session->pcb = NULL;
    close_session(session);
}

static err_t tcp_accept_cb(void *arg, struct tcp_pcb *pcb, err_t err)
{
    packet_tcp_listener_t *listener = (packet_tcp_listener_t *)arg;
    if (listener == NULL || listener->relay == NULL || pcb == NULL ||
        err != ERR_OK) {
        if (pcb != NULL) {
            tcp_abort(pcb);
        }
        return ERR_ABRT;
    }
    packet_tcp_session_t *session = listener->relay->current_session;
    if (session == NULL || session->closed || session->pcb != NULL) {
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    session->pcb = pcb;
    tcp_arg(pcb, session);
    tcp_recv(pcb, tcp_recv_cb);
    tcp_sent(pcb, tcp_sent_cb);
    tcp_poll(pcb, tcp_poll_cb, 4u);
    tcp_err(pcb, tcp_err_cb);
    tcp_nagle_disable(pcb);
    listener->relay->stats.accepts++;
    if (listener->relay->sniffing_enabled) {
        session->sniff_pending = 1;
        listener->relay->stats.sniff_attempts++;
        if (arm_sniff_timer(session) == APROXY_OK) {
            return ERR_OK;
        }
        session->sniff_pending = 0;
        listener->relay->stats.sniff_fallbacks++;
    }
    if (start_outbound(session) != APROXY_OK) {
        tcp_abort(pcb);
        session->pcb = NULL;
        return ERR_ABRT;
    }
    return ERR_OK;
}

static uint64_t listener_hash(uint8_t family,
                              const uint8_t *address,
                              uint16_t port)
{
    const size_t address_len =
        family == APROXY_PACKET_FAMILY_IPV4 ? 4u : 16u;
    uint64_t hash = UINT64_C(1469598103934665603);
    hash = (hash ^ family) * UINT64_C(1099511628211);
    for (size_t i = 0u; i < address_len; i++) {
        hash = (hash ^ address[i]) * UINT64_C(1099511628211);
    }
    hash = (hash ^ (uint8_t)(port >> 8u)) * UINT64_C(1099511628211);
    hash = (hash ^ (uint8_t)port) * UINT64_C(1099511628211);
    return hash ^ (hash >> 32u);
}

static size_t listener_bucket(const aproxy_packet_tcp_relay_t *relay,
                              uint8_t family,
                              const uint8_t *address,
                              uint16_t port)
{
    return (size_t)listener_hash(family, address, port) &
           (relay->listener_bucket_count - 1u);
}

static packet_tcp_listener_t *find_listener(
    aproxy_packet_tcp_relay_t *relay,
    const aproxy_packet_flow_key_t *key)
{
    if (relay == NULL || key == NULL ||
        (key->family != APROXY_PACKET_FAMILY_IPV4 &&
         key->family != APROXY_PACKET_FAMILY_IPV6)) {
        return NULL;
    }
    const size_t addr_len =
        key->family == APROXY_PACKET_FAMILY_IPV4 ? 4u : 16u;
    const size_t bucket = listener_bucket(
        relay, key->family, key->dst_addr, key->dst_port);
    for (packet_tcp_listener_t *cur = relay->listener_buckets[bucket];
         cur != NULL; cur = cur->hash_next) {
        if (cur->family == key->family &&
            cur->dst_port == key->dst_port &&
            memcmp(cur->dst_addr, key->dst_addr, addr_len) == 0) {
            return cur;
        }
    }
    return NULL;
}

static int resize_listener_buckets(aproxy_packet_tcp_relay_t *relay,
                                   size_t next_count)
{
    packet_tcp_listener_t **next =
        (packet_tcp_listener_t **)calloc(next_count, sizeof(*next));
    if (next == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    free(relay->listener_buckets);
    relay->listener_buckets = next;
    relay->listener_bucket_count = next_count;
    for (packet_tcp_listener_t *listener = relay->listeners;
         listener != NULL; listener = listener->next) {
        const size_t bucket = listener_bucket(
            relay, listener->family, listener->dst_addr, listener->dst_port);
        listener->hash_next = relay->listener_buckets[bucket];
        relay->listener_buckets[bucket] = listener;
    }
    return APROXY_OK;
}

static int ensure_listener(aproxy_packet_tcp_relay_t *relay,
                           const aproxy_packet_flow_key_t *key,
                           packet_tcp_listener_t **out)
{
    packet_tcp_listener_t *listener = find_listener(relay, key);
    if (listener != NULL) {
        listener->references++;
        *out = listener;
        return APROXY_OK;
    }
    if ((relay->listener_count + 1u) * 4u >=
        relay->listener_bucket_count * 3u) {
        if (relay->listener_bucket_count > SIZE_MAX / 2u) {
            return APROXY_ERR_NO_MEMORY;
        }
        const int rc = resize_listener_buckets(
            relay, relay->listener_bucket_count * 2u);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    listener = (packet_tcp_listener_t *)calloc(1u, sizeof(*listener));
    if (listener == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    listener->relay = relay;
    listener->family = key->family;
    listener->dst_port = key->dst_port;
    memcpy(listener->dst_addr, key->dst_addr,
           key->family == APROXY_PACKET_FAMILY_IPV4 ? 4u : 16u);

    struct tcp_pcb *pcb = tcp_new_ip_type(
        key->family == APROXY_PACKET_FAMILY_IPV4 ? IPADDR_TYPE_V4
                                                 : IPADDR_TYPE_V6);
    if (pcb == NULL) {
        free(listener);
        return APROXY_ERR_NO_MEMORY;
    }
    ip_addr_t bind_addr;
    ip_addr_from_key_destination(key, &bind_addr);
    err_t err = tcp_bind(pcb, &bind_addr, key->dst_port);
    if (err != ERR_OK) {
        tcp_abort(pcb);
        free(listener);
        return APROXY_ERR_UNSUPPORTED;
    }
    listener->pcb = tcp_listen(pcb);
    if (listener->pcb == NULL) {
        tcp_abort(pcb);
        free(listener);
        return APROXY_ERR_NO_MEMORY;
    }
    tcp_arg(listener->pcb, listener);
    tcp_accept(listener->pcb, tcp_accept_cb);
    listener->references = 1u;
    listener->next = relay->listeners;
    relay->listeners = listener;
    const size_t bucket = listener_bucket(
        relay, listener->family, listener->dst_addr, listener->dst_port);
    listener->hash_next = relay->listener_buckets[bucket];
    relay->listener_buckets[bucket] = listener;
    relay->listener_count++;
    relay->stats.listeners_opened++;
    relay->stats.listeners_active++;
    *out = listener;
    return APROXY_OK;
}

static void release_listener(packet_tcp_listener_t *listener)
{
    if (listener == NULL || listener->references == 0u) {
        return;
    }
    listener->references--;
    if (listener->references > 0u) {
        return;
    }

    aproxy_packet_tcp_relay_t *relay = listener->relay;
    const size_t bucket = listener_bucket(
        relay, listener->family, listener->dst_addr, listener->dst_port);
    packet_tcp_listener_t **hash_cursor = &relay->listener_buckets[bucket];
    while (*hash_cursor != NULL && *hash_cursor != listener) {
        hash_cursor = &(*hash_cursor)->hash_next;
    }
    if (*hash_cursor == listener) {
        *hash_cursor = listener->hash_next;
    }
    packet_tcp_listener_t **list_cursor = &relay->listeners;
    while (*list_cursor != NULL && *list_cursor != listener) {
        list_cursor = &(*list_cursor)->next;
    }
    if (*list_cursor == listener) {
        *list_cursor = listener->next;
    }
    if (listener->pcb != NULL) {
        tcp_arg(listener->pcb, NULL);
        tcp_accept(listener->pcb, NULL);
        if (tcp_close(listener->pcb) != ERR_OK) {
            tcp_abort(listener->pcb);
        }
    }
    if (relay->listener_count > 0u) {
        relay->listener_count--;
    }
    if (relay->stats.listeners_active > 0u) {
        relay->stats.listeners_active--;
    }
    relay->stats.listeners_closed++;
    free(listener);
}

int aproxy_packet_tcp_relay_new(
    const aproxy_packet_tcp_relay_config_t *config,
    aproxy_packet_tcp_relay_t **out)
{
    if (config == NULL || out == NULL || config->router == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int rc = ensure_lwip_started();
    if (rc != APROXY_OK) {
        return rc;
    }

    aproxy_packet_tcp_relay_t *relay =
        (aproxy_packet_tcp_relay_t *)calloc(1u, sizeof(*relay));
    if (relay == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    relay->buckets = (packet_tcp_session_t **)calloc(
        PACKET_TCP_INITIAL_BUCKETS, sizeof(*relay->buckets));
    relay->listener_buckets = (packet_tcp_listener_t **)calloc(
        PACKET_TCP_INITIAL_BUCKETS, sizeof(*relay->listener_buckets));
    if (relay->buckets == NULL || relay->listener_buckets == NULL) {
        free(relay->listener_buckets);
        free(relay->buckets);
        free(relay);
        return APROXY_ERR_NO_MEMORY;
    }
    relay->bucket_count = PACKET_TCP_INITIAL_BUCKETS;
    relay->listener_bucket_count = PACKET_TCP_INITIAL_BUCKETS;
    relay->pending_to_outbound_limit =
        config->pending_to_outbound_limit == 0u
            ? APROXY_PACKET_TCP_RELAY_DEFAULT_PENDING_LIMIT
            : config->pending_to_outbound_limit;
    relay->pending_to_client_limit =
        config->pending_to_client_limit == 0u
            ? APROXY_PACKET_TCP_RELAY_DEFAULT_PENDING_LIMIT
            : config->pending_to_client_limit;
    relay->idle_timeout_ms =
        config->idle_timeout_ms == 0u
            ? APROXY_PACKET_TCP_RELAY_DEFAULT_IDLE_TIMEOUT_MS
            : config->idle_timeout_ms;
    relay->loop = config->loop;
    relay->sniffing_enabled =
        config->sniffing_enabled != 0 && config->loop != NULL;
    relay->sniffing_max_bytes =
        config->sniffing_max_bytes == 0u
            ? APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_BYTES
            : config->sniffing_max_bytes;
    relay->sniffing_timeout_ms =
        config->sniffing_timeout_ms == 0u
            ? APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_TIMEOUT_MS
            : config->sniffing_timeout_ms;
    aproxy_bufpool_init(&relay->packet_pool, 9216u, 128u);
    relay->router = config->router;

    LOCK_TCPIP_CORE();
    ip4_addr_t ip;
    ip4_addr_t netmask;
    ip4_addr_t gateway;
    IP4_ADDR(&ip, 0, 0, 0, 0);
    IP4_ADDR(&netmask, 0, 0, 0, 0);
    IP4_ADDR(&gateway, 0, 0, 0, 0);
    if (netif_add(&relay->netif, &ip, &netmask, &gateway, relay,
                  tcp_netif_init, ip_input) == NULL) {
        UNLOCK_TCPIP_CORE();
        aproxy_bufpool_destroy(&relay->packet_pool);
        free(relay->listener_buckets);
        free(relay->buckets);
        free(relay);
        return APROXY_ERR_UNSUPPORTED;
    }
    relay->netif_added = 1;
    netif_set_up(&relay->netif);
    netif_set_link_up(&relay->netif);
    netif_set_default(&relay->netif);
    UNLOCK_TCPIP_CORE();

    *out = relay;
    return APROXY_OK;
}

static void free_session(packet_tcp_session_t *session)
{
    if (session == NULL) {
        return;
    }
    close_session(session);
    if (session->outbound_stream != NULL) {
        aproxy_stream_t *stream = session->outbound_stream;
        session->outbound_stream = NULL;
        session->outbound_close_pending = 0;
        aproxy_stream_free(stream);
    }
    aproxy_ring_free(&session->pending_to_outbound);
    aproxy_ring_free(&session->pending_to_client);
    free(session);
}

static void reap_closed_sessions(aproxy_packet_tcp_relay_t *relay)
{
    packet_tcp_session_t **cursor = &relay->sessions;
    while (*cursor != NULL) {
        packet_tcp_session_t *session = *cursor;
        if (!session->closed || session->outbound_opening ||
            session->outbound_close_pending ||
            session->outbound_stream != NULL || session->pcb != NULL ||
            session->listener != NULL || session->packet_stream != NULL) {
            cursor = &session->next;
            continue;
        }
        *cursor = session->next;
        session->next = NULL;
        aproxy_ring_free(&session->pending_to_outbound);
        aproxy_ring_free(&session->pending_to_client);
        free(session);
        relay->stats.sessions_reaped++;
    }
}

void aproxy_packet_tcp_relay_maintenance(
    aproxy_packet_tcp_relay_t *relay)
{
#if NO_SYS
    sys_check_timeouts();
#endif
    if (relay == NULL) {
        return;
    }
    const uint64_t now = relay_now_ms();
    LOCK_TCPIP_CORE();
    for (packet_tcp_session_t *session = relay->sessions; session != NULL;) {
        packet_tcp_session_t *next = session->next;
        if (!session->closed && now >= session->last_activity_ms &&
            now - session->last_activity_ms >= relay->idle_timeout_ms) {
            close_session(session);
            relay->stats.sessions_expired++;
        }
        session = next;
    }
    reap_closed_sessions(relay);
    UNLOCK_TCPIP_CORE();
}

void aproxy_packet_tcp_relay_free(aproxy_packet_tcp_relay_t *relay)
{
    if (relay == NULL) {
        return;
    }
    LOCK_TCPIP_CORE();
    packet_tcp_session_t *session = relay->sessions;
    while (session != NULL) {
        packet_tcp_session_t *next = session->next;
        free_session(session);
        session = next;
    }
    packet_tcp_listener_t *listener = relay->listeners;
    while (listener != NULL) {
        packet_tcp_listener_t *next = listener->next;
        if (listener->pcb != NULL) {
            tcp_arg(listener->pcb, NULL);
            tcp_accept(listener->pcb, NULL);
            if (tcp_close(listener->pcb) != ERR_OK) {
                tcp_abort(listener->pcb);
            }
        }
        free(listener);
        listener = next;
    }
    if (relay->netif_added) {
        netif_remove(&relay->netif);
    }
    UNLOCK_TCPIP_CORE();
    aproxy_bufpool_destroy(&relay->packet_pool);
    free(relay->listener_buckets);
    free(relay->buckets);
    free(relay);
}

int aproxy_packet_tcp_relay_on_session(
    aproxy_packet_tcp_relay_t *relay,
    aproxy_packet_session_t *packet_session,
    aproxy_stream_t *packet_stream,
    const aproxy_packet_flow_key_t *key)
{
    if (relay == NULL || packet_session == NULL || packet_stream == NULL ||
        key == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (key->proto != APROXY_PACKET_PROTO_TCP ||
        (key->family != APROXY_PACKET_FAMILY_IPV4 &&
         key->family != APROXY_PACKET_FAMILY_IPV6)) {
        relay->stats.sessions_unsupported++;
        return APROXY_ERR_UNSUPPORTED;
    }
    LOCK_TCPIP_CORE();
    reap_closed_sessions(relay);
    UNLOCK_TCPIP_CORE();
    if (find_session_by_packet_session(relay, packet_session) != NULL) {
        return APROXY_OK;
    }

    packet_tcp_session_t *session =
        (packet_tcp_session_t *)calloc(1u, sizeof(*session));
    if (session == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    session->relay = relay;
    session->packet_session = packet_session;
    session->packet_stream = packet_stream;
    session->key = *key;
    session_touch(session);
    aproxy_ring_init(&session->pending_to_outbound);
    aproxy_ring_init(&session->pending_to_client);
    int rc = key_destination(key, &session->destination);
    if (rc != APROXY_OK) {
        free_session(session);
        return rc;
    }

    LOCK_TCPIP_CORE();
    session->next = relay->sessions;
    relay->sessions = session;
    relay->stats.sessions_opened++;
    rc = index_session(session);
    if (rc == APROXY_OK) {
        rc = ensure_listener(relay, key, &session->listener);
    }
    if (rc != APROXY_OK) {
        relay->sessions = session->next;
        session->next = NULL;
        unindex_session(session);
        if (relay->stats.sessions_opened > 0u) {
            relay->stats.sessions_opened--;
        }
    }
    UNLOCK_TCPIP_CORE();
    if (rc != APROXY_OK) {
        free_session(session);
        relay->stats.open_errors++;
        return rc;
    }
    session->owns_packet_stream = 1;
    return APROXY_OK;
}

int aproxy_packet_tcp_relay_on_packet(
    aproxy_packet_tcp_relay_t *relay,
    aproxy_packet_session_t *packet_session,
    aproxy_stream_t *packet_stream,
    const uint8_t *packet,
    size_t packet_len)
{
    (void)packet_stream;
    if (relay == NULL || packet_session == NULL || packet == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const uint8_t *payload = NULL;
    size_t payload_len = 0u;
    int rc = parse_tcp_payload(packet, packet_len, &payload,
                               &payload_len);
    if (rc != APROXY_OK) {
        relay->stats.rx_errors++;
        return rc;
    }

    LOCK_TCPIP_CORE();
    packet_tcp_session_t *session =
        find_session_by_packet_session(relay, packet_session);
    if (session == NULL) {
        UNLOCK_TCPIP_CORE();
        relay->stats.sessions_unsupported++;
        return APROXY_ERR_UNSUPPORTED;
    }
    session_touch(session);
    rc = set_netif_destination(relay, &session->key);
    if (rc == APROXY_OK) {
        rc = relay_ip_input(session, packet, packet_len);
    }
    UNLOCK_TCPIP_CORE();
    if (rc != APROXY_OK) {
        relay->stats.rx_errors++;
        return rc;
    }
    relay->stats.tcp_packets_in++;
    relay->stats.tcp_payload_bytes_in += payload_len;
    return APROXY_OK;
}

void aproxy_packet_tcp_relay_get_stats(
    const aproxy_packet_tcp_relay_t *relay,
    aproxy_packet_tcp_relay_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (relay == NULL) {
        memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = relay->stats;
}
