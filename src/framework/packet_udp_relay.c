#include "aproxy/packet_udp_relay.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "aproxy/ring.h"
#include "aproxy/buffer.h"
#include "aproxy/bufpool.h"
#include "aproxy/limits.h"
#include "sniffer.h"
#include "aproxy/uot.h"

typedef struct packet_udp_session {
    aproxy_packet_udp_relay_t *relay;
    aproxy_packet_session_t *packet_session;
    aproxy_stream_t *packet_stream;
    aproxy_stream_t *uot_stream;
    aproxy_packet_flow_t *native_flow;
    aproxy_packet_flow_key_t key;
    aproxy_addr_t destination;
    aproxy_ring_t pending_tx;
    aproxy_ring_t rx;
    aproxy_ring_t sniff_pending;
    aproxy_buffer_t sniff_crypto;
    size_t sniff_packets;
    size_t sniff_bytes;
    uint64_t last_activity_ms;
    aproxy_outbound_udp_transport_t udp_transport;
    uint8_t uot_version;
    int stream_open;
    int request_sent;
    int closed;
    int owns_packet_stream;
    int sniff_pending_route;
    struct packet_udp_session *next;
    struct packet_udp_session *hash_next;
    int indexed;
} packet_udp_session_t;

#define PACKET_UDP_INITIAL_BUCKETS 64u
#define PACKET_UDP_NATIVE_SEND_BATCH_SIZE 16u
#define PACKET_UDP_POOL_MAX_FREE 16u

struct aproxy_packet_udp_relay {
    aproxy_router_t *router;
    packet_udp_session_t *sessions;
    packet_udp_session_t **buckets;
    size_t bucket_count;
    size_t indexed_count;
    size_t pending_tx_limit;
    size_t rx_limit;
    uint64_t idle_timeout_ms;
    size_t sniffing_max_bytes;
    size_t sniffing_max_packets;
    int sniffing_enabled;
    packet_udp_session_t *native_batch_session;
    aproxy_packet_flow_datagram_t native_batch[
        PACKET_UDP_NATIVE_SEND_BATCH_SIZE];
    size_t native_batch_count;
    unsigned int packet_batch_depth;
    aproxy_bufpool_t packet_pool;
    aproxy_packet_udp_relay_stats_t stats;
};

static uint64_t relay_now_ms(void)
{
    return uv_hrtime() / UINT64_C(1000000);
}

static void session_touch(packet_udp_session_t *session)
{
    session->last_activity_ms = relay_now_ms();
}

static void put_u16(uint8_t *out, uint16_t v)
{
    out[0] = (uint8_t)(v >> 8u);
    out[1] = (uint8_t)v;
}

static uint16_t get_u16(const uint8_t *in)
{
    return (uint16_t)(((uint16_t)in[0] << 8u) | (uint16_t)in[1]);
}

static int looks_like_quic_initial(const uint8_t *payload,
                                   size_t payload_len)
{
    if (payload == NULL || payload_len < 1200u ||
        (payload[0] & 0xf0u) != 0xc0u) {
        return 0;
    }
    const uint32_t version =
        ((uint32_t)payload[1] << 24u) |
        ((uint32_t)payload[2] << 16u) |
        ((uint32_t)payload[3] << 8u) |
        (uint32_t)payload[4];
    return version == 1u || version == UINT32_C(0xff00001d);
}

static uint16_t ipv4_header_checksum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0u;
    for (size_t i = 0u; i + 1u < len; i += 2u) {
        sum += (uint16_t)(((uint16_t)data[i] << 8u) | (uint16_t)data[i + 1u]);
    }
    if ((len & 1u) != 0u) {
        sum += (uint16_t)((uint16_t)data[len - 1u] << 8u);
    }
    while ((sum >> 16u) != 0u) {
        sum = (sum & 0xffffu) + (sum >> 16u);
    }
    return (uint16_t)~sum;
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

static int parse_ipv4_udp_payload(const uint8_t *packet,
                                  size_t packet_len,
                                  const uint8_t **payload,
                                  size_t *payload_len)
{
    if (packet == NULL || payload == NULL || payload_len == NULL ||
        packet_len < 28u || (packet[0] >> 4u) != 4u ||
        packet[9] != APROXY_PACKET_PROTO_UDP) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const size_t ip_header_len = (size_t)(packet[0] & 0x0fu) * 4u;
    if (ip_header_len < 20u || packet_len < ip_header_len + 8u) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const uint16_t total_len = get_u16(packet + 2u);
    const uint16_t udp_len = get_u16(packet + ip_header_len + 4u);
    if (total_len < ip_header_len + 8u ||
        packet_len < (size_t)total_len ||
        udp_len < 8u ||
        ip_header_len + (size_t)udp_len > (size_t)total_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    *payload = packet + ip_header_len + 8u;
    *payload_len = (size_t)udp_len - 8u;
    return APROXY_OK;
}

static int allocate_ipv4_udp_response(const packet_udp_session_t *session,
                                      const aproxy_addr_t *source,
                                      size_t payload_len,
                                      uint8_t **out_packet,
                                      size_t *out_len,
                                      size_t *out_capacity)
{
    if (session == NULL || source == NULL || out_packet == NULL ||
        out_len == NULL || out_capacity == NULL ||
        session->key.family != APROXY_PACKET_FAMILY_IPV4 ||
        source->family != APROXY_ADDR_IPV4 || payload_len > 65507u) {
        return APROXY_ERR_UNSUPPORTED;
    }

    const size_t total_len = 20u + 8u + payload_len;
    size_t capacity = 0u;
    uint8_t *packet = aproxy_bufpool_acquire(
        &session->relay->packet_pool, total_len, &capacity);
    if (packet == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    memset(packet, 0, 28u);

    packet[0] = 0x45u;
    packet[1] = 0x00u;
    put_u16(packet + 2u, (uint16_t)total_len);
    put_u16(packet + 4u, 0u);
    put_u16(packet + 6u, 0u);
    packet[8] = 64u;
    packet[9] = APROXY_PACKET_PROTO_UDP;
    memcpy(packet + 12u, source->addr, 4u);
    memcpy(packet + 16u, session->key.src_addr, 4u);
    put_u16(packet + 10u, ipv4_header_checksum(packet, 20u));

    const size_t udp = 20u;
    put_u16(packet + udp, source->port);
    put_u16(packet + udp + 2u, session->key.src_port);
    put_u16(packet + udp + 4u, (uint16_t)(8u + payload_len));
    put_u16(packet + udp + 6u, 0u);
    *out_packet = packet;
    *out_len = total_len;
    *out_capacity = capacity;
    return APROXY_OK;
}

static int submit_response_packet(packet_udp_session_t *session,
                                  uint8_t *packet,
                                  size_t packet_len,
                                  size_t capacity)
{
    const int rc = aproxy_stream_write(session->packet_stream, packet,
                                       packet_len);
    aproxy_bufpool_release(&session->relay->packet_pool, packet, capacity);
    if (rc != APROXY_OK) {
        session->relay->stats.write_errors++;
        return rc;
    }
    session->relay->stats.packets_written++;
    session->relay->stats.packet_bytes_written += packet_len;
    return APROXY_OK;
}

static int write_response_packet(packet_udp_session_t *session,
                                 const aproxy_addr_t *source,
                                 const uint8_t *payload,
                                 size_t payload_len)
{
    if (session == NULL || source == NULL ||
        (payload == NULL && payload_len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    uint8_t *packet = NULL;
    size_t packet_len = 0u;
    size_t capacity = 0u;
    int rc = allocate_ipv4_udp_response(session, source, payload_len, &packet,
                                        &packet_len, &capacity);
    if (rc != APROXY_OK) {
        session->relay->stats.rx_errors++;
        return rc;
    }

    if (payload_len > 0u) {
        memcpy(packet + 28u, payload, payload_len);
    }
    return submit_response_packet(session, packet, packet_len, capacity);
}

static int write_response_packet_from_ring(packet_udp_session_t *session,
                                           const aproxy_addr_t *source,
                                           size_t payload_offset,
                                           size_t payload_len)
{
    uint8_t *packet = NULL;
    size_t packet_len = 0u;
    size_t capacity = 0u;
    int rc = allocate_ipv4_udp_response(session, source, payload_len, &packet,
                                        &packet_len, &capacity);
    if (rc != APROXY_OK) {
        session->relay->stats.rx_errors++;
        return rc;
    }
    if (payload_len > 0u &&
        aproxy_ring_peek(&session->rx, payload_offset, packet + 28u,
                         payload_len) != payload_len) {
        aproxy_bufpool_release(&session->relay->packet_pool, packet, capacity);
        return APROXY_ERR_INVALID_FRAME;
    }
    return submit_response_packet(session, packet, packet_len, capacity);
}

static packet_udp_session_t *find_session(aproxy_packet_udp_relay_t *relay,
                                          aproxy_packet_session_t *session)
{
    if (relay == NULL || session == NULL) {
        return NULL;
    }
    const aproxy_packet_flow_key_t *key = aproxy_packet_session_key(session);
    if (key == NULL) {
        return NULL;
    }
    const size_t bucket = (size_t)aproxy_packet_flow_key_hash(key) &
                          (relay->bucket_count - 1u);
    for (packet_udp_session_t *cur = relay->buckets[bucket]; cur != NULL;
         cur = cur->hash_next) {
        if (cur->packet_session == session && !cur->closed) {
            return cur;
        }
    }
    return NULL;
}

static int resize_session_buckets(aproxy_packet_udp_relay_t *relay,
                                  size_t next_count)
{
    packet_udp_session_t **next =
        (packet_udp_session_t **)calloc(next_count, sizeof(*next));
    if (next == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    free(relay->buckets);
    relay->buckets = next;
    relay->bucket_count = next_count;
    for (packet_udp_session_t *session = relay->sessions; session != NULL;
         session = session->next) {
        if (session->closed) {
            session->indexed = 0;
            session->hash_next = NULL;
            continue;
        }
        const size_t bucket =
            (size_t)aproxy_packet_flow_key_hash(&session->key) &
            (relay->bucket_count - 1u);
        session->hash_next = relay->buckets[bucket];
        relay->buckets[bucket] = session;
        session->indexed = 1;
    }
    return APROXY_OK;
}

static int index_session(packet_udp_session_t *session)
{
    aproxy_packet_udp_relay_t *relay = session->relay;
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

static void unindex_session(packet_udp_session_t *session)
{
    if (session == NULL || !session->indexed) {
        return;
    }
    aproxy_packet_udp_relay_t *relay = session->relay;
    const size_t bucket =
        (size_t)aproxy_packet_flow_key_hash(&session->key) &
        (relay->bucket_count - 1u);
    packet_udp_session_t **cursor = &relay->buckets[bucket];
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

static int flush_uot_pending(packet_udp_session_t *session)
{
    if (session == NULL || session->uot_stream == NULL ||
        !session->stream_open) {
        return APROXY_OK;
    }
    while (aproxy_ring_size(&session->pending_tx) > 0u) {
        aproxy_const_span_t spans[2];
        const size_t count = aproxy_ring_read_spans(&session->pending_tx,
                                                    spans);
        if (count == 0u) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        for (size_t i = 0u; i < count; i++) {
            const int rc = aproxy_stream_write(session->uot_stream,
                                               spans[i].data,
                                               spans[i].len);
            if (rc != APROXY_OK) {
                session->relay->stats.write_errors++;
                return rc;
            }
            session->relay->stats.uot_bytes_out += spans[i].len;
        }
        aproxy_ring_consume(&session->pending_tx,
                            spans[0].len + (count > 1u ? spans[1].len : 0u));
    }
    return APROXY_OK;
}

static int queue_uot_packet(packet_udp_session_t *session,
                            const uint8_t *payload,
                            size_t payload_len)
{
    if (session == NULL || (payload == NULL && payload_len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    uint8_t request[APROXY_UOT_MAX_REQUEST_ENCODED];
    size_t request_len = 0u;
    if (!session->request_sent &&
        session->uot_version != APROXY_UOT_VERSION_1) {
        int rc = aproxy_uot_encode_request(0, &session->destination,
                                           request, sizeof(request),
                                           &request_len);
        if (rc != APROXY_OK) {
            return rc;
        }
    }

    uint8_t header[APROXY_UOT_MAX_PACKET_HEADER];
    size_t header_len = 0u;
    int rc = aproxy_uot_encode_packet_header(session->uot_version, 0,
                                             &session->destination,
                                             payload_len, header,
                                             sizeof(header), &header_len);
    if (rc != APROXY_OK) {
        return rc;
    }

    if (session->stream_open && session->uot_stream != NULL &&
        aproxy_ring_size(&session->pending_tx) == 0u) {
        if (request_len > 0u) {
            rc = aproxy_stream_write(session->uot_stream, request,
                                     request_len);
            if (rc != APROXY_OK) {
                return rc;
            }
            session->request_sent = 1;
            session->relay->stats.uot_bytes_out += request_len;
        }
        rc = aproxy_stream_write(session->uot_stream, header, header_len);
        if (rc == APROXY_OK && payload_len > 0u) {
            rc = aproxy_stream_write(session->uot_stream, payload,
                                     payload_len);
        }
        if (rc != APROXY_OK) {
            return rc;
        }
        session->relay->stats.uot_bytes_out += header_len + payload_len;
        session->relay->stats.uot_packets_out++;
        return APROXY_OK;
    }

    const size_t pending = aproxy_ring_size(&session->pending_tx);
    size_t append_len = request_len;
    if (aproxy_size_add_exceeds(append_len, header_len, SIZE_MAX)) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    append_len += header_len;
    if (aproxy_size_add_exceeds(append_len, payload_len, SIZE_MAX)) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    append_len += payload_len;
    if (append_len > session->relay->pending_tx_limit ||
        pending > session->relay->pending_tx_limit - append_len) {
        session->relay->stats.queue_limit_drops++;
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    rc = aproxy_ring_reserve(&session->pending_tx, pending + append_len);
    if (rc != APROXY_OK) {
        return rc;
    }

    if (request_len > 0u) {
        rc = aproxy_ring_write(&session->pending_tx, request, request_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        session->request_sent = 1;
    }
    rc = aproxy_ring_write(&session->pending_tx, header, header_len);
    if (rc == APROXY_OK && payload_len > 0u) {
        rc = aproxy_ring_write(&session->pending_tx, payload, payload_len);
    }
    if (rc != APROXY_OK) {
        return rc;
    }

    session->relay->stats.uot_packets_out++;
    return flush_uot_pending(session);
}

static int flush_native_pending(packet_udp_session_t *session)
{
    if (session == NULL || session->native_flow == NULL ||
        !session->stream_open) {
        return APROXY_OK;
    }
    while (aproxy_ring_size(&session->pending_tx) > 0u) {
        const size_t buffered = aproxy_ring_size(&session->pending_tx);
        aproxy_packet_flow_datagram_t datagrams[
            PACKET_UDP_NATIVE_SEND_BATCH_SIZE];
        size_t record_sizes[PACKET_UDP_NATIVE_SEND_BATCH_SIZE];
        size_t payload_lengths[PACKET_UDP_NATIVE_SEND_BATCH_SIZE];
        uint8_t *scratch[PACKET_UDP_NATIVE_SEND_BATCH_SIZE] = {0};
        size_t scratch_capacities[PACKET_UDP_NATIVE_SEND_BATCH_SIZE] = {0};
        size_t batch_count = 0u;
        size_t offset = 0u;
        int prepare_rc = APROXY_OK;
        while (batch_count < PACKET_UDP_NATIVE_SEND_BATCH_SIZE &&
               offset < buffered) {
            uint8_t len_bytes[2];
            if (buffered - offset < sizeof(len_bytes) ||
                aproxy_ring_peek(&session->pending_tx, offset, len_bytes,
                                 sizeof(len_bytes)) != sizeof(len_bytes)) {
                prepare_rc = APROXY_ERR_INVALID_FRAME;
                break;
            }
            const size_t payload_len = get_u16(len_bytes);
            const size_t record_size = sizeof(len_bytes) + payload_len;
            if (record_size > buffered - offset) {
                prepare_rc = APROXY_ERR_INVALID_FRAME;
                break;
            }
            aproxy_const_span_t spans[2];
            const size_t span_count = aproxy_ring_read_spans_at(
                &session->pending_tx, offset + sizeof(len_bytes),
                payload_len, spans);
            if (payload_len > 0u && span_count == 0u) {
                prepare_rc = APROXY_ERR_INVALID_FRAME;
                break;
            }
            const uint8_t *payload =
                payload_len == 0u ? NULL : spans[0].data;
            if (span_count == 2u) {
                scratch[batch_count] = aproxy_bufpool_acquire(
                    &session->relay->packet_pool, payload_len,
                    &scratch_capacities[batch_count]);
                if (scratch[batch_count] == NULL) {
                    prepare_rc = APROXY_ERR_NO_MEMORY;
                    break;
                }
                memcpy(scratch[batch_count], spans[0].data, spans[0].len);
                memcpy(scratch[batch_count] + spans[0].len,
                       spans[1].data, spans[1].len);
                payload = scratch[batch_count];
            }
            datagrams[batch_count].destination = &session->destination;
            datagrams[batch_count].data = payload;
            datagrams[batch_count].len = payload_len;
            record_sizes[batch_count] = record_size;
            payload_lengths[batch_count] = payload_len;
            batch_count++;
            offset += record_size;
        }

        size_t accepted = 0u;
        int rc = prepare_rc;
        const int supports_batch =
            aproxy_packet_flow_supports_batch(session->native_flow);
        if (rc == APROXY_OK && batch_count > 0u) {
            rc = aproxy_packet_flow_send_batch(
                session->native_flow, datagrams, batch_count, &accepted);
        }
        for (size_t i = 0u; i < batch_count; i++) {
            aproxy_bufpool_release(&session->relay->packet_pool,
                                   scratch[i], scratch_capacities[i]);
        }
        for (size_t i = 0u; i < accepted; i++) {
            aproxy_ring_consume(&session->pending_tx, record_sizes[i]);
            session->relay->stats.native_packets_out++;
            session->relay->stats.native_payload_bytes_out +=
                payload_lengths[i];
        }
        if (supports_batch && accepted > 1u) {
            session->relay->stats.native_send_batches++;
            session->relay->stats.native_send_batch_packets += accepted;
        }
        if (rc != APROXY_OK) {
            session->relay->stats.write_errors++;
            return rc;
        }
        if (batch_count == 0u || accepted != batch_count) {
            session->relay->stats.write_errors++;
            return APROXY_ERR_INVALID_FRAME;
        }
    }
    return APROXY_OK;
}

static int flush_native_borrowed(aproxy_packet_udp_relay_t *relay)
{
    if (relay == NULL || relay->native_batch_count == 0u) {
        return APROXY_OK;
    }
    packet_udp_session_t *session = relay->native_batch_session;
    const size_t count = relay->native_batch_count;
    relay->native_batch_session = NULL;
    relay->native_batch_count = 0u;
    if (session == NULL || session->closed || !session->stream_open ||
        session->native_flow == NULL) {
        relay->stats.write_errors++;
        return APROXY_ERR_BUSY;
    }

    size_t accepted = 0u;
    const int supports_batch =
        aproxy_packet_flow_supports_batch(session->native_flow);
    int rc = APROXY_OK;
    if (count == 1u) {
        const aproxy_packet_flow_datagram_t *datagram =
            &relay->native_batch[0];
        rc = aproxy_packet_flow_send(
            session->native_flow, datagram->destination,
            datagram->data, datagram->len);
        accepted = rc == APROXY_OK ? 1u : 0u;
    } else {
        rc = aproxy_packet_flow_send_batch(
            session->native_flow, relay->native_batch, count, &accepted);
    }
    session->relay->stats.native_packets_out += accepted;
    for (size_t i = 0u; i < accepted; i++) {
        session->relay->stats.native_payload_bytes_out +=
            relay->native_batch[i].len;
    }
    if (supports_batch && accepted > 1u) {
        session->relay->stats.native_send_batches++;
        session->relay->stats.native_send_batch_packets += accepted;
    }
    if (rc != APROXY_OK) {
        session->relay->stats.write_errors++;
        return rc;
    }
    if (accepted != count) {
        session->relay->stats.write_errors++;
        return APROXY_ERR_INVALID_FRAME;
    }
    return APROXY_OK;
}

static int queue_native_borrowed(packet_udp_session_t *session,
                                 const uint8_t *payload,
                                 size_t payload_len)
{
    aproxy_packet_udp_relay_t *relay = session->relay;
    if (relay->native_batch_session != NULL &&
        relay->native_batch_session != session) {
        const int rc = flush_native_borrowed(relay);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    relay->native_batch_session = session;
    aproxy_packet_flow_datagram_t *datagram =
        &relay->native_batch[relay->native_batch_count++];
    datagram->destination = &session->destination;
    datagram->data = payload;
    datagram->len = payload_len;
    if (relay->native_batch_count == PACKET_UDP_NATIVE_SEND_BATCH_SIZE) {
        return flush_native_borrowed(relay);
    }
    return APROXY_OK;
}

static int queue_native_packet_mode(packet_udp_session_t *session,
                                    const uint8_t *payload,
                                    size_t payload_len,
                                    int allow_borrow)
{
    if (session == NULL || (payload == NULL && payload_len > 0u) ||
        payload_len > UINT16_MAX) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (session->native_flow != NULL && session->stream_open &&
        aproxy_ring_size(&session->pending_tx) == 0u) {
        if (allow_borrow && session->relay->packet_batch_depth > 0u) {
            return queue_native_borrowed(session, payload, payload_len);
        }
        const int rc = aproxy_packet_flow_send(
            session->native_flow, &session->destination, payload,
            payload_len);
        if (rc == APROXY_OK) {
            session->relay->stats.native_packets_out++;
            session->relay->stats.native_payload_bytes_out += payload_len;
        }
        return rc;
    }

    uint8_t len_bytes[2];
    put_u16(len_bytes, (uint16_t)payload_len);
    const size_t pending = aproxy_ring_size(&session->pending_tx);
    const size_t append_len = sizeof(len_bytes) + payload_len;
    if (append_len > session->relay->pending_tx_limit ||
        pending > session->relay->pending_tx_limit - append_len) {
        session->relay->stats.queue_limit_drops++;
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    int rc = aproxy_ring_reserve(&session->pending_tx,
                                 pending + append_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = aproxy_ring_write(&session->pending_tx, len_bytes,
                           sizeof(len_bytes));
    if (rc == APROXY_OK && payload_len > 0u) {
        rc = aproxy_ring_write(&session->pending_tx, payload, payload_len);
    }
    if (rc != APROXY_OK) {
        return rc;
    }
    return flush_native_pending(session);
}

static int queue_native_packet(packet_udp_session_t *session,
                               const uint8_t *payload,
                               size_t payload_len)
{
    return queue_native_packet_mode(session, payload, payload_len, 1);
}

static int process_rx(packet_udp_session_t *session)
{
    if (session == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    for (;;) {
        const size_t buffered = aproxy_ring_size(&session->rx);
        if (buffered == 0u) {
            return APROXY_OK;
        }
        uint8_t header[APROXY_UOT_MAX_PACKET_HEADER];
        const size_t header_probe = buffered < sizeof(header)
                                        ? buffered
                                        : sizeof(header);
        if (aproxy_ring_peek(&session->rx, 0u, header, header_probe) !=
            header_probe) {
            return APROXY_ERR_INVALID_FRAME;
        }

        aproxy_addr_t source;
        uint16_t payload_len = 0u;
        size_t header_len = 0u;
        const int rc = aproxy_uot_decode_packet_header(
            session->uot_version, 0, header, header_probe, &source,
            &payload_len, &header_len);
        if (rc == APROXY_ERR_BUFFER_TOO_SMALL) {
            return APROXY_OK;
        }
        if (rc != APROXY_OK) {
            session->relay->stats.rx_errors++;
            return rc;
        }
        if (buffered < header_len + (size_t)payload_len) {
            return APROXY_OK;
        }

        int build_rc = write_response_packet_from_ring(
            session, &source, header_len, payload_len);
        if (build_rc != APROXY_OK) {
            return build_rc;
        }

        aproxy_ring_consume(&session->rx, header_len + payload_len);
        session->relay->stats.uot_packets_in++;
        session->relay->stats.uot_payload_bytes_in += payload_len;
    }
}

static void uot_data_cb(aproxy_stream_t *stream,
                        const uint8_t *data,
                        size_t len,
                        void *user_data)
{
    (void)stream;
    packet_udp_session_t *session = (packet_udp_session_t *)user_data;
    if (session == NULL || data == NULL || session->closed) {
        return;
    }
    session_touch(session);
    const size_t buffered = aproxy_ring_size(&session->rx);
    if (len > session->relay->rx_limit ||
        buffered > session->relay->rx_limit - len) {
        session->relay->stats.rx_errors++;
        session->relay->stats.rx_limit_closes++;
        session->closed = 1;
        unindex_session(session);
        (void)aproxy_stream_close(stream);
        return;
    }
    if (aproxy_ring_write(&session->rx, data, len) != APROXY_OK ||
        process_rx(session) != APROXY_OK) {
        session->relay->stats.rx_errors++;
    }
}

static void uot_open_cb(aproxy_stream_t *stream, int status, void *user_data)
{
    packet_udp_session_t *session = (packet_udp_session_t *)user_data;
    if (session == NULL || session->closed) {
        return;
    }
    if (status != APROXY_OK) {
        session->relay->stats.open_errors++;
        return;
    }
    if (session->uot_stream == NULL) {
        session->uot_stream = stream;
    }
    session->stream_open = 1;
    if (flush_uot_pending(session) != APROXY_OK) {
        session->relay->stats.write_errors++;
    }
}

static void uot_close_cb(aproxy_stream_t *stream, int status, void *user_data)
{
    (void)status;
    packet_udp_session_t *session = (packet_udp_session_t *)user_data;
    if (session == NULL) {
        return;
    }
    if (session->uot_stream == stream) {
        session->uot_stream = NULL;
        aproxy_stream_free(stream);
    }
    unindex_session(session);
    session->closed = 1;
    if (session->owns_packet_stream && session->packet_stream != NULL) {
        aproxy_stream_t *packet_stream = session->packet_stream;
        session->packet_stream = NULL;
        session->packet_session = NULL;
        session->owns_packet_stream = 0;
        (void)aproxy_stream_close(packet_stream);
        aproxy_stream_free(packet_stream);
    }
}

static void native_data_cb(aproxy_packet_flow_t *flow,
                           const aproxy_addr_t *source,
                           const uint8_t *data,
                           size_t len,
                           void *user_data)
{
    (void)flow;
    packet_udp_session_t *session = (packet_udp_session_t *)user_data;
    if (session == NULL || source == NULL || (data == NULL && len > 0u)) {
        return;
    }
    session_touch(session);
    if (write_response_packet(session, source, data, len) != APROXY_OK) {
        session->relay->stats.rx_errors++;
        return;
    }
    session->relay->stats.native_packets_in++;
    session->relay->stats.native_payload_bytes_in += len;
}

static void native_open_cb(aproxy_packet_flow_t *flow,
                           int status,
                           void *user_data)
{
    packet_udp_session_t *session = (packet_udp_session_t *)user_data;
    if (session == NULL || session->closed) {
        return;
    }
    if (status != APROXY_OK) {
        session->relay->stats.open_errors++;
        return;
    }
    if (session->native_flow == NULL) {
        session->native_flow = flow;
    }
    session->stream_open = 1;
    if (flush_native_pending(session) != APROXY_OK) {
        session->relay->stats.write_errors++;
    }
}

static void native_close_cb(aproxy_packet_flow_t *flow,
                            int status,
                            void *user_data)
{
    (void)status;
    packet_udp_session_t *session = (packet_udp_session_t *)user_data;
    if (session == NULL) {
        return;
    }
    if (session->native_flow == flow) {
        session->native_flow = NULL;
        aproxy_packet_flow_free(flow);
    }
    unindex_session(session);
    session->closed = 1;
    if (session->owns_packet_stream && session->packet_stream != NULL) {
        aproxy_stream_t *packet_stream = session->packet_stream;
        session->packet_stream = NULL;
        session->packet_session = NULL;
        session->owns_packet_stream = 0;
        (void)aproxy_stream_close(packet_stream);
        aproxy_stream_free(packet_stream);
    }
}

static void free_session(packet_udp_session_t *session)
{
    if (session == NULL) {
        return;
    }
    if (session->uot_stream != NULL) {
        aproxy_stream_t *stream = session->uot_stream;
        session->uot_stream = NULL;
        (void)aproxy_stream_close(stream);
        aproxy_stream_free(stream);
    }
    if (session->native_flow != NULL) {
        aproxy_packet_flow_t *flow = session->native_flow;
        session->native_flow = NULL;
        (void)aproxy_packet_flow_close(flow);
        aproxy_packet_flow_free(flow);
    }
    if (session->owns_packet_stream && session->packet_stream != NULL) {
        aproxy_stream_t *stream = session->packet_stream;
        session->packet_stream = NULL;
        session->packet_session = NULL;
        session->owns_packet_stream = 0;
        (void)aproxy_stream_close(stream);
        aproxy_stream_free(stream);
    }
    aproxy_ring_free(&session->pending_tx);
    aproxy_ring_free(&session->rx);
    aproxy_ring_free(&session->sniff_pending);
    aproxy_buffer_free(&session->sniff_crypto);
    free(session);
}

static void reap_closed_sessions(aproxy_packet_udp_relay_t *relay)
{
    packet_udp_session_t **cursor = &relay->sessions;
    while (*cursor != NULL) {
        packet_udp_session_t *session = *cursor;
        if (!session->closed || session->uot_stream != NULL ||
            session->native_flow != NULL || session->packet_stream != NULL) {
            cursor = &session->next;
            continue;
        }
        *cursor = session->next;
        session->next = NULL;
        aproxy_ring_free(&session->pending_tx);
        aproxy_ring_free(&session->rx);
        aproxy_ring_free(&session->sniff_pending);
        aproxy_buffer_free(&session->sniff_crypto);
        free(session);
        relay->stats.sessions_reaped++;
    }
    if (relay->sessions == NULL) {
        aproxy_bufpool_trim(&relay->packet_pool);
    }
}

static void close_idle_session(packet_udp_session_t *session)
{
    if (session == NULL || session->closed) {
        return;
    }
    unindex_session(session);
    session->closed = 1;
    if (session->uot_stream != NULL) {
        (void)aproxy_stream_close(session->uot_stream);
    }
    if (session->native_flow != NULL) {
        (void)aproxy_packet_flow_close(session->native_flow);
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

void aproxy_packet_udp_relay_maintenance(
    aproxy_packet_udp_relay_t *relay)
{
    if (relay == NULL) {
        return;
    }
    const uint64_t now = relay_now_ms();
    for (packet_udp_session_t *session = relay->sessions; session != NULL;) {
        packet_udp_session_t *next = session->next;
        if (!session->closed && now >= session->last_activity_ms &&
            now - session->last_activity_ms >= relay->idle_timeout_ms) {
            close_idle_session(session);
            relay->stats.sessions_expired++;
        }
        session = next;
    }
    reap_closed_sessions(relay);
}

void aproxy_packet_udp_relay_begin_packet_batch(
    aproxy_packet_udp_relay_t *relay)
{
    if (relay == NULL) {
        return;
    }
    if (relay->packet_batch_depth < UINT_MAX) {
        relay->packet_batch_depth++;
    }
}

int aproxy_packet_udp_relay_end_packet_batch(
    aproxy_packet_udp_relay_t *relay)
{
    if (relay == NULL || relay->packet_batch_depth == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    relay->packet_batch_depth--;
    if (relay->packet_batch_depth > 0u) {
        return APROXY_OK;
    }
    return flush_native_borrowed(relay);
}

int aproxy_packet_udp_relay_new(
    const aproxy_packet_udp_relay_config_t *config,
    aproxy_packet_udp_relay_t **out)
{
    if (config == NULL || out == NULL || config->router == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    aproxy_packet_udp_relay_t *relay =
        (aproxy_packet_udp_relay_t *)calloc(1u, sizeof(*relay));
    if (relay == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    relay->buckets = (packet_udp_session_t **)calloc(
        PACKET_UDP_INITIAL_BUCKETS, sizeof(*relay->buckets));
    if (relay->buckets == NULL) {
        free(relay);
        return APROXY_ERR_NO_MEMORY;
    }
    relay->bucket_count = PACKET_UDP_INITIAL_BUCKETS;
    aproxy_bufpool_init(&relay->packet_pool, 9216u,
                        PACKET_UDP_POOL_MAX_FREE);
    relay->router = config->router;
    relay->pending_tx_limit =
        config->pending_tx_limit == 0u
            ? APROXY_PACKET_UDP_RELAY_DEFAULT_PENDING_LIMIT
            : config->pending_tx_limit;
    relay->rx_limit = config->rx_limit == 0u
                          ? APROXY_PACKET_UDP_RELAY_DEFAULT_RX_LIMIT
                          : config->rx_limit;
    relay->idle_timeout_ms =
        config->idle_timeout_ms == 0u
            ? APROXY_PACKET_UDP_RELAY_DEFAULT_IDLE_TIMEOUT_MS
            : config->idle_timeout_ms;
    relay->sniffing_enabled = config->sniffing_enabled != 0;
    relay->sniffing_max_bytes =
        config->sniffing_max_bytes == 0u
            ? APROXY_PACKET_UDP_RELAY_DEFAULT_SNIFF_BYTES
            : config->sniffing_max_bytes;
    relay->sniffing_max_packets =
        config->sniffing_max_packets == 0u
            ? APROXY_PACKET_UDP_RELAY_DEFAULT_SNIFF_PACKETS
            : config->sniffing_max_packets;
    *out = relay;
    return APROXY_OK;
}

void aproxy_packet_udp_relay_free(aproxy_packet_udp_relay_t *relay)
{
    if (relay == NULL) {
        return;
    }
    packet_udp_session_t *session = relay->sessions;
    while (session != NULL) {
        packet_udp_session_t *next = session->next;
        free_session(session);
        session = next;
    }
    free(relay->buckets);
    aproxy_bufpool_destroy(&relay->packet_pool);
    free(relay);
}

static int open_session_transport(packet_udp_session_t *session,
                                  aproxy_outbound_t *outbound)
{
    if (session == NULL || outbound == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    session->udp_transport = outbound->udp_transport;
    session->uot_version = outbound->uot_version;
    if (session->udp_transport == APROXY_OUTBOUND_UDP_UOT) {
        if (session->uot_version != APROXY_UOT_VERSION_1 &&
            session->uot_version != APROXY_UOT_VERSION_2) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        session->request_sent =
            session->uot_version == APROXY_UOT_VERSION_1;
        aproxy_addr_t transport_destination = session->destination;
        int rc = aproxy_uot_request_destination(
            session->uot_version, &transport_destination);
        if (rc != APROXY_OK) {
            return rc;
        }
        return aproxy_outbound_open_stream(
            outbound, &transport_destination, uot_data_cb, uot_open_cb,
            uot_close_cb, session, &session->uot_stream);
    }
    if (session->udp_transport != APROXY_OUTBOUND_UDP_PACKET) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return aproxy_outbound_open_packet(
        outbound, &session->destination, native_data_cb, native_open_cb,
        native_close_cb, session, &session->native_flow);
}

static aproxy_outbound_t *sniff_route(packet_udp_session_t *session,
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

static int store_sniff_packet(packet_udp_session_t *session,
                              const uint8_t *payload,
                              size_t payload_len)
{
    if (session == NULL || (payload == NULL && payload_len > 0u) ||
        payload_len > UINT16_MAX) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t pending = aproxy_ring_size(&session->sniff_pending);
    const size_t append = 2u + payload_len;
    if (append > session->relay->sniffing_max_bytes ||
        pending > session->relay->sniffing_max_bytes - append) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    uint8_t length[2];
    put_u16(length, (uint16_t)payload_len);
    int rc = aproxy_ring_write(&session->sniff_pending, length,
                               sizeof(length));
    if (rc == APROXY_OK) {
        rc = aproxy_ring_write(&session->sniff_pending, payload,
                               payload_len);
    }
    return rc;
}

static int queue_owned_payload(packet_udp_session_t *session,
                               const uint8_t *payload,
                               size_t payload_len)
{
    return session->udp_transport == APROXY_OUTBOUND_UDP_UOT
               ? queue_uot_packet(session, payload, payload_len)
               : queue_native_packet_mode(session, payload, payload_len, 0);
}

static int drain_sniff_packets(packet_udp_session_t *session)
{
    while (aproxy_ring_size(&session->sniff_pending) > 0u) {
        uint8_t length[2];
        if (aproxy_ring_peek(&session->sniff_pending, 0u, length,
                             sizeof(length)) != sizeof(length)) {
            return APROXY_ERR_INVALID_FRAME;
        }
        const size_t payload_len = get_u16(length);
        if (aproxy_ring_size(&session->sniff_pending) < 2u + payload_len) {
            return APROXY_ERR_INVALID_FRAME;
        }
        aproxy_const_span_t spans[2];
        const size_t count = aproxy_ring_read_spans_at(
            &session->sniff_pending, 2u, payload_len, spans);
        int rc = APROXY_OK;
        if (count == 1u) {
            rc = queue_owned_payload(session, spans[0].data, spans[0].len);
        } else {
            size_t capacity = 0u;
            uint8_t *copy = aproxy_bufpool_acquire(
                &session->relay->packet_pool, payload_len, &capacity);
            if (copy == NULL) {
                return APROXY_ERR_NO_MEMORY;
            }
            if (aproxy_ring_peek(&session->sniff_pending, 2u, copy,
                                 payload_len) != payload_len) {
                rc = APROXY_ERR_INVALID_FRAME;
            } else {
                rc = queue_owned_payload(session, copy, payload_len);
            }
            aproxy_bufpool_release(&session->relay->packet_pool, copy,
                                   capacity);
        }
        if (rc != APROXY_OK) {
            return rc;
        }
        aproxy_ring_consume(&session->sniff_pending, 2u + payload_len);
    }
    return APROXY_OK;
}

static int finish_udp_sniff(packet_udp_session_t *session,
                            aproxy_sniff_status_t status,
                            const aproxy_sniff_result_t *result)
{
    if (session == NULL || !session->sniff_pending_route) {
        return APROXY_OK;
    }
    session->sniff_pending_route = 0;
    aproxy_outbound_t *outbound = NULL;
    if (status == APROXY_SNIFF_MATCH) {
        outbound = sniff_route(session, result);
        if (outbound != NULL) {
            session->relay->stats.sniff_matches++;
            session->relay->stats.sniff_quic_matches++;
        }
    }
    if (outbound == NULL) {
        session->relay->stats.sniff_fallbacks++;
        outbound = aproxy_router_pick(session->relay->router,
                                      &session->destination);
    }
    int rc = open_session_transport(session, outbound);
    if (rc == APROXY_OK) {
        rc = drain_sniff_packets(session);
    }
    aproxy_ring_free(&session->sniff_pending);
    aproxy_buffer_free(&session->sniff_crypto);
    return rc;
}

int aproxy_packet_udp_relay_on_session(
    aproxy_packet_udp_relay_t *relay,
    aproxy_packet_session_t *packet_session,
    aproxy_stream_t *packet_stream,
    const aproxy_packet_flow_key_t *key)
{
    if (relay == NULL || packet_session == NULL || packet_stream == NULL ||
        key == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (key->proto != APROXY_PACKET_PROTO_UDP ||
        key->family != APROXY_PACKET_FAMILY_IPV4) {
        relay->stats.sessions_unsupported++;
        return APROXY_ERR_UNSUPPORTED;
    }
    reap_closed_sessions(relay);
    if (find_session(relay, packet_session) != NULL) {
        return APROXY_OK;
    }

    packet_udp_session_t *session =
        (packet_udp_session_t *)calloc(1u, sizeof(*session));
    if (session == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    session->relay = relay;
    session->packet_session = packet_session;
    session->packet_stream = packet_stream;
    session->key = *key;
    session_touch(session);
    aproxy_ring_init(&session->pending_tx);
    aproxy_ring_init(&session->rx);
    aproxy_ring_init(&session->sniff_pending);
    aproxy_buffer_init(&session->sniff_crypto);

    int rc = key_destination(key, &session->destination);
    if (rc != APROXY_OK) {
        free_session(session);
        return rc;
    }

    session->next = relay->sessions;
    relay->sessions = session;
    rc = index_session(session);
    if (rc != APROXY_OK) {
        relay->sessions = session->next;
        session->next = NULL;
        free_session(session);
        return rc;
    }
    relay->stats.sessions_opened++;
    session->sniff_pending_route =
        relay->sniffing_enabled && key->dst_port == 443u;
    if (session->sniff_pending_route) {
        session->owns_packet_stream = 1;
        relay->stats.sniff_attempts++;
        return APROXY_OK;
    }

    aproxy_outbound_t *outbound = aproxy_router_pick(
        relay->router, &session->destination);
    rc = open_session_transport(session, outbound);
    if (rc != APROXY_OK) {
        relay->sessions = session->next;
        unindex_session(session);
        relay->stats.open_errors++;
        free_session(session);
        return rc;
    }
    session->owns_packet_stream = 1;
    if (session->closed) {
        aproxy_stream_t *stream = session->packet_stream;
        session->packet_stream = NULL;
        session->packet_session = NULL;
        session->owns_packet_stream = 0;
        (void)aproxy_stream_close(stream);
        aproxy_stream_free(stream);
    }
    return APROXY_OK;
}

int aproxy_packet_udp_relay_on_packet(
    aproxy_packet_udp_relay_t *relay,
    aproxy_packet_session_t *packet_session,
    aproxy_stream_t *packet_stream,
    const uint8_t *packet,
    size_t packet_len)
{
    if (relay == NULL || packet_session == NULL || packet_stream == NULL ||
        packet == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    packet_udp_session_t *session = find_session(relay, packet_session);
    if (session == NULL) {
        relay->stats.sessions_unsupported++;
        return APROXY_ERR_UNSUPPORTED;
    }
    session_touch(session);

    const uint8_t *payload = NULL;
    size_t payload_len = 0u;
    int rc = parse_ipv4_udp_payload(packet, packet_len, &payload,
                                    &payload_len);
    if (rc != APROXY_OK) {
        relay->stats.rx_errors++;
        return rc;
    }
    if (session->sniff_pending_route) {
        aproxy_sniff_result_t result;
        memset(&result, 0, sizeof(result));
        aproxy_sniff_status_t status = APROXY_SNIFF_NO_MATCH;
        const size_t remaining =
            session->sniff_bytes < relay->sniffing_max_bytes
                ? relay->sniffing_max_bytes - session->sniff_bytes
                : 0u;
        if (payload_len <= remaining &&
            looks_like_quic_initial(payload, payload_len)) {
            size_t capacity = 0u;
            uint8_t *scratch = aproxy_bufpool_acquire(
                &relay->packet_pool, payload_len, &capacity);
            if (scratch != NULL) {
                status = aproxy_sniff_quic_initial(
                    payload, payload_len, scratch, capacity,
                    &session->sniff_crypto, relay->sniffing_max_bytes,
                    &result);
                aproxy_bufpool_release(&relay->packet_pool, scratch,
                                       capacity);
            }
        }
        session->sniff_packets++;
        if (session->sniff_bytes <= SIZE_MAX - payload_len) {
            session->sniff_bytes += payload_len;
        } else {
            session->sniff_bytes = SIZE_MAX;
        }
        if (status == APROXY_SNIFF_NEED_MORE &&
            session->sniff_packets < relay->sniffing_max_packets &&
            session->sniff_bytes < relay->sniffing_max_bytes) {
            rc = store_sniff_packet(session, payload, payload_len);
            if (rc == APROXY_OK) {
                relay->stats.udp_packets_in++;
                relay->stats.udp_payload_bytes_in += payload_len;
                return APROXY_OK;
            }
            status = APROXY_SNIFF_NO_MATCH;
        } else if (status == APROXY_SNIFF_NEED_MORE) {
            status = APROXY_SNIFF_NO_MATCH;
        }
        rc = finish_udp_sniff(session, status, &result);
        if (rc != APROXY_OK) {
            relay->stats.open_errors++;
            close_idle_session(session);
            return rc;
        }
    }
    if (session->udp_transport == APROXY_OUTBOUND_UDP_UOT) {
        rc = queue_uot_packet(session, payload, payload_len);
    } else {
        rc = queue_native_packet(session, payload, payload_len);
    }
    if (rc != APROXY_OK) {
        relay->stats.write_errors++;
        return rc;
    }
    relay->stats.udp_packets_in++;
    relay->stats.udp_payload_bytes_in += payload_len;
    return APROXY_OK;
}

void aproxy_packet_udp_relay_get_stats(
    const aproxy_packet_udp_relay_t *relay,
    aproxy_packet_udp_relay_stats_t *out_stats)
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
