#include "aproxy/packet_session.h"

#include <stdlib.h>
#include <string.h>

#include "platform.h"
#include "stream_internal.h"

struct aproxy_packet_session {
    aproxy_packet_session_table_t *table;
    aproxy_packet_flow_key_t key;
    aproxy_stream_t *stream;
    struct aproxy_packet_session *prev;
    struct aproxy_packet_session *next;
    struct aproxy_packet_session *hash_next;
    uint32_t id;
    unsigned int callback_depth;
    int closed;
    int indexed;
    int free_pending;
};

struct aproxy_packet_session_table {
    aproxy_packet_session_t *sessions;
    aproxy_packet_session_t **buckets;
    size_t bucket_count;
    uint32_t next_id;
    aproxy_packet_session_open_cb on_open;
    aproxy_packet_session_data_cb on_data;
    aproxy_packet_session_write_cb on_write;
    void *user_data;
    aproxy_packet_session_stats_t stats;
};

#define PACKET_SESSION_INITIAL_BUCKETS 64u
#define PACKET_SESSION_MAX_LOAD_NUM 3u
#define PACKET_SESSION_MAX_LOAD_DEN 4u

static int parse_ports(const uint8_t *packet,
                       size_t packet_len,
                       size_t offset,
                       aproxy_packet_flow_key_t *key)
{
    if (packet_len < offset + 4u) {
        return APROXY_ERR_INVALID_FRAME;
    }
    key->src_port = (uint16_t)(((uint16_t)packet[offset] << 8u) |
                               (uint16_t)packet[offset + 1u]);
    key->dst_port = (uint16_t)(((uint16_t)packet[offset + 2u] << 8u) |
                               (uint16_t)packet[offset + 3u]);
    return APROXY_OK;
}

static int parse_ipv4_key(const uint8_t *packet,
                          size_t packet_len,
                          aproxy_packet_flow_key_t *key)
{
    if (packet_len < 20u || (packet[0] >> 4u) != 4u) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const size_t header_len = (size_t)(packet[0] & 0x0fu) * 4u;
    if (header_len < 20u || packet_len < header_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const uint16_t total_len =
        (uint16_t)(((uint16_t)packet[2] << 8u) | (uint16_t)packet[3]);
    if (total_len < header_len || packet_len < (size_t)total_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const uint16_t frag =
        (uint16_t)(((uint16_t)packet[6] << 8u) | (uint16_t)packet[7]);
    if ((frag & 0x3fffu) != 0u) {
        return APROXY_ERR_UNSUPPORTED;
    }

    memset(key, 0, sizeof(*key));
    key->family = APROXY_PACKET_FAMILY_IPV4;
    key->proto = packet[9];
    memcpy(key->src_addr, packet + 12u, 4u);
    memcpy(key->dst_addr, packet + 16u, 4u);

    if (key->proto != APROXY_PACKET_PROTO_TCP &&
        key->proto != APROXY_PACKET_PROTO_UDP) {
        return APROXY_ERR_UNSUPPORTED;
    }
    return parse_ports(packet, (size_t)total_len, header_len, key);
}

static int parse_ipv6_key(const uint8_t *packet,
                          size_t packet_len,
                          aproxy_packet_flow_key_t *key)
{
    if (packet_len < 40u || (packet[0] >> 4u) != 6u) {
        return APROXY_ERR_INVALID_FRAME;
    }
    const size_t payload_len =
        ((size_t)packet[4] << 8u) | (size_t)packet[5];
    if (packet_len < 40u + payload_len) {
        return APROXY_ERR_INVALID_FRAME;
    }

    memset(key, 0, sizeof(*key));
    key->family = APROXY_PACKET_FAMILY_IPV6;
    key->proto = packet[6];
    memcpy(key->src_addr, packet + 8u, 16u);
    memcpy(key->dst_addr, packet + 24u, 16u);

    if (key->proto != APROXY_PACKET_PROTO_TCP &&
        key->proto != APROXY_PACKET_PROTO_UDP) {
        return APROXY_ERR_UNSUPPORTED;
    }
    return parse_ports(packet, packet_len, 40u, key);
}

static int parse_packet_key(const uint8_t *packet,
                            size_t packet_len,
                            aproxy_packet_flow_key_t *key)
{
    if (packet == NULL || key == NULL || packet_len == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const uint8_t version = (uint8_t)(packet[0] >> 4u);
    if (version == 4u) {
        return parse_ipv4_key(packet, packet_len, key);
    }
    if (version == 6u) {
        return parse_ipv6_key(packet, packet_len, key);
    }
    return APROXY_ERR_INVALID_FRAME;
}

static int flow_key_equal(const aproxy_packet_flow_key_t *a,
                          const aproxy_packet_flow_key_t *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

uint64_t aproxy_packet_flow_key_hash(const aproxy_packet_flow_key_t *key)
{
    const uint8_t *bytes = (const uint8_t *)key;
    uint64_t hash = UINT64_C(1469598103934665603);
    for (size_t i = 0u; i < sizeof(*key); i++) {
        hash ^= bytes[i];
        hash *= UINT64_C(1099511628211);
    }
    hash ^= hash >> 32u;
    return hash;
}

static size_t session_bucket(const aproxy_packet_session_table_t *table,
                             const aproxy_packet_flow_key_t *key)
{
    return (size_t)aproxy_packet_flow_key_hash(key) &
           (table->bucket_count - 1u);
}

static aproxy_packet_session_t *find_session(
    aproxy_packet_session_table_t *table,
    const aproxy_packet_flow_key_t *key)
{
    const size_t bucket = session_bucket(table, key);
    for (aproxy_packet_session_t *session = table->buckets[bucket];
         session != NULL; session = session->hash_next) {
        if (!session->closed && flow_key_equal(&session->key, key)) {
            return session;
        }
    }
    return NULL;
}

static int resize_buckets(aproxy_packet_session_table_t *table,
                          size_t next_count)
{
    aproxy_packet_session_t **next =
        (aproxy_packet_session_t **)calloc(next_count, sizeof(*next));
    if (next == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    aproxy_packet_session_t **old = table->buckets;
    table->buckets = next;
    table->bucket_count = next_count;
    for (aproxy_packet_session_t *session = table->sessions;
         session != NULL; session = session->next) {
        if (!session->indexed) {
            continue;
        }
        const size_t bucket = session_bucket(table, &session->key);
        session->hash_next = table->buckets[bucket];
        table->buckets[bucket] = session;
    }
    free(old);
    return APROXY_OK;
}

static int ensure_session_capacity(aproxy_packet_session_table_t *table)
{
    if (table->stats.sessions_active * PACKET_SESSION_MAX_LOAD_DEN <
        table->bucket_count * PACKET_SESSION_MAX_LOAD_NUM) {
        return APROXY_OK;
    }
    if (table->bucket_count > SIZE_MAX / 2u) {
        return APROXY_ERR_NO_MEMORY;
    }
    return resize_buckets(table, table->bucket_count * 2u);
}

static void index_session(aproxy_packet_session_table_t *table,
                          aproxy_packet_session_t *session)
{
    const size_t bucket = session_bucket(table, &session->key);
    session->hash_next = table->buckets[bucket];
    table->buckets[bucket] = session;
    session->indexed = 1;
}

static void unindex_session(aproxy_packet_session_table_t *table,
                            aproxy_packet_session_t *session)
{
    if (!session->indexed) {
        return;
    }
    const size_t bucket = session_bucket(table, &session->key);
    aproxy_packet_session_t **cursor = &table->buckets[bucket];
    while (*cursor != NULL) {
        if (*cursor == session) {
            *cursor = session->hash_next;
            session->hash_next = NULL;
            session->indexed = 0;
            return;
        }
        cursor = &(*cursor)->hash_next;
    }
}

static void deactivate_session(aproxy_packet_session_t *session)
{
    if (session == NULL || session->table == NULL || !session->indexed) {
        return;
    }
    aproxy_packet_session_table_t *table = session->table;
    unindex_session(table, session);
    if (table->stats.sessions_active > 0u) {
        table->stats.sessions_active--;
    }
}

static void remove_session(aproxy_packet_session_t *session)
{
    if (session == NULL || session->table == NULL) {
        return;
    }
    aproxy_packet_session_table_t *table = session->table;
    deactivate_session(session);
    if (session->prev != NULL) {
        session->prev->next = session->next;
    } else if (table->sessions == session) {
        table->sessions = session->next;
    }
    if (session->next != NULL) {
        session->next->prev = session->prev;
    }
    session->prev = NULL;
    session->next = NULL;
}

static void session_maybe_free(aproxy_packet_session_t *session)
{
    if (session == NULL || !session->free_pending ||
        session->callback_depth > 0u) {
        return;
    }
    remove_session(session);
    free(session);
}

static int packet_stream_write(void *impl, const uint8_t *data, size_t len)
{
    aproxy_packet_session_t *session =
        (aproxy_packet_session_t *)impl;
    if (session == NULL || session->closed ||
        (data == NULL && len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_packet_session_table_t *table = session->table;
    if (table == NULL || table->on_write == NULL) {
        return APROXY_ERR_UNSUPPORTED;
    }
    session->callback_depth++;
    const int rc = table->on_write(session, data, len, table->user_data);
    if (rc == APROXY_OK) {
        table->stats.packets_written++;
        table->stats.bytes_written += len;
    } else {
        table->stats.write_errors++;
    }
    session->callback_depth--;
    session_maybe_free(session);
    return rc;
}

static int packet_stream_close(void *impl)
{
    aproxy_packet_session_t *session =
        (aproxy_packet_session_t *)impl;
    if (session == NULL || session->closed) {
        return APROXY_OK;
    }
    session->closed = 1;
    deactivate_session(session);
    return APROXY_OK;
}

static uint32_t packet_stream_id(const void *impl)
{
    const aproxy_packet_session_t *session =
        (const aproxy_packet_session_t *)impl;
    return session == NULL ? 0u : session->id;
}

static void *packet_stream_native(const void *impl)
{
    return (void *)impl;
}

static void packet_stream_free(void *impl)
{
    aproxy_packet_session_t *session =
        (aproxy_packet_session_t *)impl;
    if (session == NULL) {
        return;
    }
    session->stream = NULL;
    session->free_pending = 1;
    session_maybe_free(session);
}

static const aproxy_stream_vtable_t packet_stream_vtable = {
    .write = packet_stream_write,
    .close = packet_stream_close,
    .id = packet_stream_id,
    .native = packet_stream_native,
    .free = packet_stream_free,
};

static int create_session(aproxy_packet_session_table_t *table,
                          const aproxy_packet_flow_key_t *key,
                          aproxy_packet_session_t **out)
{
    int rc = ensure_session_capacity(table);
    if (rc != APROXY_OK) {
        return rc;
    }
    aproxy_packet_session_t *session =
        (aproxy_packet_session_t *)calloc(1u, sizeof(*session));
    if (session == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    session->table = table;
    session->key = *key;
    session->id = ++table->next_id;

    rc = aproxy_stream_new(&packet_stream_vtable, session, &session->stream);
    if (rc != APROXY_OK) {
        free(session);
        return rc;
    }

    session->prev = NULL;
    session->next = table->sessions;
    if (table->sessions != NULL) {
        table->sessions->prev = session;
    }
    table->sessions = session;
    index_session(table, session);
    table->stats.sessions_created++;
    table->stats.sessions_active++;
    if (table->on_open != NULL) {
        session->callback_depth++;
        table->on_open(session, session->stream, &session->key,
                       table->user_data);
        session->callback_depth--;
    }
    if (session->free_pending) {
        session_maybe_free(session);
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (session->closed) {
        aproxy_stream_free(session->stream);
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = session;
    return APROXY_OK;
}

int aproxy_packet_session_table_new(
    const aproxy_packet_session_table_config_t *config,
    aproxy_packet_session_table_t **out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_packet_session_table_t *table =
        (aproxy_packet_session_table_t *)calloc(1u, sizeof(*table));
    if (table == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    table->buckets = (aproxy_packet_session_t **)calloc(
        PACKET_SESSION_INITIAL_BUCKETS, sizeof(*table->buckets));
    if (table->buckets == NULL) {
        free(table);
        return APROXY_ERR_NO_MEMORY;
    }
    table->bucket_count = PACKET_SESSION_INITIAL_BUCKETS;
    if (config != NULL) {
        table->on_open = config->on_open;
        table->on_data = config->on_data;
        table->on_write = config->on_write;
        table->user_data = config->user_data;
    }
    *out = table;
    return APROXY_OK;
}

void aproxy_packet_session_table_free(aproxy_packet_session_table_t *table)
{
    if (table == NULL) {
        return;
    }
    while (table->sessions != NULL) {
        aproxy_stream_t *stream = table->sessions->stream;
        aproxy_stream_free(stream);
    }
    free(table->buckets);
    free(table);
}

int aproxy_packet_session_table_dispatch_packet(
    aproxy_packet_session_table_t *table,
    const uint8_t *packet,
    size_t packet_len)
{
    if (table == NULL || packet == NULL || packet_len == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    aproxy_packet_flow_key_t key;
    const int parse_rc = parse_packet_key(packet, packet_len, &key);
    if (parse_rc != APROXY_OK) {
        if (parse_rc == APROXY_ERR_UNSUPPORTED) {
            if (packet_len >= 8u && (packet[0] >> 4u) == 4u) {
                const uint16_t frag =
                    (uint16_t)(((uint16_t)packet[6] << 8u) |
                               (uint16_t)packet[7]);
                if ((frag & 0x3fffu) != 0u) {
                    table->stats.packets_fragmented++;
                }
            }
            table->stats.packets_unsupported++;
        } else {
            table->stats.packets_invalid++;
        }
        return parse_rc;
    }

    table->stats.packets_classified++;
    aproxy_packet_session_t *session = find_session(table, &key);
    if (session == NULL) {
        int rc = create_session(table, &key, &session);
        if (rc != APROXY_OK) {
            return rc;
        }
    }

    table->stats.packets_delivered++;
    table->stats.bytes_delivered += packet_len;
    if (table->on_data != NULL) {
        session->callback_depth++;
        table->on_data(session, session->stream, packet, packet_len,
                       table->user_data);
        session->callback_depth--;
        session_maybe_free(session);
    }
    return APROXY_OK;
}

void aproxy_packet_session_table_get_stats(
    const aproxy_packet_session_table_t *table,
    aproxy_packet_session_stats_t *out_stats)
{
    if (out_stats == NULL) {
        return;
    }
    if (table == NULL) {
        memset(out_stats, 0, sizeof(*out_stats));
        return;
    }
    *out_stats = table->stats;
}

uint32_t aproxy_packet_session_id(const aproxy_packet_session_t *session)
{
    return session == NULL ? 0u : session->id;
}

const aproxy_packet_flow_key_t *aproxy_packet_session_key(
    const aproxy_packet_session_t *session)
{
    return session == NULL ? NULL : &session->key;
}
