#include "aproxy/engine.h"

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "anytls/outbound.h"
#include "aproxy/direct_outbound.h"
#include "aproxy/error.h"
#include "aproxy/inbound.h"
#include "aproxy/library.h"
#include "aproxy/memory.h"
#if defined(APROXY_ENABLE_TUN)
#include "aproxy/buffer.h"
#include "aproxy/packet_tcp_relay.h"
#include "aproxy/packet_udp_relay.h"
#include "aproxy/ring.h"
#endif
#include "aproxy/reality.h"
#include "aproxy/socket_protect.h"
#include "aproxy/socks5_inbound.h"
#include "aproxy/tls.h"
#include "platform.h"
#if defined(APROXY_ENABLE_TUN)
#include "aproxy/tun_inbound.h"
#endif
#include "shadowsocks/outbound.h"
#include "vless/outbound.h"

#define ENGINE_ID "aproxy-core"
#define ENGINE_SCHEMA "aproxy.proxy-config"
#define ENGINE_SCHEMA_VERSION 2u
#define ENGINE_ARENA_CHUNK 16384u
#define ENGINE_MAX_DEPTH 32u
#define ENGINE_MAX_NODES 65536u
#define ENGINE_MAX_CONFIG_BYTES (8u * 1024u * 1024u)
#define ENGINE_MAX_OUTBOUNDS 258u
#define ENGINE_MAX_OUTBOUND_TAG_BYTES 255u
#define ENGINE_MAX_ROUTE_RULES 8192u
#define ENGINE_MAX_ROUTE_PROFILES 64u
#define ENGINE_ERROR_SIZE 384u
#define ENGINE_MAX_PENDING_SOCKET_PROTECT 4096u
#define ENGINE_TUN_INGRESS_LIMIT (4u * 1024u * 1024u)
#define ENGINE_TUN_PACKET_HEADER_SIZE 4u
#define ENGINE_TUN_MAX_PACKET_SIZE 65535u
#define ENGINE_TUN_MAX_BATCH 256u

typedef struct arena_chunk {
    struct arena_chunk *next;
    size_t used;
    size_t capacity;
    unsigned char data[];
} arena_chunk_t;

typedef struct value_arena {
    arena_chunk_t *head;
    size_t node_count;
    size_t allocated_capacity;
} value_arena_t;

typedef struct owned_config {
    value_arena_t arena;
    aproxy_engine_config_v2_t value;
} owned_config_t;

typedef enum command_kind {
    COMMAND_NONE = 0,
    COMMAND_VALIDATE,
    COMMAND_START,
    COMMAND_RELOAD,
    COMMAND_SELECT_NODE,
    COMMAND_SELECT_ROUTING,
    COMMAND_STOP,
    COMMAND_SHUTDOWN
} command_kind_t;

typedef struct engine_command {
    command_kind_t kind;
    uint64_t operation_id;
    owned_config_t *config;
    char *selection_id;
} engine_command_t;

typedef struct engine_socket_protect_request {
    struct engine_socket_protect_request *next;
    uint64_t id;
    aproxy_socket_protect_result_cb result;
    void *result_context;
    int status;
} engine_socket_protect_request_t;

typedef enum cleanup_action {
    CLEANUP_NONE = 0,
    CLEANUP_STOP,
    CLEANUP_RELOAD,
    CLEANUP_ERROR,
    CLEANUP_SHUTDOWN
} cleanup_action_t;

struct aproxy_engine {
    aproxy_engine_host_v2_t host;
    uv_mutex_t mutex;
    uv_sem_t ready;
    uv_thread_t thread;
    int thread_started;
    int ready_status;

    uv_loop_t native_loop;
    int native_loop_initialized;
    aproxy_loop_t *loop;
    uv_async_t command_async;
    uv_timer_t cleanup_timer;
    uv_timer_t stats_timer;
    int handles_initialized;
    engine_command_t pending;
    engine_socket_protect_request_t *protect_pending;
    engine_socket_protect_request_t *protect_completed_head;
    engine_socket_protect_request_t *protect_completed_tail;
    uint64_t next_protect_request_id;
    size_t protect_pending_count;

    cleanup_action_t cleanup_action;
    uint64_t cleanup_operation_id;
    owned_config_t *reload_config;
    int cleanup_status;
    char cleanup_error[ENGINE_ERROR_SIZE];

    aproxy_node_t *node;
    aproxy_inbound_t *inbound;
#if defined(APROXY_ENABLE_TUN)
    aproxy_packet_tcp_relay_t *tcp_relay;
    aproxy_packet_udp_relay_t *packet_relay;
    aproxy_packet_tcp_relay_stats_t packet_tcp_stats;
    aproxy_packet_udp_relay_stats_t packet_udp_stats;
    uv_timer_t flow_timer;
    aproxy_ring_t tun_ingress;
    aproxy_ring_t tun_ingress_drain;
    aproxy_buffer_t tun_packet_scratch;
    uint64_t tun_packets_submitted;
    uint64_t tun_bytes_submitted;
    uint64_t tun_packets_dropped;
#endif
    int inbound_is_tun;
    uint16_t bound_port;
    uint64_t active_operation_id;
    uint64_t started_at_ms;

    uint32_t state;
    int last_status;
    uint64_t config_revision;
    char last_error[ENGINE_ERROR_SIZE];
    char active_node[ENGINE_MAX_OUTBOUND_TAG_BYTES + 1u];
    char active_routing[65u];
    aproxy_socks5_udp_stats_t udp_stats;
    aproxy_memory_stats_t memory_stats;
    size_t process_memory_bytes;
};

static void command_cb(uv_async_t *handle);
static void cleanup_timer_cb(uv_timer_t *timer);
static void stats_timer_cb(uv_timer_t *timer);
static int engine_complete_socket_protect(aproxy_engine_t *engine,
                                          uint64_t request_id,
                                          int status);
static int engine_submit_tun_packets(aproxy_engine_t *engine,
                                     const aproxy_bytes_view_t *packets,
                                     size_t packet_count);
#if defined(APROXY_ENABLE_TUN)
static void flow_timer_cb(uv_timer_t *timer);
#endif

static size_t align_up(size_t value, size_t alignment)
{
    return (value + alignment - 1u) & ~(alignment - 1u);
}

static engine_socket_protect_request_t *remove_protect_request_locked(
    aproxy_engine_t *engine,
    uint64_t request_id)
{
    engine_socket_protect_request_t **link = &engine->protect_pending;
    while (*link != NULL) {
        engine_socket_protect_request_t *request = *link;
        if (request->id == request_id) {
            *link = request->next;
            request->next = NULL;
            if (engine->protect_pending_count > 0u) {
                engine->protect_pending_count--;
            }
            return request;
        }
        link = &request->next;
    }
    return NULL;
}

static int submit_socket_protect(void *context,
                                 intptr_t socket_handle,
                                 aproxy_socket_protect_result_cb result,
                                 void *result_context)
{
    aproxy_engine_t *engine = (aproxy_engine_t *)context;
    if (engine == NULL || socket_handle < 0 || result == NULL ||
        (engine->host.submit_socket_protect == NULL &&
         engine->host.protect_socket == NULL)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    engine_socket_protect_request_t *request =
        (engine_socket_protect_request_t *)calloc(1u, sizeof(*request));
    if (request == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    request->result = result;
    request->result_context = result_context;

    uv_mutex_lock(&engine->mutex);
    if (engine->protect_pending_count >=
        ENGINE_MAX_PENDING_SOCKET_PROTECT) {
        uv_mutex_unlock(&engine->mutex);
        free(request);
        return APROXY_ERR_BUSY;
    }
    request->id = ++engine->next_protect_request_id;
    if (request->id == 0u) {
        request->id = ++engine->next_protect_request_id;
    }
    request->next = engine->protect_pending;
    engine->protect_pending = request;
    engine->protect_pending_count++;
    uv_mutex_unlock(&engine->mutex);

    int rc = APROXY_OK;
    if (engine->host.submit_socket_protect != NULL) {
        rc = engine->host.submit_socket_protect(
            engine->host.context, request->id, socket_handle);
    } else {
        const int status = engine->host.protect_socket(
            engine->host.context, socket_handle);
        rc = engine_complete_socket_protect(engine, request->id, status);
    }
    if (rc == APROXY_OK) {
        return APROXY_OK;
    }

    uv_mutex_lock(&engine->mutex);
    engine_socket_protect_request_t *removed =
        remove_protect_request_locked(engine, request->id);
    uv_mutex_unlock(&engine->mutex);
    if (removed == NULL) {
        /* A completion raced a host rejection; honor the accepted result. */
        return APROXY_OK;
    }
    free(removed);
    return rc;
}

static void dispatch_socket_protect_results(aproxy_engine_t *engine)
{
    uv_mutex_lock(&engine->mutex);
    engine_socket_protect_request_t *completed =
        engine->protect_completed_head;
    engine->protect_completed_head = NULL;
    engine->protect_completed_tail = NULL;
    uv_mutex_unlock(&engine->mutex);

    while (completed != NULL) {
        engine_socket_protect_request_t *next = completed->next;
        completed->result(completed->result_context, completed->status);
        free(completed);
        completed = next;
    }
}

static void *arena_alloc(value_arena_t *arena, size_t size, size_t alignment)
{
    if (arena == NULL || size == 0u || alignment == 0u) {
        return NULL;
    }
    if (size > SIZE_MAX - alignment ||
        size + alignment > SIZE_MAX - sizeof(arena_chunk_t)) {
        return NULL;
    }
    arena_chunk_t *chunk = arena->head;
    size_t offset = chunk == NULL ? 0u : align_up(chunk->used, alignment);
    if (chunk == NULL || offset > chunk->capacity ||
        size > chunk->capacity - offset) {
        const size_t minimum = size + alignment;
        const size_t capacity =
            minimum > ENGINE_ARENA_CHUNK ? minimum : ENGINE_ARENA_CHUNK;
        if (capacity > ENGINE_MAX_CONFIG_BYTES -
                           arena->allocated_capacity) {
            return NULL;
        }
        chunk = (arena_chunk_t *)malloc(sizeof(*chunk) + capacity);
        if (chunk == NULL) {
            return NULL;
        }
        chunk->next = arena->head;
        chunk->used = 0u;
        chunk->capacity = capacity;
        arena->head = chunk;
        arena->allocated_capacity += capacity;
        offset = 0u;
    }
    void *result = chunk->data + offset;
    chunk->used = offset + size;
    memset(result, 0, size);
    return result;
}

static char *arena_string(value_arena_t *arena,
                          const char *data,
                          size_t len)
{
    if ((data == NULL && len > 0u) || len == SIZE_MAX) {
        return NULL;
    }
    char *copy = (char *)arena_alloc(arena, len + 1u, 1u);
    if (copy == NULL) {
        return NULL;
    }
    if (len > 0u) {
        memcpy(copy, data, len);
    }
    copy[len] = '\0';
    return copy;
}

static int clone_value(value_arena_t *arena,
                       const aproxy_value_t *source,
                       aproxy_value_t *destination,
                       unsigned int depth)
{
    if (arena == NULL || source == NULL || destination == NULL ||
        source->struct_size < sizeof(*source) || depth > ENGINE_MAX_DEPTH ||
        ++arena->node_count > ENGINE_MAX_NODES) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    destination->struct_size = sizeof(*destination);
    destination->type = source->type;
    switch ((aproxy_value_type_t)source->type) {
    case APROXY_VALUE_NULL:
        return APROXY_OK;
    case APROXY_VALUE_BOOL:
        destination->as.boolean = source->as.boolean != 0;
        return APROXY_OK;
    case APROXY_VALUE_I64:
        destination->as.i64 = source->as.i64;
        return APROXY_OK;
    case APROXY_VALUE_U64:
        destination->as.u64 = source->as.u64;
        return APROXY_OK;
    case APROXY_VALUE_F64:
        destination->as.f64 = source->as.f64;
        return APROXY_OK;
    case APROXY_VALUE_STRING: {
        char *copy = arena_string(arena, source->as.string.data,
                                  source->as.string.len);
        if (copy == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        destination->as.string.data = copy;
        destination->as.string.len = source->as.string.len;
        return APROXY_OK;
    }
    case APROXY_VALUE_BYTES: {
        if (source->as.bytes.data == NULL && source->as.bytes.len > 0u) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        uint8_t *copy = (uint8_t *)arena_alloc(
            arena, source->as.bytes.len == 0u ? 1u : source->as.bytes.len, 1u);
        if (copy == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        if (source->as.bytes.len > 0u) {
            memcpy(copy, source->as.bytes.data, source->as.bytes.len);
        }
        destination->as.bytes.data = copy;
        destination->as.bytes.len = source->as.bytes.len;
        return APROXY_OK;
    }
    case APROXY_VALUE_ARRAY: {
        if (source->as.array.count > ENGINE_MAX_NODES ||
            (source->as.array.values == NULL &&
             source->as.array.count > 0u)) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        aproxy_value_t *values = NULL;
        if (source->as.array.count > 0u) {
            values = (aproxy_value_t *)arena_alloc(
                arena, source->as.array.count * sizeof(*values),
                _Alignof(aproxy_value_t));
            if (values == NULL) {
                return APROXY_ERR_NO_MEMORY;
            }
        }
        destination->as.array.values = values;
        destination->as.array.count = source->as.array.count;
        for (size_t i = 0u; i < source->as.array.count; i++) {
            int rc = clone_value(arena, &source->as.array.values[i],
                                 &values[i], depth + 1u);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
        return APROXY_OK;
    }
    case APROXY_VALUE_OBJECT: {
        if (source->as.object.count > ENGINE_MAX_NODES ||
            (source->as.object.entries == NULL &&
             source->as.object.count > 0u)) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        aproxy_object_entry_t *entries = NULL;
        if (source->as.object.count > 0u) {
            entries = (aproxy_object_entry_t *)arena_alloc(
                arena, source->as.object.count * sizeof(*entries),
                _Alignof(aproxy_object_entry_t));
            if (entries == NULL) {
                return APROXY_ERR_NO_MEMORY;
            }
        }
        destination->as.object.entries = entries;
        destination->as.object.count = source->as.object.count;
        for (size_t i = 0u; i < source->as.object.count; i++) {
            const aproxy_object_entry_t *item =
                &source->as.object.entries[i];
            char *key = arena_string(arena, item->key.data, item->key.len);
            aproxy_value_t *value = (aproxy_value_t *)arena_alloc(
                arena, sizeof(*value), _Alignof(aproxy_value_t));
            if (key == NULL || value == NULL || item->value == NULL) {
                return APROXY_ERR_INVALID_ARGUMENT;
            }
            entries[i].key.data = key;
            entries[i].key.len = item->key.len;
            entries[i].value = value;
            int rc = clone_value(arena, item->value, value, depth + 1u);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
        return APROXY_OK;
    }
    default:
        return APROXY_ERR_UNSUPPORTED;
    }
}

static void arena_free(value_arena_t *arena)
{
    arena_chunk_t *chunk = arena == NULL ? NULL : arena->head;
    while (chunk != NULL) {
        arena_chunk_t *next = chunk->next;
        free(chunk);
        chunk = next;
    }
    if (arena != NULL) {
        memset(arena, 0, sizeof(*arena));
    }
}

static void owned_config_free(owned_config_t *config)
{
    if (config != NULL) {
        arena_free(&config->arena);
        free(config);
    }
}

static void command_payload_free(engine_command_t *command)
{
    if (command == NULL) {
        return;
    }
    owned_config_free(command->config);
    free(command->selection_id);
    command->config = NULL;
    command->selection_id = NULL;
}

static int owned_config_new(const aproxy_engine_config_v2_t *source,
                            owned_config_t **out)
{
    if (source == NULL || out == NULL ||
        source->abi_version != APROXY_ENGINE_ABI_VERSION ||
        source->struct_size < sizeof(*source) || source->root == NULL ||
        source->schema_version != ENGINE_SCHEMA_VERSION) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    owned_config_t *config =
        (owned_config_t *)calloc(1u, sizeof(*config));
    if (config == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    aproxy_value_t *root = (aproxy_value_t *)arena_alloc(
        &config->arena, sizeof(*root), _Alignof(aproxy_value_t));
    char *schema = arena_string(&config->arena, source->schema_id.data,
                                source->schema_id.len);
    int rc = root == NULL || schema == NULL
                 ? APROXY_ERR_NO_MEMORY
                 : clone_value(&config->arena, source->root, root, 0u);
    if (rc != APROXY_OK) {
        owned_config_free(config);
        return rc;
    }
    config->value = *source;
    config->value.struct_size = sizeof(config->value);
    config->value.schema_id.data = schema;
    config->value.root = root;
    *out = config;
    return APROXY_OK;
}

static const aproxy_value_t *object_get(const aproxy_value_t *object,
                                        const char *key)
{
    if (object == NULL || key == NULL ||
        object->type != APROXY_VALUE_OBJECT) {
        return NULL;
    }
    const size_t len = strlen(key);
    for (size_t i = 0u; i < object->as.object.count; i++) {
        const aproxy_object_entry_t *entry = &object->as.object.entries[i];
        if (entry->key.len == len &&
            memcmp(entry->key.data, key, len) == 0) {
            return entry->value;
        }
    }
    return NULL;
}

static const char *as_string(const aproxy_value_t *value)
{
    return value != NULL && value->type == APROXY_VALUE_STRING
               ? value->as.string.data
               : NULL;
}

static int as_bool(const aproxy_value_t *value, int fallback, int *out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (value == NULL) {
        *out = fallback;
        return APROXY_OK;
    }
    if (value->type != APROXY_VALUE_BOOL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = value->as.boolean != 0;
    return APROXY_OK;
}

static int as_i64(const aproxy_value_t *value,
                  int64_t fallback,
                  int64_t minimum,
                  int64_t maximum,
                  int64_t *out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int64_t result = fallback;
    if (value != NULL) {
        if (value->type == APROXY_VALUE_I64) {
            result = value->as.i64;
        } else if (value->type == APROXY_VALUE_U64 &&
                   value->as.u64 <= (uint64_t)INT64_MAX) {
            result = (int64_t)value->as.u64;
        } else {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
    }
    if (result < minimum || result > maximum) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = result;
    return APROXY_OK;
}

static int as_size(const aproxy_value_t *value,
                   size_t fallback,
                   size_t *out)
{
    int64_t result = 0;
    int rc = as_i64(value, (int64_t)fallback, 0, INT64_MAX, &result);
    if (rc != APROXY_OK || (uint64_t)result > SIZE_MAX) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = (size_t)result;
    return APROXY_OK;
}

static void copy_error(char *destination,
                       size_t capacity,
                       const char *source)
{
    if (destination != NULL && capacity > 0u) {
        snprintf(destination, capacity, "%s", source == NULL ? "" : source);
    }
}

static int field_error(char *error,
                       size_t capacity,
                       const char *field,
                       const char *reason)
{
    snprintf(error, capacity, "%s: %s", field, reason);
    return APROXY_ERR_INVALID_ARGUMENT;
}

static int parse_reality(const aproxy_value_t *outbound,
                         const char *security,
                         aproxy_reality_config_t *reality,
                         char *error,
                         size_t error_size)
{
    memset(reality, 0, sizeof(*reality));
    if (strcmp(security, "reality") != 0) {
        return APROXY_OK;
    }
    const aproxy_value_t *object = object_get(outbound, "reality");
    const char *public_key = as_string(object_get(object, "publicKey"));
    const char *short_id = as_string(object_get(object, "shortId"));
    if (object == NULL || object->type != APROXY_VALUE_OBJECT ||
        public_key == NULL) {
        return field_error(error, error_size, "reality",
                           "publicKey is required");
    }
    int rc = aproxy_reality_config_parse(
        public_key, short_id == NULL ? "" : short_id, reality);
    if (rc != APROXY_OK) {
        return field_error(error, error_size, "reality",
                           "invalid publicKey or shortId");
    }
    return APROXY_OK;
}

static int parse_ech(const aproxy_value_t *outbound,
                     aproxy_ech_config_t *ech,
                     uint8_t **storage,
                     char *error,
                     size_t error_size)
{
    memset(ech, 0, sizeof(*ech));
    *storage = NULL;
    const aproxy_value_t *object = object_get(outbound, "ech");
    if (object == NULL) {
        return APROXY_OK;
    }
    if (object->type != APROXY_VALUE_OBJECT ||
        as_bool(object_get(object, "grease"), 0, &ech->grease) !=
            APROXY_OK ||
        as_bool(object_get(object, "required"), 0, &ech->required) !=
            APROXY_OK) {
        return field_error(error, error_size, "ech", "invalid object");
    }
    const char *encoded = as_string(object_get(object, "configList"));
    if (encoded != NULL && encoded[0] != '\0') {
        int rc = aproxy_ech_config_list_decode_base64(
            encoded, storage, &ech->config_list_len);
        if (rc != APROXY_OK) {
            return field_error(error, error_size, "ech.configList",
                               "invalid ECHConfigList");
        }
        ech->config_list = *storage;
    }
    return APROXY_OK;
}

static int validate_alpn(const aproxy_value_t *value)
{
    if (value == NULL) {
        return APROXY_OK;
    }
    if (value->type == APROXY_VALUE_STRING) {
        return value->as.string.len > 0u &&
                       value->as.string.len <= 4096u
                   ? APROXY_OK
                   : APROXY_ERR_INVALID_ARGUMENT;
    }
    if (value->type != APROXY_VALUE_ARRAY ||
        value->as.array.count == 0u ||
        value->as.array.count > 32u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    size_t total = 0u;
    for (size_t i = 0u; i < value->as.array.count; i++) {
        const aproxy_value_t *item = &value->as.array.values[i];
        if (item->type != APROXY_VALUE_STRING ||
            item->as.string.len == 0u ||
            item->as.string.len > 255u) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        total += item->as.string.len;
        if (total > 4096u) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
    }
    return APROXY_OK;
}

static int validate_outbound(const aproxy_value_t *outbound,
                             char *error,
                             size_t error_size)
{
    if (outbound == NULL || outbound->type != APROXY_VALUE_OBJECT) {
        return field_error(error, error_size, "outbounds[]",
                           "must be an object");
    }
    const char *type = as_string(object_get(outbound, "type"));
    const aproxy_value_t *tag_value = object_get(outbound, "tag");
    const char *tag = as_string(tag_value);
    if (type == NULL || tag == NULL || tag[0] == '\0' ||
        tag_value->as.string.len > ENGINE_MAX_OUTBOUND_TAG_BYTES ||
        memchr(tag, '\0', tag_value->as.string.len) != NULL) {
        return field_error(error, error_size, "outbounds[]",
                           "type and a valid tag are required");
    }
    size_t size_value = 0u;
    if (as_size(object_get(outbound, "readBufferSize"), 0u,
                &size_value) != APROXY_OK ||
        as_size(object_get(outbound, "maxPendingBytes"), 0u,
                &size_value) != APROXY_OK) {
        return field_error(error, error_size, tag,
                           "invalid buffer limit");
    }
    if (strcmp(type, "direct") == 0 || strcmp(type, "block") == 0) {
        if (object_get(outbound, "udpTransport") != NULL ||
            object_get(outbound, "uotVersion") != NULL) {
            return field_error(error, error_size, tag,
                               "UDP transport is fixed for this outbound");
        }
        return APROXY_OK;
    }
    int64_t port = 0;
    const char *server = as_string(object_get(outbound, "server"));
    if (server == NULL || server[0] == '\0' ||
        as_i64(object_get(outbound, "port"), 0, 1, 65535, &port) !=
            APROXY_OK) {
        return field_error(error, error_size, tag,
                           "server and valid port are required");
    }
    if (strcmp(type, "shadowsocks") == 0) {
        const char *method = as_string(object_get(outbound, "method"));
        const char *password =
            as_string(object_get(outbound, "password"));
        const char *udp_transport =
            as_string(object_get(outbound, "udpTransport"));
        int64_t uot_version = 2;
        if (method == NULL || method[0] == '\0' || password == NULL ||
            password[0] == '\0') {
            return field_error(error, error_size, tag,
                               "method and password are required");
        }
        if ((object_get(outbound, "udpTransport") != NULL &&
             (udp_transport == NULL ||
              (strcmp(udp_transport, "native") != 0 &&
               strcmp(udp_transport, "uot") != 0))) ||
            as_i64(object_get(outbound, "uotVersion"), 2, 1, 2,
                   &uot_version) != APROXY_OK ||
            (object_get(outbound, "uotVersion") != NULL &&
             (udp_transport == NULL ||
              strcmp(udp_transport, "uot") != 0))) {
            return field_error(error, error_size, tag,
                               "invalid Shadowsocks transport");
        }
        return APROXY_OK;
    }
    if (strcmp(type, "anytls") != 0 && strcmp(type, "vless") != 0) {
        return field_error(error, error_size, tag,
                           "unsupported outbound type");
    }
    const char *security = as_string(object_get(outbound, "security"));
    security = security == NULL
                   ? (strcmp(type, "anytls") == 0 ? "tls" : "none")
                   : security;
    if ((strcmp(type, "anytls") == 0 && strcmp(security, "tls") != 0 &&
         strcmp(security, "reality") != 0) ||
        (strcmp(type, "vless") == 0 && strcmp(security, "none") != 0 &&
         strcmp(security, "tls") != 0 &&
         strcmp(security, "reality") != 0)) {
        return field_error(error, error_size, tag, "invalid security");
    }
    const char *credential =
        as_string(object_get(outbound, strcmp(type, "anytls") == 0
                                           ? "password"
                                           : "uuid"));
    if (credential == NULL || credential[0] == '\0') {
        return field_error(error, error_size, tag,
                           "protocol credential is required");
    }
    if (validate_alpn(object_get(outbound, "alpn")) != APROXY_OK) {
        return field_error(error, error_size, tag, "invalid alpn");
    }
    int insecure = 0;
    if (as_bool(object_get(outbound, "insecure"), 0, &insecure) !=
        APROXY_OK) {
        return field_error(error, error_size, tag,
                           "invalid insecure flag");
    }
    (void)insecure;

    if (strcmp(type, "anytls") == 0) {
        int64_t setting = 0;
        if (object_get(outbound, "udpTransport") != NULL ||
            as_i64(object_get(outbound, "uotVersion"), 2, 1, 2,
                   &setting) != APROXY_OK ||
            as_i64(object_get(outbound, "heartbeatIntervalMs"), 0,
                   -1, INT64_MAX, &setting) != APROXY_OK ||
            as_i64(object_get(outbound, "heartbeatTimeoutMs"), 0,
                   0, INT64_MAX, &setting) != APROXY_OK ||
            as_i64(object_get(outbound, "idleSessionCheckIntervalMs"),
                   0, 0, INT64_MAX, &setting) != APROXY_OK ||
            as_i64(object_get(outbound, "idleSessionTimeoutMs"), 0,
                   0, INT64_MAX, &setting) != APROXY_OK ||
            as_i64(object_get(outbound, "minIdleSessions"), 0,
                   0, INT_MAX, &setting) != APROXY_OK ||
            as_i64(object_get(outbound, "maxIdleSessions"), 0,
                   0, INT_MAX, &setting) != APROXY_OK) {
            return field_error(error, error_size, tag,
                               "invalid session setting");
        }
    } else if (object_get(outbound, "udpTransport") != NULL ||
               object_get(outbound, "uotVersion") != NULL) {
        return field_error(error, error_size, tag,
                           "UDP transport is fixed for VLESS");
    }
    aproxy_reality_config_t reality;
    aproxy_ech_config_t ech;
    uint8_t *ech_storage = NULL;
    int rc = parse_reality(outbound, security, &reality, error, error_size);
    if (rc == APROXY_OK) {
        rc = parse_ech(outbound, &ech, &ech_storage, error, error_size);
    }
    if (rc == APROXY_OK && strcmp(security, "reality") == 0 &&
        (ech.config_list_len > 0u || ech.grease || ech.required)) {
        rc = field_error(error, error_size, tag,
                         "Reality cannot be combined with ECH");
    }
    if (rc == APROXY_OK && strcmp(security, "none") == 0 &&
        (ech.config_list_len > 0u || ech.grease || ech.required)) {
        rc = field_error(error, error_size, tag,
                         "ECH requires TLS security");
    }
    if (rc == APROXY_OK && strcmp(type, "vless") == 0) {
        const char *flow = as_string(object_get(outbound, "flow"));
        const char *encryption =
            as_string(object_get(outbound, "encryption"));
        flow = flow == NULL ? "" : flow;
        encryption = encryption == NULL ? "none" : encryption;
        if (flow[0] != '\0' &&
            strcmp(flow, "xtls-rprx-vision") != 0) {
            rc = field_error(error, error_size, tag,
                             "unsupported VLESS flow");
        } else if (strcmp(flow, "xtls-rprx-vision") == 0 &&
                   strcmp(security, "none") == 0 &&
                   strcmp(encryption, "none") == 0) {
            rc = field_error(error, error_size, tag,
                             "Vision requires an outer security layer");
        }
    }
    free(ech_storage);
    return rc;
}

static int outbound_tag_exists(const aproxy_value_t *outbounds,
                               const char *tag)
{
    if (outbounds == NULL || tag == NULL) {
        return 0;
    }
    for (size_t i = 0u; i < outbounds->as.array.count; i++) {
        const char *candidate = as_string(object_get(
            &outbounds->as.array.values[i], "tag"));
        if (candidate != NULL && strcmp(candidate, tag) == 0) {
            return 1;
        }
    }
    return 0;
}

static int validate_cidr_text(const char *cidr)
{
    if (cidr == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const char *slash = strchr(cidr, '/');
    const size_t host_len = slash == NULL ? strlen(cidr)
                                          : (size_t)(slash - cidr);
    if (host_len == 0u || host_len >= INET6_ADDRSTRLEN) {
        return APROXY_ERR_PARSE;
    }
    char host[INET6_ADDRSTRLEN];
    memcpy(host, cidr, host_len);
    host[host_len] = '\0';
    uint8_t address[16];
    unsigned long maximum = 32u;
    if (inet_pton(AF_INET, host, address) != 1) {
        maximum = 128u;
        if (inet_pton(AF_INET6, host, address) != 1) {
            return APROXY_ERR_PARSE;
        }
    }
    if (slash == NULL) {
        return APROXY_OK;
    }
    char *end = NULL;
    errno = 0;
    const unsigned long prefix = strtoul(slash + 1, &end, 10);
    return errno == 0 && end != slash + 1 && *end == '\0' &&
                   prefix <= maximum
               ? APROXY_OK
               : APROXY_ERR_PARSE;
}

static int validate_inbound(const aproxy_value_t *inbound,
                            char *error,
                            size_t error_size)
{
    const char *type = as_string(object_get(inbound, "type"));
    if (inbound == NULL || inbound->type != APROXY_VALUE_OBJECT ||
        type == NULL) {
        return field_error(error, error_size, "inbounds[0]",
                           "inbound type is required");
    }
    const aproxy_value_t *tag = object_get(inbound, "tag");
    if (tag != NULL && as_string(tag) == NULL) {
        return field_error(error, error_size, "inbounds[0]",
                           "tag must be a string");
    }
    int flag = 0;
    int64_t number = 0;
    size_t size_value = 0u;
    if (strcmp(type, "socks5") == 0) {
        const aproxy_value_t *listen = object_get(inbound, "listen");
        if (listen != NULL && as_string(listen) == NULL) {
            return field_error(error, error_size, "inbounds[0]",
                               "listen must be a string");
        }
        if (as_bool(object_get(inbound, "allowLan"), 0, &flag) !=
            APROXY_OK ||
            as_i64(object_get(inbound, "port"), 1080, 0, 65535,
                   &number) != APROXY_OK ||
            as_i64(object_get(inbound, "uotVersion"), 2, 1, 2,
                   &number) != APROXY_OK ||
            as_size(object_get(inbound, "streamPendingLimit"), 0u,
                    &size_value) != APROXY_OK ||
            as_size(object_get(inbound, "udpPendingLimit"), 0u,
                    &size_value) != APROXY_OK ||
            as_size(object_get(inbound, "udpStreamRxLimit"), 0u,
                    &size_value) != APROXY_OK) {
            return field_error(error, error_size, "inbounds[0]",
                               "invalid SOCKS5 setting");
        }
        return APROXY_OK;
    }
#if defined(APROXY_ENABLE_TUN)
    if (strcmp(type, "tun") == 0) {
        const char *ipv4 = as_string(object_get(inbound, "ipv4"));
        const char *ipv6 = as_string(object_get(inbound, "ipv6"));
        uint8_t address[16];
        if ((object_get(inbound, "ipv4") != NULL && ipv4 == NULL) ||
            (ipv4 != NULL && inet_pton(AF_INET, ipv4, address) != 1) ||
            (object_get(inbound, "ipv6") != NULL && ipv6 == NULL) ||
            (ipv6 != NULL && inet_pton(AF_INET6, ipv6, address) != 1)) {
            return field_error(error, error_size, "inbounds[0]",
                               "invalid TUN address");
        }
        if (object_get(inbound, "udpRelayMode") != NULL ||
            object_get(inbound, "uotVersion") != NULL) {
            return field_error(error, error_size, "inbounds[0]",
                               "UDP transport must be configured per outbound");
        }
        if (as_i64(object_get(inbound, "mtu"), APROXY_TUN_DEFAULT_MTU,
                   576, 65535, &number) != APROXY_OK ||
            as_i64(object_get(inbound, "ipv4Prefix"),
                   APROXY_TUN_DEFAULT_IPV4_PREFIX, 0, 32,
                   &number) != APROXY_OK ||
            as_i64(object_get(inbound, "ipv6Prefix"),
                   APROXY_TUN_DEFAULT_IPV6_PREFIX, 0, 128,
                   &number) != APROXY_OK ||
            as_size(object_get(inbound, "udpPendingLimit"), 0u,
                    &size_value) != APROXY_OK ||
            as_size(object_get(inbound, "udpStreamRxLimit"), 0u,
                    &size_value) != APROXY_OK ||
            as_i64(object_get(inbound, "tcpFlowIdleTimeoutMs"), 0,
                   0, INT64_MAX, &number) != APROXY_OK ||
            as_i64(object_get(inbound, "udpFlowIdleTimeoutMs"), 0,
                   0, INT64_MAX, &number) != APROXY_OK) {
            return field_error(error, error_size, "inbounds[0]",
                               "invalid TUN setting");
        }
        return APROXY_OK;
    }
#endif
    return field_error(error, error_size, "inbounds[0]",
                       "unsupported inbound type");
}

static int validate_dns_and_memory(const aproxy_value_t *root,
                                   char *error,
                                   size_t error_size)
{
    const aproxy_value_t *dns = object_get(root, "dns");
    if (dns != NULL && dns->type != APROXY_VALUE_OBJECT) {
        return field_error(error, error_size, "dns",
                           "object is required");
    }
    size_t size_value = 0u;
    int64_t time_value = 0;
    if (as_size(object_get(dns, "maxCacheEntries"), 256u,
                &size_value) != APROXY_OK ||
        as_size(object_get(dns, "maxPendingRequests"), 64u,
                &size_value) != APROXY_OK ||
        as_size(object_get(dns, "maxWaitersPerRequest"), 64u,
                &size_value) != APROXY_OK ||
        as_i64(object_get(dns, "cacheTtlMs"), 60000, 0, INT64_MAX,
               &time_value) != APROXY_OK ||
        as_i64(object_get(dns, "negativeCacheTtlMs"), 5000, 0,
               INT64_MAX, &time_value) != APROXY_OK) {
        return field_error(error, error_size, "dns",
                           "invalid DNS setting");
    }
    const aproxy_value_t *memory = object_get(root, "memory");
    if (memory != NULL && memory->type != APROXY_VALUE_OBJECT) {
        return field_error(error, error_size, "memory",
                           "object is required");
    }
    if (as_size(object_get(memory, "dynamicLimitBytes"),
                APROXY_DEFAULT_DYNAMIC_MEMORY_LIMIT_BYTES,
                &size_value) != APROXY_OK) {
        return field_error(error, error_size,
                           "memory.dynamicLimitBytes", "invalid value");
    }
    return APROXY_OK;
}

static int validate_routes(const aproxy_value_t *route,
                           const aproxy_value_t *outbounds,
                           char *error,
                           size_t error_size)
{
    const char *default_tag = as_string(object_get(route, "default"));
    if (route == NULL || route->type != APROXY_VALUE_OBJECT ||
        default_tag == NULL || default_tag[0] == '\0') {
        return field_error(error, error_size, "route.default",
                           "string is required");
    }
    if (strcmp(default_tag, "proxy") != 0 &&
        !outbound_tag_exists(outbounds, default_tag)) {
        return field_error(error, error_size, "route.default",
                           "unknown outbound");
    }
    const aproxy_value_t *geoip = object_get(route, "geoipPath");
    const aproxy_value_t *geosite = object_get(route, "geositePath");
    if ((geoip != NULL && as_string(geoip) == NULL) ||
        (geosite != NULL && as_string(geosite) == NULL)) {
        return field_error(error, error_size, "route",
                           "Geo database paths must be strings");
    }
    const aproxy_value_t *rules = object_get(route, "rules");
    if (rules == NULL) {
        return APROXY_OK;
    }
    if (rules->type != APROXY_VALUE_ARRAY) {
        return field_error(error, error_size, "route.rules",
                           "array is required");
    }
    if (rules->as.array.count > ENGINE_MAX_ROUTE_RULES) {
        return field_error(error, error_size, "route.rules",
                           "too many rules");
    }
    for (size_t i = 0u; i < rules->as.array.count; i++) {
        const aproxy_value_t *rule = &rules->as.array.values[i];
        const char *type = as_string(object_get(rule, "type"));
        const char *value = as_string(object_get(rule, "value"));
        const char *outbound = as_string(object_get(rule, "outbound"));
        if (rule->type != APROXY_VALUE_OBJECT || type == NULL ||
            value == NULL || value[0] == '\0' || outbound == NULL) {
            (void)snprintf(error, error_size,
                           "route.rules[%u]: type, value and outbound "
                           "are required",
                           (unsigned int)i);
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        if (strcmp(outbound, "proxy") != 0 &&
            !outbound_tag_exists(outbounds, outbound)) {
            (void)snprintf(error, error_size,
                           "route.rules[%u].outbound: unknown outbound",
                           (unsigned int)i);
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        const int known =
            strcmp(type, "domain") == 0 ||
            strcmp(type, "domainSuffix") == 0 ||
            strcmp(type, "cidr") == 0 ||
            strcmp(type, "geoip") == 0 ||
            strcmp(type, "geosite") == 0;
        if (!known ||
            (strcmp(type, "cidr") == 0 &&
             validate_cidr_text(value) != APROXY_OK) ||
            (strcmp(type, "geoip") == 0 && geoip == NULL) ||
            (strcmp(type, "geosite") == 0 && geosite == NULL)) {
            (void)snprintf(error, error_size,
                           "route.rules[%u]: invalid rule or missing "
                           "Geo database path",
                           (unsigned int)i);
            return APROXY_ERR_INVALID_ARGUMENT;
        }
    }
    return APROXY_OK;
}

static int route_profile_exists(const aproxy_value_t *profiles,
                                const char *profile_id)
{
    if (profiles == NULL || profile_id == NULL ||
        profiles->type != APROXY_VALUE_ARRAY) {
        return 0;
    }
    for (size_t i = 0u; i < profiles->as.array.count; i++) {
        const char *candidate = as_string(object_get(
            &profiles->as.array.values[i], "id"));
        if (candidate != NULL && strcmp(candidate, profile_id) == 0) {
            return 1;
        }
    }
    return 0;
}

static int validate_config(const aproxy_engine_config_v2_t *config,
                           char *error,
                           size_t error_size)
{
    if (config == NULL || config->root == NULL ||
        config->root->type != APROXY_VALUE_OBJECT ||
        config->schema_version != ENGINE_SCHEMA_VERSION ||
        config->schema_id.len != strlen(ENGINE_SCHEMA) ||
        memcmp(config->schema_id.data, ENGINE_SCHEMA,
               config->schema_id.len) != 0) {
        return field_error(error, error_size, "config",
                           "unsupported schema or root");
    }
    const aproxy_value_t *inbounds =
        object_get(config->root, "inbounds");
    if (inbounds == NULL || inbounds->type != APROXY_VALUE_ARRAY ||
        inbounds->as.array.count != 1u) {
        return field_error(error, error_size, "inbounds",
                           "exactly one inbound is required");
    }
    const aproxy_value_t *inbound = &inbounds->as.array.values[0];
    int rc = validate_inbound(inbound, error, error_size);
    if (rc != APROXY_OK) {
        return rc;
    }
    const aproxy_value_t *outbounds =
        object_get(config->root, "outbounds");
    if (outbounds == NULL || outbounds->type != APROXY_VALUE_ARRAY ||
        outbounds->as.array.count == 0u ||
        outbounds->as.array.count > ENGINE_MAX_OUTBOUNDS) {
        return field_error(error, error_size, "outbounds",
                           "array size is outside the supported range");
    }
    for (size_t i = 0u; i < outbounds->as.array.count; i++) {
        rc = validate_outbound(&outbounds->as.array.values[i],
                               error, error_size);
        if (rc != APROXY_OK) {
            return rc;
        }
        const char *tag = as_string(object_get(
            &outbounds->as.array.values[i], "tag"));
        for (size_t j = 0u; j < i; j++) {
            const char *previous = as_string(object_get(
                &outbounds->as.array.values[j], "tag"));
            if (previous != NULL && strcmp(previous, tag) == 0) {
                return field_error(error, error_size, tag,
                                   "duplicate outbound tag");
            }
        }
    }
    const aproxy_value_t *profiles =
        object_get(config->root, "routeProfiles");
    if (profiles == NULL || profiles->type != APROXY_VALUE_ARRAY ||
        profiles->as.array.count == 0u ||
        profiles->as.array.count > ENGINE_MAX_ROUTE_PROFILES) {
        return field_error(error, error_size, "routeProfiles",
                           "array size is outside the supported range");
    }
    for (size_t i = 0u; i < profiles->as.array.count; i++) {
        const aproxy_value_t *profile = &profiles->as.array.values[i];
        const aproxy_value_t *profile_id_value = object_get(profile, "id");
        const char *profile_id = as_string(profile_id_value);
        if (profile->type != APROXY_VALUE_OBJECT || profile_id == NULL ||
            profile_id[0] == '\0' || profile_id_value->as.string.len > 64u ||
            memchr(profile_id, '\0', profile_id_value->as.string.len) != NULL) {
            return field_error(error, error_size, "routeProfiles[].id",
                               "valid string is required");
        }
        for (size_t j = 0u; j < i; j++) {
            const char *previous = as_string(object_get(
                &profiles->as.array.values[j], "id"));
            if (previous != NULL && strcmp(previous, profile_id) == 0) {
                return field_error(error, error_size, profile_id,
                                   "duplicate route profile id");
            }
        }
        rc = validate_routes(profile, outbounds, error, error_size);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    const aproxy_value_t *selection =
        object_get(config->root, "selection");
    const char *node_tag = as_string(object_get(selection, "node"));
    const char *routing_id =
        as_string(object_get(selection, "routing"));
    if (selection == NULL || selection->type != APROXY_VALUE_OBJECT ||
        node_tag == NULL || !outbound_tag_exists(outbounds, node_tag) ||
        routing_id == NULL || !route_profile_exists(profiles, routing_id)) {
        return field_error(error, error_size, "selection",
                           "known node and routing ids are required");
    }
    return validate_dns_and_memory(config->root, error, error_size);
}

static char *alpn_string(const aproxy_value_t *value)
{
    if (value == NULL) {
        return NULL;
    }
    if (value->type == APROXY_VALUE_STRING) {
        const size_t len = value->as.string.len;
        char *result = (char *)malloc(len + 1u);
        if (result != NULL) {
            memcpy(result, value->as.string.data, len);
            result[len] = '\0';
        }
        return result;
    }
    if (value->type != APROXY_VALUE_ARRAY) {
        return NULL;
    }
    size_t length = 0u;
    for (size_t i = 0u; i < value->as.array.count; i++) {
        const aproxy_value_t *item = &value->as.array.values[i];
        if (item->type != APROXY_VALUE_STRING ||
            item->as.string.len > SIZE_MAX - length - 2u) {
            return NULL;
        }
        length += item->as.string.len + (i == 0u ? 0u : 1u);
    }
    char *result = (char *)malloc(length + 1u);
    if (result == NULL) {
        return NULL;
    }
    size_t offset = 0u;
    for (size_t i = 0u; i < value->as.array.count; i++) {
        const aproxy_value_t *item = &value->as.array.values[i];
        if (i != 0u) {
            result[offset++] = ',';
        }
        memcpy(result + offset, item->as.string.data, item->as.string.len);
        offset += item->as.string.len;
    }
    result[offset] = '\0';
    return result;
}

static int add_outbound(aproxy_engine_t *engine,
                        const aproxy_value_t *value,
                        char *error,
                        size_t error_size)
{
    const char *type = as_string(object_get(value, "type"));
    const char *tag = as_string(object_get(value, "tag"));
    size_t read_buffer_size = 0u;
    size_t max_pending_bytes = 0u;
    if (as_size(object_get(value, "readBufferSize"), 0u,
                &read_buffer_size) != APROXY_OK ||
        as_size(object_get(value, "maxPendingBytes"), 0u,
                &max_pending_bytes) != APROXY_OK) {
        return field_error(error, error_size, tag, "invalid buffer limit");
    }
    aproxy_socket_protector_t socket_protector;
    memset(&socket_protector, 0, sizeof(socket_protector));
    if (engine->host.submit_socket_protect != NULL ||
        engine->host.protect_socket != NULL) {
        socket_protector.context = engine;
        socket_protector.submit = submit_socket_protect;
    }
    if (strcmp(type, "direct") == 0) {
        const aproxy_direct_outbound_config_t config = {
            .tag = tag,
            .read_buffer_size = read_buffer_size,
            .max_pending_bytes = max_pending_bytes,
            .socket_protector = socket_protector,
        };
        return aproxy_node_add_direct(engine->node, &config);
    }
    if (strcmp(type, "block") == 0) {
        return aproxy_node_add_block(engine->node, tag);
    }

    int64_t port_number = 0;
    if (as_i64(object_get(value, "port"), 0, 1, 65535,
               &port_number) != APROXY_OK) {
        return field_error(error, error_size, tag, "invalid port");
    }
    char port[6];
    (void)snprintf(port, sizeof(port), "%u", (unsigned int)port_number);
    const char *server = as_string(object_get(value, "server"));
    if (strcmp(type, "shadowsocks") == 0) {
        const char *udp_transport =
            as_string(object_get(value, "udpTransport"));
        int64_t uot_version = 2;
        if (as_i64(object_get(value, "uotVersion"), 2, 1, 2,
                   &uot_version) != APROXY_OK) {
            return field_error(error, error_size, tag,
                               "invalid Shadowsocks UoT version");
        }
        const shadowsocks_outbound_config_t config = {
            .tag = tag,
            .server_host = server,
            .server_port = port,
            .method = as_string(object_get(value, "method")),
            .password = as_string(object_get(value, "password")),
            .read_buffer_size = read_buffer_size,
            .max_pending_bytes = max_pending_bytes,
            .udp_transport =
                udp_transport != NULL && strcmp(udp_transport, "uot") == 0
                    ? APROXY_OUTBOUND_UDP_UOT
                    : APROXY_OUTBOUND_UDP_PACKET,
            .uot_version = (uint8_t)uot_version,
            .socket_protector = socket_protector,
        };
        return aproxy_node_add_shadowsocks(engine->node, &config);
    }

    const char *security = as_string(object_get(value, "security"));
    security = security == NULL
                   ? (strcmp(type, "anytls") == 0 ? "tls" : "none")
                   : security;
    aproxy_reality_config_t reality;
    aproxy_ech_config_t ech;
    uint8_t *ech_storage = NULL;
    int rc = parse_reality(value, security, &reality, error, error_size);
    if (rc == APROXY_OK) {
        rc = parse_ech(value, &ech, &ech_storage, error, error_size);
    }
    int insecure = 0;
    if (rc == APROXY_OK &&
        as_bool(object_get(value, "insecure"), 0, &insecure) != APROXY_OK) {
        rc = field_error(error, error_size, tag, "invalid insecure flag");
    }
    char *alpn = NULL;
    const aproxy_value_t *alpn_value = object_get(value, "alpn");
    if (rc == APROXY_OK && alpn_value != NULL) {
        alpn = alpn_string(alpn_value);
        if (alpn == NULL) {
            rc = field_error(error, error_size, tag, "invalid alpn");
        }
    }

    if (rc == APROXY_OK && strcmp(type, "anytls") == 0) {
        int64_t heartbeat_interval = 0;
        int64_t heartbeat_timeout = 0;
        int64_t idle_check = 0;
        int64_t idle_timeout = 0;
        int64_t min_idle = 0;
        int64_t max_idle = 0;
        int64_t uot_version = 2;
        if (as_i64(object_get(value, "uotVersion"), 2, 1, 2,
                   &uot_version) != APROXY_OK ||
            as_i64(object_get(value, "heartbeatIntervalMs"), 0,
                   -1, INT64_MAX, &heartbeat_interval) != APROXY_OK ||
            as_i64(object_get(value, "heartbeatTimeoutMs"), 0,
                   0, INT64_MAX, &heartbeat_timeout) != APROXY_OK ||
            as_i64(object_get(value, "idleSessionCheckIntervalMs"), 0,
                   0, INT64_MAX, &idle_check) != APROXY_OK ||
            as_i64(object_get(value, "idleSessionTimeoutMs"), 0,
                   0, INT64_MAX, &idle_timeout) != APROXY_OK ||
            as_i64(object_get(value, "minIdleSessions"), 0,
                   0, INT_MAX, &min_idle) != APROXY_OK ||
            as_i64(object_get(value, "maxIdleSessions"), 0,
                   0, INT_MAX, &max_idle) != APROXY_OK) {
            rc = field_error(error, error_size, tag,
                             "invalid session setting");
        } else {
            anytls_outbound_config_t config;
            memset(&config, 0, sizeof(config));
            config.tag = tag;
            config.client.server_host = server;
            config.client.server_port = port;
            config.client.password =
                as_string(object_get(value, "password"));
            config.client.sni = as_string(object_get(value, "sni"));
            config.client.alpn = alpn;
            config.client.ech = ech;
            config.client.insecure_skip_verify = insecure;
            config.client.reality = reality;
            config.client.heartbeat_interval_ms = heartbeat_interval;
            config.client.heartbeat_timeout_ms = heartbeat_timeout;
            config.client.max_pending_bytes = max_pending_bytes;
            config.client.socket_protector = socket_protector;
            config.uot_version = (uint8_t)uot_version;
            config.idle_session_check_interval_ms = idle_check;
            config.idle_session_timeout_ms = idle_timeout;
            config.min_idle_sessions = (int)min_idle;
            config.max_idle_sessions = (int)max_idle;
            rc = aproxy_node_add_anytls(engine->node, &config);
        }
    } else if (rc == APROXY_OK && strcmp(type, "vless") == 0) {
        const char *sni = as_string(object_get(value, "sni"));
        vless_outbound_config_t config;
        memset(&config, 0, sizeof(config));
        config.tag = tag;
        config.server_host = server;
        config.server_port = port;
        config.uuid = as_string(object_get(value, "uuid"));
        config.flow = as_string(object_get(value, "flow"));
        config.encryption = as_string(object_get(value, "encryption"));
        config.tls_enabled = strcmp(security, "tls") == 0;
        config.sni = sni == NULL ? server : sni;
        config.alpn = alpn;
        config.ech = ech;
        config.insecure_skip_verify = insecure;
        config.reality = reality;
        config.read_buffer_size = read_buffer_size;
        config.max_pending_bytes = max_pending_bytes;
        config.socket_protector = socket_protector;
        rc = aproxy_node_add_vless(engine->node, &config);
    }
    free(alpn);
    free(ech_storage);
    if (rc != APROXY_OK && error[0] == '\0') {
        (void)snprintf(error, error_size, "%s: create failed (%d)",
                       tag, rc);
    }
    return rc;
}

static int add_cidr_route(aproxy_router_t *router,
                          aproxy_node_t *node,
                          const char *cidr,
                          const char *outbound)
{
    const char *slash = strchr(cidr, '/');
    const size_t host_len = slash == NULL ? strlen(cidr)
                                          : (size_t)(slash - cidr);
    if (host_len == 0u || host_len >= INET6_ADDRSTRLEN) {
        return APROXY_ERR_PARSE;
    }
    char host[INET6_ADDRSTRLEN];
    memcpy(host, cidr, host_len);
    host[host_len] = '\0';

    uint8_t address[16];
    int family = AF_INET;
    unsigned long prefix = 32u;
    if (inet_pton(AF_INET, host, address) != 1) {
        family = AF_INET6;
        prefix = 128u;
        if (inet_pton(AF_INET6, host, address) != 1) {
            return APROXY_ERR_PARSE;
        }
    }
    if (slash != NULL) {
        char *end = NULL;
        errno = 0;
        prefix = strtoul(slash + 1, &end, 10);
        if (errno != 0 || end == slash + 1 || *end != '\0' ||
            prefix > (family == AF_INET ? 32u : 128u)) {
            return APROXY_ERR_PARSE;
        }
    }
    const int use_proxy = strcmp(outbound, "proxy") == 0;
    aproxy_outbound_t *target = use_proxy
                                    ? NULL
                                    : aproxy_node_find_outbound(node,
                                                                outbound);
    if (!use_proxy && target == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (family == AF_INET) {
        return use_proxy
                   ? aproxy_router_add_ipv4_cidr_proxy(
                         router, address, (uint8_t)prefix)
                   : aproxy_router_add_ipv4_cidr(
                         router, address, (uint8_t)prefix, target);
    }
    return use_proxy
               ? aproxy_router_add_ipv6_cidr_proxy(
                     router, address, (uint8_t)prefix)
               : aproxy_router_add_ipv6_cidr(
                     router, address, (uint8_t)prefix, target);
}

static int setup_route_profile(aproxy_engine_t *engine,
                               aproxy_router_t *router,
                               const aproxy_value_t *route,
                               char *error,
                               size_t error_size)
{
    const char *default_tag = as_string(object_get(route, "default"));
    const int default_is_proxy = strcmp(default_tag, "proxy") == 0;
    aproxy_outbound_t *default_outbound =
        default_is_proxy
            ? NULL
            : aproxy_node_find_outbound(engine->node, default_tag);
    int rc = default_is_proxy
                 ? aproxy_router_set_default_proxy(router)
                 : aproxy_router_set_default(router, default_outbound);
    if (rc != APROXY_OK) {
        return field_error(error, error_size, "route.default",
                           "unknown outbound");
    }
    const char *geoip_path = as_string(object_get(route, "geoipPath"));
    const char *geosite_path = as_string(object_get(route, "geositePath"));
    const aproxy_value_t *rules = object_get(route, "rules");
    if (rules == NULL) {
        return APROXY_OK;
    }
    if (rules->type != APROXY_VALUE_ARRAY) {
        return field_error(error, error_size, "route.rules",
                           "array is required");
    }
    for (size_t i = 0u; i < rules->as.array.count; i++) {
        const aproxy_value_t *rule = &rules->as.array.values[i];
        const char *type = as_string(object_get(rule, "type"));
        const char *value = as_string(object_get(rule, "value"));
        const char *outbound = as_string(object_get(rule, "outbound"));
        if (rule->type != APROXY_VALUE_OBJECT || type == NULL ||
            value == NULL || outbound == NULL) {
            return field_error(error, error_size, "route.rules[]",
                               "type, value and outbound are required");
        }
        const int use_proxy = strcmp(outbound, "proxy") == 0;
        aproxy_outbound_t *target = use_proxy
                                        ? NULL
                                        : aproxy_node_find_outbound(
                                              engine->node, outbound);
        if (!use_proxy && target == NULL) {
            rc = APROXY_ERR_INVALID_ARGUMENT;
        } else if (strcmp(type, "domain") == 0) {
            rc = use_proxy
                     ? aproxy_router_add_domain_exact_proxy(router, value)
                     : aproxy_router_add_domain_exact(router, value, target);
        } else if (strcmp(type, "domainSuffix") == 0) {
            rc = use_proxy
                     ? aproxy_router_add_domain_suffix_proxy(router, value)
                     : aproxy_router_add_domain_suffix(router, value, target);
        } else if (strcmp(type, "cidr") == 0) {
            rc = add_cidr_route(router, engine->node, value, outbound);
        } else if (strcmp(type, "geoip") == 0 && geoip_path != NULL) {
            rc = aproxy_node_add_geoip_route_to(
                engine->node, router, geoip_path, value,
                use_proxy ? NULL : outbound, use_proxy);
        } else if (strcmp(type, "geosite") == 0 &&
                   geosite_path != NULL) {
            rc = aproxy_node_add_geosite_route_to(
                engine->node, router, geosite_path, value,
                use_proxy ? NULL : outbound, use_proxy);
        } else {
            rc = APROXY_ERR_INVALID_ARGUMENT;
        }
        if (rc != APROXY_OK) {
            (void)snprintf(error, error_size,
                           "route.rules[%u]: setup failed (%d)",
                           (unsigned int)i, rc);
            return rc;
        }
    }
    return APROXY_OK;
}

static int setup_routes(aproxy_engine_t *engine,
                        const aproxy_value_t *root,
                        char *error,
                        size_t error_size)
{
    aproxy_router_t *selector = aproxy_node_router(engine->node);
    const aproxy_value_t *profiles = object_get(root, "routeProfiles");
    for (size_t i = 0u; i < profiles->as.array.count; i++) {
        const aproxy_value_t *value = &profiles->as.array.values[i];
        const char *profile_id = as_string(object_get(value, "id"));
        aproxy_router_t *profile = NULL;
        int rc = aproxy_router_new(&profile);
        if (rc == APROXY_OK) {
            rc = setup_route_profile(engine, profile, value,
                                     error, error_size);
        }
        if (rc == APROXY_OK) {
            rc = aproxy_router_add_profile(selector, profile_id, profile);
        }
        if (rc != APROXY_OK) {
            aproxy_router_free(profile);
            if (error[0] == '\0') {
                (void)snprintf(error, error_size,
                               "routeProfiles[%u]: setup failed (%d)",
                               (unsigned int)i, rc);
            }
            return rc;
        }
    }
    const aproxy_value_t *selection = object_get(root, "selection");
    const char *node_tag = as_string(object_get(selection, "node"));
    const char *routing_id = as_string(object_get(selection, "routing"));
    aproxy_outbound_t *selected =
        aproxy_node_find_outbound(engine->node, node_tag);
    int rc = aproxy_router_set_selected_proxy(selector, selected);
    if (rc == APROXY_OK) {
        rc = aproxy_router_select_profile(selector, routing_id);
    }
    if (rc != APROXY_OK) {
        return field_error(error, error_size, "selection",
                           "unable to select node or routing profile");
    }
    uv_mutex_lock(&engine->mutex);
    copy_error(engine->active_node, sizeof(engine->active_node), node_tag);
    copy_error(engine->active_routing, sizeof(engine->active_routing),
               routing_id);
    uv_mutex_unlock(&engine->mutex);
    return APROXY_OK;
}

#if defined(APROXY_ENABLE_TUN)
static void release_tun_packet_stream(aproxy_stream_t *stream)
{
    if (stream == NULL) {
        return;
    }
    (void)aproxy_stream_close(stream);
    aproxy_stream_free(stream);
}

static void tun_session_cb(aproxy_inbound_t *inbound,
                           aproxy_packet_session_t *session,
                           aproxy_stream_t *stream,
                           const aproxy_packet_flow_key_t *key,
                           void *user_data)
{
    (void)inbound;
    aproxy_engine_t *engine = (aproxy_engine_t *)user_data;
    if (engine == NULL) {
        release_tun_packet_stream(stream);
        return;
    }
    int rc = APROXY_ERR_UNSUPPORTED;
    if (key != NULL && key->proto == APROXY_PACKET_PROTO_TCP &&
        engine->tcp_relay != NULL) {
        rc = aproxy_packet_tcp_relay_on_session(
            engine->tcp_relay, session, stream, key);
    } else if (engine->packet_relay != NULL) {
        rc = aproxy_packet_udp_relay_on_session(
            engine->packet_relay, session, stream, key);
    }
    if (rc != APROXY_OK) {
        release_tun_packet_stream(stream);
    }
}

static void tun_stream_data_cb(aproxy_inbound_t *inbound,
                               aproxy_packet_session_t *session,
                               aproxy_stream_t *stream,
                               const uint8_t *packet,
                               size_t packet_len,
                               void *user_data)
{
    (void)inbound;
    aproxy_engine_t *engine = (aproxy_engine_t *)user_data;
    if (engine == NULL) {
        return;
    }
    const aproxy_packet_flow_key_t *key =
        aproxy_packet_session_key(session);
    if (key != NULL && key->proto == APROXY_PACKET_PROTO_TCP &&
        engine->tcp_relay != NULL) {
        (void)aproxy_packet_tcp_relay_on_packet(
            engine->tcp_relay, session, stream, packet, packet_len);
    } else if (engine->packet_relay != NULL) {
        (void)aproxy_packet_udp_relay_on_packet(
            engine->packet_relay, session, stream, packet, packet_len);
    }
}

static void tun_packet_batch_begin_cb(aproxy_inbound_t *inbound,
                                      void *user_data)
{
    (void)inbound;
    aproxy_engine_t *engine = (aproxy_engine_t *)user_data;
    if (engine != NULL) {
        aproxy_packet_udp_relay_begin_packet_batch(engine->packet_relay);
    }
}

static void tun_packet_batch_end_cb(aproxy_inbound_t *inbound,
                                    void *user_data)
{
    (void)inbound;
    aproxy_engine_t *engine = (aproxy_engine_t *)user_data;
    if (engine != NULL && engine->packet_relay != NULL) {
        (void)aproxy_packet_udp_relay_end_packet_batch(
            engine->packet_relay);
    }
}

static void flow_timer_cb(uv_timer_t *timer)
{
    aproxy_engine_t *engine = (aproxy_engine_t *)timer->data;
    if (engine == NULL) {
        return;
    }
    aproxy_packet_udp_relay_maintenance(engine->packet_relay);
    aproxy_packet_tcp_relay_maintenance(engine->tcp_relay);
}

static int write_tun_packet_to_host(aproxy_inbound_t *inbound,
                                    const uint8_t *packet,
                                    size_t packet_len,
                                    void *user_data)
{
    (void)inbound;
    aproxy_engine_t *engine = (aproxy_engine_t *)user_data;
    if (engine == NULL || engine->host.write_tun_packets == NULL ||
        packet == NULL || packet_len == 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const aproxy_bytes_view_t view = {
        .data = packet,
        .len = packet_len,
    };
    return engine->host.write_tun_packets(
        engine->host.context, &view, 1u);
}

static void encode_tun_packet_length(uint8_t output[4], size_t length)
{
    output[0] = (uint8_t)(length >> 24u);
    output[1] = (uint8_t)(length >> 16u);
    output[2] = (uint8_t)(length >> 8u);
    output[3] = (uint8_t)length;
}

static size_t decode_tun_packet_length(const uint8_t input[4])
{
    return ((size_t)input[0] << 24u) | ((size_t)input[1] << 16u) |
           ((size_t)input[2] << 8u) | (size_t)input[3];
}

static void drain_tun_ingress(aproxy_engine_t *engine)
{
    aproxy_ring_t swap;
    uv_mutex_lock(&engine->mutex);
    swap = engine->tun_ingress_drain;
    engine->tun_ingress_drain = engine->tun_ingress;
    engine->tun_ingress = swap;
    aproxy_ring_clear(&engine->tun_ingress);
    uv_mutex_unlock(&engine->mutex);

    uint64_t dropped = 0u;
    aproxy_packet_udp_relay_begin_packet_batch(engine->packet_relay);
    while (aproxy_ring_size(&engine->tun_ingress_drain) >=
           ENGINE_TUN_PACKET_HEADER_SIZE) {
        uint8_t header[ENGINE_TUN_PACKET_HEADER_SIZE];
        if (aproxy_ring_peek(&engine->tun_ingress_drain, 0u, header,
                             sizeof(header)) != sizeof(header)) {
            dropped++;
            break;
        }
        const size_t packet_len = decode_tun_packet_length(header);
        const size_t record_len = ENGINE_TUN_PACKET_HEADER_SIZE + packet_len;
        if (packet_len == 0u || packet_len > ENGINE_TUN_MAX_PACKET_SIZE ||
            aproxy_ring_size(&engine->tun_ingress_drain) < record_len) {
            dropped++;
            break;
        }

        aproxy_const_span_t spans[2];
        const size_t span_count = aproxy_ring_read_spans_at(
            &engine->tun_ingress_drain, ENGINE_TUN_PACKET_HEADER_SIZE,
            packet_len, spans);
        const uint8_t *packet = NULL;
        if (span_count == 1u) {
            packet = spans[0].data;
        } else {
            if (engine->packet_relay != NULL) {
                (void)aproxy_packet_udp_relay_end_packet_batch(
                    engine->packet_relay);
                aproxy_packet_udp_relay_begin_packet_batch(
                    engine->packet_relay);
            }
            aproxy_buffer_clear(&engine->tun_packet_scratch);
            if (aproxy_buffer_reserve(&engine->tun_packet_scratch,
                                      packet_len) != APROXY_OK ||
                aproxy_ring_peek(
                    &engine->tun_ingress_drain,
                    ENGINE_TUN_PACKET_HEADER_SIZE,
                    engine->tun_packet_scratch.data,
                    packet_len) != packet_len) {
                dropped++;
                aproxy_ring_consume(&engine->tun_ingress_drain, record_len);
                continue;
            }
            engine->tun_packet_scratch.len = packet_len;
            packet = engine->tun_packet_scratch.data;
        }
        if (aproxy_tun_inbound_submit_packet(
                engine->inbound, packet, packet_len) != APROXY_OK) {
            dropped++;
        }
        aproxy_ring_consume(&engine->tun_ingress_drain, record_len);
    }
    if (engine->packet_relay != NULL) {
        (void)aproxy_packet_udp_relay_end_packet_batch(
            engine->packet_relay);
    }
    if (aproxy_ring_size(&engine->tun_ingress_drain) != 0u) {
        aproxy_ring_clear(&engine->tun_ingress_drain);
    }

    uv_mutex_lock(&engine->mutex);
    engine->tun_packets_dropped += dropped;
    const int pending = aproxy_ring_size(&engine->tun_ingress) != 0u;
    uv_mutex_unlock(&engine->mutex);
    if (pending) {
        (void)uv_async_send(&engine->command_async);
    }
}

static void clear_tun_ingress(aproxy_engine_t *engine)
{
    uv_mutex_lock(&engine->mutex);
    aproxy_ring_clear(&engine->tun_ingress);
    uv_mutex_unlock(&engine->mutex);
    aproxy_ring_clear(&engine->tun_ingress_drain);
    aproxy_buffer_clear(&engine->tun_packet_scratch);
}

static int setup_tun_inbound(aproxy_engine_t *engine,
                             const aproxy_value_t *inbound,
                             char *error,
                             size_t error_size)
{
    const int use_packet_io = engine->host.write_tun_packets != NULL;
    int fd = -1;
    int rc = APROXY_OK;
    if (!use_packet_io) {
        if (engine->host.get_tun_fd == NULL) {
            return field_error(
                error, error_size, "inbounds[0]",
                "platform host does not provide TUN packet I/O or a TUN fd");
        }
        rc = engine->host.get_tun_fd(engine->host.context, &fd);
        if (rc != APROXY_OK || fd < 0) {
            (void)snprintf(error, error_size,
                           "inbounds[0]: acquire TUN fd failed (%d)", rc);
            return rc == APROXY_OK ? APROXY_ERR_INVALID_ARGUMENT : rc;
        }
    }

    int64_t mtu = APROXY_TUN_DEFAULT_MTU;
    int64_t ipv4_prefix = APROXY_TUN_DEFAULT_IPV4_PREFIX;
    int64_t ipv6_prefix = APROXY_TUN_DEFAULT_IPV6_PREFIX;
    int64_t tcp_idle_timeout = 0;
    int64_t udp_idle_timeout = 0;
    int64_t sniff_timeout =
        APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_TIMEOUT_MS;
    int sniffing_enabled = 1;
    size_t udp_pending_limit = 0u;
    size_t udp_rx_limit = 0u;
    size_t sniff_max_bytes =
        APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_BYTES;
    size_t sniff_max_packets =
        APROXY_PACKET_UDP_RELAY_DEFAULT_SNIFF_PACKETS;
    if (as_i64(object_get(inbound, "mtu"), APROXY_TUN_DEFAULT_MTU,
               576, 65535, &mtu) != APROXY_OK ||
        as_i64(object_get(inbound, "ipv4Prefix"),
               APROXY_TUN_DEFAULT_IPV4_PREFIX, 0, 32,
               &ipv4_prefix) != APROXY_OK ||
        as_i64(object_get(inbound, "ipv6Prefix"),
               APROXY_TUN_DEFAULT_IPV6_PREFIX, 0, 128,
               &ipv6_prefix) != APROXY_OK ||
        as_i64(object_get(inbound, "tcpFlowIdleTimeoutMs"), 0,
               0, INT64_MAX, &tcp_idle_timeout) != APROXY_OK ||
        as_i64(object_get(inbound, "udpFlowIdleTimeoutMs"), 0,
               0, INT64_MAX, &udp_idle_timeout) != APROXY_OK ||
        as_size(object_get(inbound, "udpPendingLimit"), 0u,
                &udp_pending_limit) != APROXY_OK ||
        as_size(object_get(inbound, "udpStreamRxLimit"), 0u,
                &udp_rx_limit) != APROXY_OK ||
        as_bool(object_get(inbound, "sniffingEnabled"), 1,
                &sniffing_enabled) != APROXY_OK ||
        as_size(object_get(inbound, "sniffingMaxBytes"),
                APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_BYTES,
                &sniff_max_bytes) != APROXY_OK ||
        as_size(object_get(inbound, "sniffingMaxPackets"),
                APROXY_PACKET_UDP_RELAY_DEFAULT_SNIFF_PACKETS,
                &sniff_max_packets) != APROXY_OK ||
        as_i64(object_get(inbound, "sniffingTimeoutMs"),
               APROXY_PACKET_TCP_RELAY_DEFAULT_SNIFF_TIMEOUT_MS,
               1, 2000, &sniff_timeout) != APROXY_OK ||
        sniff_max_bytes < 1024u || sniff_max_bytes > 32767u ||
        sniff_max_packets == 0u || sniff_max_packets > 16u) {
        return field_error(error, error_size, "inbounds[0]",
                           "invalid TUN setting");
    }
    sniffing_enabled =
        sniffing_enabled && aproxy_router_has_domain_rules(
                                 aproxy_node_router(engine->node));

    const aproxy_packet_tcp_relay_config_t tcp_config = {
        .loop = (uv_loop_t *)aproxy_loop_native(engine->loop),
        .router = aproxy_node_router(engine->node),
        .idle_timeout_ms = (uint64_t)tcp_idle_timeout,
        .sniffing_enabled = sniffing_enabled,
        .sniffing_max_bytes = sniff_max_bytes,
        .sniffing_timeout_ms = (uint64_t)sniff_timeout,
    };
    rc = aproxy_packet_tcp_relay_new(&tcp_config, &engine->tcp_relay);
    if (rc != APROXY_OK) {
        (void)snprintf(error, error_size,
                       "create TUN TCP relay failed (%d)", rc);
        return rc;
    }
    const aproxy_packet_udp_relay_config_t udp_config = {
        .router = aproxy_node_router(engine->node),
        .pending_tx_limit = udp_pending_limit,
        .rx_limit = udp_rx_limit,
        .idle_timeout_ms = (uint64_t)udp_idle_timeout,
        .sniffing_enabled = sniffing_enabled,
        .sniffing_max_bytes = sniff_max_bytes,
        .sniffing_max_packets = sniff_max_packets,
    };
    rc = aproxy_packet_udp_relay_new(&udp_config, &engine->packet_relay);
    if (rc != APROXY_OK) {
        (void)snprintf(error, error_size,
                       "create TUN UDP relay failed (%d)", rc);
        return rc;
    }

    const char *tag = as_string(object_get(inbound, "tag"));
    const char *ipv4 = as_string(object_get(inbound, "ipv4"));
    const char *ipv6 = as_string(object_get(inbound, "ipv6"));
    const aproxy_tun_inbound_config_t tun_config = {
        .loop = (uv_loop_t *)aproxy_loop_native(engine->loop),
        .tag = tag == NULL ? "tun-in" : tag,
        .name = use_packet_io ? "packet-flow" : "platform-tun",
        .mtu = (uint32_t)mtu,
        .ipv4 = ipv4 == NULL ? APROXY_TUN_DEFAULT_IPV4 : ipv4,
        .ipv4_prefix = (uint8_t)ipv4_prefix,
        .ipv6 = ipv6,
        .ipv6_prefix = (uint8_t)ipv6_prefix,
        .use_fd = !use_packet_io,
        .fd = fd,
        .close_fd = 0,
        .configure_device = 0,
        .on_session = tun_session_cb,
        .on_stream_data = tun_stream_data_cb,
        .on_packet_batch_begin = tun_packet_batch_begin_cb,
        .on_packet_batch_end = tun_packet_batch_end_cb,
        .user_data = engine,
        .use_packet_io = use_packet_io,
        .on_write_packet = use_packet_io ? write_tun_packet_to_host : NULL,
    };
    rc = aproxy_tun_inbound_new(&tun_config, &engine->inbound);
    if (rc == APROXY_OK) {
        rc = aproxy_inbound_start(engine->inbound);
    }
    if (rc == APROXY_OK) {
        rc = uv_timer_start(&engine->flow_timer, flow_timer_cb,
                            1000u, 1000u);
    }
    if (rc != APROXY_OK) {
        (void)snprintf(error, error_size,
                       "start TUN inbound failed (%d)", rc);
        return rc;
    }
    engine->inbound_is_tun = 1;
    return APROXY_OK;
}
#endif

static int setup_runtime(aproxy_engine_t *engine,
                         const owned_config_t *config,
                         char *error,
                         size_t error_size)
{
    const aproxy_value_t *root = config->value.root;
    const aproxy_value_t *dns = object_get(root, "dns");
    aproxy_node_options_t options;
    aproxy_node_options_init(&options, engine->loop);
    if (dns != NULL && dns->type != APROXY_VALUE_OBJECT) {
        return field_error(error, error_size, "dns", "object is required");
    }
    size_t dns_size = 0u;
    int64_t dns_time = 0;
    if (as_size(object_get(dns, "maxCacheEntries"), 256u,
                &dns_size) != APROXY_OK) {
        return field_error(error, error_size, "dns.maxCacheEntries",
                           "invalid value");
    }
    options.dns_max_cache_entries = dns_size;
    if (as_i64(object_get(dns, "cacheTtlMs"), 60000, 0, INT64_MAX,
               &dns_time) != APROXY_OK) {
        return field_error(error, error_size, "dns.cacheTtlMs",
                           "invalid value");
    }
    options.dns_cache_ttl_ms = (uint64_t)dns_time;
    if (as_i64(object_get(dns, "negativeCacheTtlMs"), 5000, 0,
               INT64_MAX, &dns_time) != APROXY_OK) {
        return field_error(error, error_size, "dns.negativeCacheTtlMs",
                           "invalid value");
    }
    options.dns_negative_cache_ttl_ms = (uint64_t)dns_time;
    if (as_size(object_get(dns, "maxPendingRequests"), 64u,
                &dns_size) != APROXY_OK) {
        return field_error(error, error_size, "dns.maxPendingRequests",
                           "invalid value");
    }
    options.dns_max_pending_requests = dns_size;
    if (as_size(object_get(dns, "maxWaitersPerRequest"), 64u,
                &dns_size) != APROXY_OK) {
        return field_error(error, error_size,
                           "dns.maxWaitersPerRequest", "invalid value");
    }
    options.dns_max_waiters_per_request = dns_size;

    const aproxy_value_t *memory = object_get(root, "memory");
    size_t dynamic_limit = APROXY_DEFAULT_DYNAMIC_MEMORY_LIMIT_BYTES;
    if (memory != NULL && memory->type != APROXY_VALUE_OBJECT) {
        return field_error(error, error_size, "memory",
                           "object is required");
    }
    if (as_size(object_get(memory, "dynamicLimitBytes"), dynamic_limit,
                &dynamic_limit) != APROXY_OK) {
        return field_error(error, error_size, "memory.dynamicLimitBytes",
                           "invalid value");
    }
    aproxy_memory_set_dynamic_limit(dynamic_limit);

    int rc = aproxy_node_new(&options, &engine->node);
    if (rc != APROXY_OK) {
        copy_error(error, error_size, "create node failed");
        return rc;
    }
    const aproxy_value_t *outbounds = object_get(root, "outbounds");
    for (size_t i = 0u; i < outbounds->as.array.count; i++) {
        rc = add_outbound(engine, &outbounds->as.array.values[i],
                          error, error_size);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    rc = setup_routes(engine, root, error, error_size);
    aproxy_node_release_route_databases(engine->node);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = aproxy_node_connect_outbound(engine->node, engine->active_node);
    if (rc != APROXY_OK) {
        (void)snprintf(error, error_size,
                       "connect selected node failed (%d)", rc);
        return rc;
    }

    const aproxy_value_t *inbounds = object_get(root, "inbounds");
    const aproxy_value_t *inbound = &inbounds->as.array.values[0];
#if defined(APROXY_ENABLE_TUN)
    const char *inbound_type = as_string(object_get(inbound, "type"));
    if (inbound_type != NULL && strcmp(inbound_type, "tun") == 0) {
        return setup_tun_inbound(engine, inbound, error, error_size);
    }
#endif
    int allow_lan = 0;
    int64_t port = 1080;
    int64_t uot_version = 2;
    size_t stream_limit = 0u;
    size_t udp_limit = 0u;
    size_t udp_rx_limit = 0u;
    if (as_bool(object_get(inbound, "allowLan"), 0, &allow_lan) !=
            APROXY_OK ||
        as_i64(object_get(inbound, "port"), 1080, 0, 65535, &port) !=
            APROXY_OK ||
        as_i64(object_get(inbound, "uotVersion"), 2, 1, 2,
               &uot_version) != APROXY_OK ||
        as_size(object_get(inbound, "streamPendingLimit"), 0u,
                &stream_limit) != APROXY_OK ||
        as_size(object_get(inbound, "udpPendingLimit"), 0u,
                &udp_limit) != APROXY_OK ||
        as_size(object_get(inbound, "udpStreamRxLimit"), 0u,
                &udp_rx_limit) != APROXY_OK) {
        return field_error(error, error_size, "inbounds[0]",
                           "invalid SOCKS5 setting");
    }
    const char *listen = as_string(object_get(inbound, "listen"));
    if (listen == NULL) {
        listen = allow_lan ? "0.0.0.0" : "127.0.0.1";
    }
    const char *tag = as_string(object_get(inbound, "tag"));
    const aproxy_socks5_inbound_config_t inbound_config = {
        .loop = (uv_loop_t *)aproxy_loop_native(engine->loop),
        .tag = tag == NULL ? "socks5-in" : tag,
        .listen_host = listen,
        .listen_port = (uint16_t)port,
        .backlog = 128,
        .udp_uot_version = (uint8_t)uot_version,
        .stream_pending_limit = stream_limit,
        .udp_pending_tx_limit = udp_limit,
        .udp_stream_rx_limit = udp_rx_limit,
        .router = aproxy_node_router(engine->node),
        .resolver = aproxy_node_resolver(engine->node),
    };
    rc = aproxy_socks5_inbound_new(&inbound_config, &engine->inbound);
    if (rc == APROXY_OK) {
        rc = aproxy_inbound_start(engine->inbound);
    }
    if (rc == APROXY_OK) {
        uint16_t bound_port = 0u;
        rc = aproxy_socks5_inbound_get_bound_port(
            engine->inbound, &bound_port);
        if (rc == APROXY_OK) {
            uv_mutex_lock(&engine->mutex);
            engine->bound_port = bound_port;
            uv_mutex_unlock(&engine->mutex);
        }
    }
    if (rc != APROXY_OK) {
        (void)snprintf(error, error_size,
                       "start SOCKS5 inbound failed (%d)", rc);
    } else {
        engine->inbound_is_tun = 0;
    }
    return rc;
}

static void emit_event(aproxy_engine_t *engine,
                       uint32_t type,
                       uint64_t operation_id,
                       int status,
                       const char *message)
{
    if (engine->host.emit_event == NULL) {
        return;
    }
    aproxy_engine_event_v2_t event;
    memset(&event, 0, sizeof(event));
    event.abi_version = APROXY_ENGINE_ABI_VERSION;
    event.struct_size = sizeof(event);
    event.type = type;
    event.operation_id = operation_id;
    event.status = status;
    uv_mutex_lock(&engine->mutex);
    event.state = engine->state;
    uv_mutex_unlock(&engine->mutex);
    event.message.data = message == NULL ? "" : message;
    event.message.len = strlen(event.message.data);
    engine->host.emit_event(engine->host.context, &event);
}

static void set_state(aproxy_engine_t *engine,
                      uint32_t state,
                      int status,
                      const char *error)
{
    uv_mutex_lock(&engine->mutex);
    engine->state = state;
    engine->last_status = status;
    if (error != NULL) {
        copy_error(engine->last_error, sizeof(engine->last_error), error);
    } else if (status == APROXY_OK) {
        engine->last_error[0] = '\0';
    }
    uv_mutex_unlock(&engine->mutex);
    emit_event(engine, APROXY_ENGINE_EVENT_STATE, 0u, status,
               error == NULL ? "" : error);
}

static void complete_operation(aproxy_engine_t *engine,
                               uint64_t operation_id,
                               int status,
                               const char *message)
{
    emit_event(engine, APROXY_ENGINE_EVENT_OPERATION, operation_id,
               status, message);
}

static void refresh_stats(aproxy_engine_t *engine)
{
    aproxy_socks5_udp_stats_t udp;
    aproxy_memory_stats_t memory;
#if defined(APROXY_ENABLE_TUN)
    aproxy_packet_tcp_relay_stats_t packet_tcp;
    aproxy_packet_udp_relay_stats_t packet_udp;
#endif
    size_t process = 0u;
    memset(&udp, 0, sizeof(udp));
#if defined(APROXY_ENABLE_TUN)
    memset(&packet_tcp, 0, sizeof(packet_tcp));
    memset(&packet_udp, 0, sizeof(packet_udp));
#endif
    if (engine->inbound != NULL && !engine->inbound_is_tun) {
        (void)aproxy_socks5_inbound_get_udp_stats(engine->inbound, &udp);
    }
#if defined(APROXY_ENABLE_TUN)
    if (engine->tcp_relay != NULL) {
        aproxy_packet_tcp_relay_get_stats(engine->tcp_relay, &packet_tcp);
    }
    if (engine->packet_relay != NULL) {
        aproxy_packet_udp_relay_get_stats(engine->packet_relay, &packet_udp);
    }
#endif
    aproxy_memory_get_stats(&memory);
    (void)aproxy_process_memory_bytes(&process);
    uv_mutex_lock(&engine->mutex);
    engine->udp_stats = udp;
#if defined(APROXY_ENABLE_TUN)
    engine->packet_tcp_stats = packet_tcp;
    engine->packet_udp_stats = packet_udp;
#endif
    engine->memory_stats = memory;
    engine->process_memory_bytes = process;
    uv_mutex_unlock(&engine->mutex);
}

static void stats_timer_cb(uv_timer_t *timer)
{
    aproxy_engine_t *engine = (aproxy_engine_t *)timer->data;
    refresh_stats(engine);
}

static int release_runtime_once(aproxy_engine_t *engine)
{
#if defined(APROXY_ENABLE_TUN)
    uv_timer_stop(&engine->flow_timer);
    clear_tun_ingress(engine);
#endif
    if (engine->inbound != NULL) {
        aproxy_inbound_stop(engine->inbound);
        aproxy_inbound_free(engine->inbound);
        engine->inbound = NULL;
    }
#if defined(APROXY_ENABLE_TUN)
    if (engine->tcp_relay != NULL) {
        aproxy_packet_tcp_relay_free(engine->tcp_relay);
        engine->tcp_relay = NULL;
    }
    if (engine->packet_relay != NULL) {
        aproxy_packet_udp_relay_free(engine->packet_relay);
        engine->packet_relay = NULL;
    }
#endif
    engine->inbound_is_tun = 0;
    uv_mutex_lock(&engine->mutex);
    engine->bound_port = 0u;
    engine->started_at_ms = 0u;
    uv_mutex_unlock(&engine->mutex);
    if (engine->node == NULL) {
        return APROXY_OK;
    }
    aproxy_node_close(engine->node);
    const int rc = aproxy_node_free(engine->node);
    if (rc == APROXY_OK) {
        engine->node = NULL;
        uv_mutex_lock(&engine->mutex);
        engine->active_node[0] = '\0';
        engine->active_routing[0] = '\0';
        uv_mutex_unlock(&engine->mutex);
    }
    return rc;
}

static void close_control_handles(aproxy_engine_t *engine)
{
    uv_timer_stop(&engine->cleanup_timer);
    uv_timer_stop(&engine->stats_timer);
#if defined(APROXY_ENABLE_TUN)
    uv_timer_stop(&engine->flow_timer);
    if (!uv_is_closing((uv_handle_t *)&engine->flow_timer)) {
        uv_close((uv_handle_t *)&engine->flow_timer, NULL);
    }
#endif
    if (!uv_is_closing((uv_handle_t *)&engine->cleanup_timer)) {
        uv_close((uv_handle_t *)&engine->cleanup_timer, NULL);
    }
    if (!uv_is_closing((uv_handle_t *)&engine->stats_timer)) {
        uv_close((uv_handle_t *)&engine->stats_timer, NULL);
    }
    if (!uv_is_closing((uv_handle_t *)&engine->command_async)) {
        uv_close((uv_handle_t *)&engine->command_async, NULL);
    }
}

static void finish_cleanup(aproxy_engine_t *engine)
{
    const cleanup_action_t action = engine->cleanup_action;
    const uint64_t operation_id = engine->cleanup_operation_id;
    const int cleanup_status = engine->cleanup_status;
    char cleanup_error[ENGINE_ERROR_SIZE];
    copy_error(cleanup_error, sizeof(cleanup_error),
               engine->cleanup_error);
    engine->cleanup_action = CLEANUP_NONE;
    engine->cleanup_operation_id = 0u;

    if (action == CLEANUP_STOP) {
        set_state(engine, APROXY_ENGINE_STOPPED, APROXY_OK, NULL);
        complete_operation(engine, operation_id, APROXY_OK, "stopped");
        return;
    }
    if (action == CLEANUP_ERROR) {
        set_state(engine, APROXY_ENGINE_ERROR, cleanup_status,
                  cleanup_error);
        complete_operation(engine, operation_id, cleanup_status,
                           cleanup_error);
        return;
    }
    if (action == CLEANUP_RELOAD) {
        char error[ENGINE_ERROR_SIZE] = "";
        const int rc = setup_runtime(engine, engine->reload_config,
                                     error, sizeof(error));
        if (rc == APROXY_OK) {
            uv_mutex_lock(&engine->mutex);
            engine->config_revision =
                engine->reload_config->value.revision;
            engine->started_at_ms = uv_hrtime() / 1000000u;
            uv_mutex_unlock(&engine->mutex);
            owned_config_free(engine->reload_config);
            engine->reload_config = NULL;
            set_state(engine, APROXY_ENGINE_RUNNING, APROXY_OK, NULL);
            complete_operation(engine, operation_id, APROXY_OK,
                               "reloaded");
        } else {
            owned_config_free(engine->reload_config);
            engine->reload_config = NULL;
            engine->cleanup_action = CLEANUP_ERROR;
            engine->cleanup_operation_id = operation_id;
            engine->cleanup_status = rc;
            copy_error(engine->cleanup_error,
                       sizeof(engine->cleanup_error), error);
            aproxy_node_close(engine->node);
            cleanup_timer_cb(&engine->cleanup_timer);
        }
        return;
    }
    if (action == CLEANUP_SHUTDOWN) {
        owned_config_free(engine->reload_config);
        engine->reload_config = NULL;
        close_control_handles(engine);
    }
}

static void cleanup_timer_cb(uv_timer_t *timer)
{
    aproxy_engine_t *engine = (aproxy_engine_t *)timer->data;
    const int rc = release_runtime_once(engine);
    if (rc == APROXY_ERR_BUSY) {
        (void)uv_timer_start(&engine->cleanup_timer, cleanup_timer_cb,
                             5u, 0u);
        return;
    }
    uv_timer_stop(&engine->cleanup_timer);
    if (rc != APROXY_OK &&
        engine->cleanup_action != CLEANUP_SHUTDOWN) {
        engine->cleanup_action = CLEANUP_ERROR;
        engine->cleanup_status = rc;
        (void)snprintf(engine->cleanup_error,
                       sizeof(engine->cleanup_error),
                       "runtime cleanup failed (%d)", rc);
    }
    finish_cleanup(engine);
}

static void begin_cleanup(aproxy_engine_t *engine,
                          cleanup_action_t action,
                          uint64_t operation_id,
                          int status,
                          const char *error)
{
    engine->cleanup_action = action;
    engine->cleanup_operation_id = operation_id;
    engine->cleanup_status = status;
    copy_error(engine->cleanup_error, sizeof(engine->cleanup_error),
               error);
    cleanup_timer_cb(&engine->cleanup_timer);
}

static void run_validate(aproxy_engine_t *engine,
                         engine_command_t *command)
{
    char error[ENGINE_ERROR_SIZE] = "";
    const int rc = validate_config(&command->config->value,
                                   error, sizeof(error));
    complete_operation(engine, command->operation_id, rc,
                       rc == APROXY_OK ? "valid" : error);
}

static void run_start(aproxy_engine_t *engine,
                      engine_command_t *command)
{
    char error[ENGINE_ERROR_SIZE] = "";
    int rc = validate_config(&command->config->value,
                             error, sizeof(error));
    if (rc == APROXY_OK) {
        set_state(engine, APROXY_ENGINE_STARTING, APROXY_OK, NULL);
        rc = setup_runtime(engine, command->config, error, sizeof(error));
    }
    if (rc == APROXY_OK) {
        uv_mutex_lock(&engine->mutex);
        engine->config_revision = command->config->value.revision;
        engine->started_at_ms = uv_hrtime() / 1000000u;
        uv_mutex_unlock(&engine->mutex);
        set_state(engine, APROXY_ENGINE_RUNNING, APROXY_OK, NULL);
        complete_operation(engine, command->operation_id, APROXY_OK,
                           "started");
    } else {
        begin_cleanup(engine, CLEANUP_ERROR, command->operation_id,
                      rc, error);
    }
}

static void run_reload(aproxy_engine_t *engine,
                       engine_command_t *command)
{
    char error[ENGINE_ERROR_SIZE] = "";
    int rc = validate_config(&command->config->value,
                             error, sizeof(error));
    if (rc == APROXY_OK) {
        uv_mutex_lock(&engine->mutex);
        const uint64_t current_revision = engine->config_revision;
        uv_mutex_unlock(&engine->mutex);
        if (command->config->value.revision <= current_revision) {
            rc = field_error(error, sizeof(error), "config.revision",
                             "must increase on reload");
        }
    }
    if (rc != APROXY_OK) {
        complete_operation(engine, command->operation_id, rc, error);
        return;
    }
    engine->reload_config = command->config;
    command->config = NULL;
    set_state(engine, APROXY_ENGINE_RELOADING, APROXY_OK, NULL);
    begin_cleanup(engine, CLEANUP_RELOAD, command->operation_id,
                  APROXY_OK, NULL);
}

static void run_select_node(aproxy_engine_t *engine,
                            engine_command_t *command)
{
    aproxy_outbound_t *outbound = engine->node == NULL
                                      ? NULL
                                      : aproxy_node_find_outbound(
                                            engine->node,
                                            command->selection_id);
    int rc = outbound == NULL
                 ? APROXY_ERR_INVALID_ARGUMENT
                 : aproxy_node_connect_outbound(engine->node,
                                                command->selection_id);
    if (rc == APROXY_OK) {
        rc = aproxy_router_set_selected_proxy(
            aproxy_node_router(engine->node), outbound);
    }
    char message[ENGINE_ERROR_SIZE];
    if (rc == APROXY_OK) {
        uv_mutex_lock(&engine->mutex);
        copy_error(engine->active_node, sizeof(engine->active_node),
                   command->selection_id);
        uv_mutex_unlock(&engine->mutex);
        (void)snprintf(message, sizeof(message),
                       "selected node: %s", command->selection_id);
    } else {
        copy_error(message, sizeof(message),
                   "node tag does not exist or cannot connect");
    }
    complete_operation(engine, command->operation_id, rc, message);
}

static void run_select_routing(aproxy_engine_t *engine,
                               engine_command_t *command)
{
    const int rc = engine->node == NULL
                       ? APROXY_ERR_INVALID_ARGUMENT
                       : aproxy_router_select_profile(
                             aproxy_node_router(engine->node),
                             command->selection_id);
    char message[ENGINE_ERROR_SIZE];
    if (rc == APROXY_OK) {
        uv_mutex_lock(&engine->mutex);
        copy_error(engine->active_routing, sizeof(engine->active_routing),
                   command->selection_id);
        uv_mutex_unlock(&engine->mutex);
        (void)snprintf(message, sizeof(message),
                       "selected routing: %s", command->selection_id);
    } else {
        copy_error(message, sizeof(message),
                   "routing profile does not exist");
    }
    complete_operation(engine, command->operation_id, rc, message);
}

static void run_stop(aproxy_engine_t *engine,
                     engine_command_t *command)
{
    if (engine->node == NULL && engine->inbound == NULL) {
        set_state(engine, APROXY_ENGINE_STOPPED, APROXY_OK, NULL);
        complete_operation(engine, command->operation_id, APROXY_OK,
                           "stopped");
        return;
    }
    set_state(engine, APROXY_ENGINE_STOPPING, APROXY_OK, NULL);
    begin_cleanup(engine, CLEANUP_STOP, command->operation_id,
                  APROXY_OK, NULL);
}

static void command_cb(uv_async_t *handle)
{
    aproxy_engine_t *engine = (aproxy_engine_t *)handle->data;
    dispatch_socket_protect_results(engine);
#if defined(APROXY_ENABLE_TUN)
    drain_tun_ingress(engine);
#endif
    engine_command_t command;
    memset(&command, 0, sizeof(command));
    uv_mutex_lock(&engine->mutex);
    command = engine->pending;
    memset(&engine->pending, 0, sizeof(engine->pending));
    uv_mutex_unlock(&engine->mutex);
    if (command.kind == COMMAND_NONE) {
        return;
    }
    if (command.kind == COMMAND_SHUTDOWN) {
        command_payload_free(&command);
        if (engine->cleanup_action != CLEANUP_NONE) {
            engine->cleanup_action = CLEANUP_SHUTDOWN;
            engine->cleanup_operation_id = 0u;
            owned_config_free(engine->reload_config);
            engine->reload_config = NULL;
        } else {
            begin_cleanup(engine, CLEANUP_SHUTDOWN, 0u,
                          APROXY_OK, NULL);
        }
        return;
    }
    if (engine->cleanup_action != CLEANUP_NONE) {
        complete_operation(engine, command.operation_id,
                           APROXY_ERR_BUSY, "engine is busy");
        command_payload_free(&command);
        return;
    }
    switch (command.kind) {
    case COMMAND_VALIDATE:
        run_validate(engine, &command);
        break;
    case COMMAND_START:
        run_start(engine, &command);
        break;
    case COMMAND_RELOAD:
        run_reload(engine, &command);
        break;
    case COMMAND_SELECT_NODE:
        run_select_node(engine, &command);
        break;
    case COMMAND_SELECT_ROUTING:
        run_select_routing(engine, &command);
        break;
    case COMMAND_STOP:
        run_stop(engine, &command);
        break;
    default:
        break;
    }
    command_payload_free(&command);
    refresh_stats(engine);
}

static int engine_complete_socket_protect(aproxy_engine_t *engine,
                                          uint64_t request_id,
                                          int status)
{
    if (engine == NULL || request_id == 0u ||
        !engine->handles_initialized) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uv_mutex_lock(&engine->mutex);
    engine_socket_protect_request_t *request =
        remove_protect_request_locked(engine, request_id);
    if (request == NULL) {
        uv_mutex_unlock(&engine->mutex);
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    request->status = status;
    if (engine->protect_completed_tail == NULL) {
        engine->protect_completed_head = request;
    } else {
        engine->protect_completed_tail->next = request;
    }
    engine->protect_completed_tail = request;
    uv_mutex_unlock(&engine->mutex);
    return uv_async_send(&engine->command_async);
}

static void engine_worker(void *context)
{
    aproxy_engine_t *engine = (aproxy_engine_t *)context;
    int rc = uv_loop_init(&engine->native_loop);
    if (rc == 0) {
        engine->native_loop_initialized = 1;
        rc = aproxy_loop_wrap(&engine->native_loop, &engine->loop);
    }
    int command_initialized = 0;
    int cleanup_initialized = 0;
    int stats_initialized = 0;
#if defined(APROXY_ENABLE_TUN)
    int flow_initialized = 0;
#endif
    if (rc == APROXY_OK) {
        rc = uv_async_init(&engine->native_loop, &engine->command_async,
                           command_cb);
        command_initialized = rc == 0;
    }
    if (rc == 0) {
        rc = uv_timer_init(&engine->native_loop, &engine->cleanup_timer);
        cleanup_initialized = rc == 0;
    }
    if (rc == 0) {
        rc = uv_timer_init(&engine->native_loop, &engine->stats_timer);
        stats_initialized = rc == 0;
    }
#if defined(APROXY_ENABLE_TUN)
    if (rc == 0) {
        rc = uv_timer_init(&engine->native_loop, &engine->flow_timer);
        flow_initialized = rc == 0;
    }
#endif
    if (rc == 0) {
        engine->command_async.data = engine;
        engine->cleanup_timer.data = engine;
        engine->stats_timer.data = engine;
#if defined(APROXY_ENABLE_TUN)
        engine->flow_timer.data = engine;
#endif
        engine->handles_initialized = 1;
        rc = uv_timer_start(&engine->stats_timer, stats_timer_cb,
                            0u, 1000u);
    }
    engine->ready_status = rc;
    uv_sem_post(&engine->ready);
    if (rc == 0) {
        (void)uv_run(&engine->native_loop, UV_RUN_DEFAULT);
    } else if (engine->native_loop_initialized) {
#if defined(APROXY_ENABLE_TUN)
        if (flow_initialized) {
            uv_close((uv_handle_t *)&engine->flow_timer, NULL);
        }
#endif
        if (stats_initialized) {
            uv_close((uv_handle_t *)&engine->stats_timer, NULL);
        }
        if (cleanup_initialized) {
            uv_close((uv_handle_t *)&engine->cleanup_timer, NULL);
        }
        if (command_initialized) {
            uv_close((uv_handle_t *)&engine->command_async, NULL);
        }
        (void)uv_run(&engine->native_loop, UV_RUN_DEFAULT);
    }
    if (engine->loop != NULL) {
        (void)aproxy_loop_free(engine->loop);
        engine->loop = NULL;
    }
    if (engine->native_loop_initialized) {
        (void)uv_loop_close(&engine->native_loop);
        engine->native_loop_initialized = 0;
    }
}

static void value_string(aproxy_value_t *value, const char *text)
{
    memset(value, 0, sizeof(*value));
    value->struct_size = sizeof(*value);
    value->type = APROXY_VALUE_STRING;
    value->as.string.data = text;
    value->as.string.len = strlen(text);
}

static void value_u64(aproxy_value_t *value, uint64_t number)
{
    memset(value, 0, sizeof(*value));
    value->struct_size = sizeof(*value);
    value->type = APROXY_VALUE_U64;
    value->as.u64 = number;
}

static void value_array(aproxy_value_t *value,
                        aproxy_value_t *items,
                        size_t count)
{
    memset(value, 0, sizeof(*value));
    value->struct_size = sizeof(*value);
    value->type = APROXY_VALUE_ARRAY;
    value->as.array.values = items;
    value->as.array.count = count;
}

static void value_object(aproxy_value_t *value,
                         aproxy_object_entry_t *entries,
                         size_t count)
{
    memset(value, 0, sizeof(*value));
    value->struct_size = sizeof(*value);
    value->type = APROXY_VALUE_OBJECT;
    value->as.object.entries = entries;
    value->as.object.count = count;
}

static void object_entry(aproxy_object_entry_t *entry,
                         const char *key,
                         const aproxy_value_t *value)
{
    entry->key.data = key;
    entry->key.len = strlen(key);
    entry->value = value;
}

static void string_array(aproxy_value_t *array,
                         aproxy_value_t *items,
                         const char *const *strings,
                         size_t count)
{
    for (size_t i = 0u; i < count; i++) {
        value_string(&items[i], strings[i]);
    }
    value_array(array, items, count);
}

static int engine_create(const aproxy_engine_host_v2_t *host,
                         aproxy_engine_t **out_engine)
{
    if (out_engine == NULL || host == NULL ||
        host->abi_version != APROXY_ENGINE_ABI_VERSION ||
        host->struct_size < sizeof(*host)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out_engine = NULL;
    aproxy_engine_t *engine =
        (aproxy_engine_t *)calloc(1u, sizeof(*engine));
    if (engine == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    engine->host = *host;
    engine->state = APROXY_ENGINE_IDLE;
#if defined(APROXY_ENABLE_TUN)
    aproxy_ring_init(&engine->tun_ingress);
    aproxy_ring_init(&engine->tun_ingress_drain);
    aproxy_buffer_init(&engine->tun_packet_scratch);
#endif
    int rc = uv_mutex_init(&engine->mutex);
    if (rc != 0) {
        free(engine);
        return rc;
    }
    rc = uv_sem_init(&engine->ready, 0u);
    if (rc != 0) {
        uv_mutex_destroy(&engine->mutex);
        free(engine);
        return rc;
    }
    rc = uv_thread_create(&engine->thread, engine_worker, engine);
    if (rc == 0) {
        engine->thread_started = 1;
        uv_sem_wait(&engine->ready);
        rc = engine->ready_status;
    }
    if (rc != 0) {
        if (engine->thread_started) {
            uv_thread_join(&engine->thread);
        }
        uv_sem_destroy(&engine->ready);
        uv_mutex_destroy(&engine->mutex);
        free(engine);
        return rc;
    }
    *out_engine = engine;
    return APROXY_OK;
}

static int engine_get_capabilities(aproxy_engine_t *engine,
                                   aproxy_engine_value_sink_cb sink,
                                   void *sink_context)
{
    if (engine == NULL || sink == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
#if defined(APROXY_ENABLE_TUN)
    const char *const inbounds[] = {"socks5", "tun"};
#else
    const char *const inbounds[] = {"socks5"};
#endif
    const char *const outbounds[] = {
        "direct", "block", "anytls", "shadowsocks", "vless"};
    const char *const routing[] = {
        "domain", "domainSuffix", "cidr", "geoip", "geosite"};
    const char *const security[] = {"none", "tls", "reality"};
    const char *const features[] = {
        "socks5TcpConnect",
        "socks5UdpAssociate",
        "uotV1",
        "uotV2",
        "reality",
        "ech",
        "geoipMmap",
        "geositeMmap",
        "asyncSocketProtect",
        "runtimeNodeSelection",
        "runtimeRoutingSelection",
        "precompiledRouteProfiles",
#if defined(APROXY_ENABLE_TUN)
        "tunPacketFlow",
        "tunTcpRelay",
        "tunUdpRelay",
        "tunRouteOnlySniff",
#endif
    };
    aproxy_value_t inbound_items[
        sizeof(inbounds) / sizeof(inbounds[0])];
    aproxy_value_t outbound_items[5];
    aproxy_value_t routing_items[5];
    aproxy_value_t security_items[3];
    aproxy_value_t feature_items[
        sizeof(features) / sizeof(features[0])];
    aproxy_value_t values[12];
    string_array(&values[4], inbound_items, inbounds,
                 sizeof(inbounds) / sizeof(inbounds[0]));
    string_array(&values[5], outbound_items, outbounds, 5u);
    string_array(&values[6], routing_items, routing, 5u);
    string_array(&values[7], security_items, security, 3u);
    string_array(&values[9], feature_items, features,
                 sizeof(features) / sizeof(features[0]));
    value_string(&values[0], ENGINE_ID);
    value_string(&values[1], APROXY_LIBRARY_VERSION);
    value_string(&values[2], ENGINE_SCHEMA);
    value_u64(&values[3], ENGINE_SCHEMA_VERSION);
    value_string(&values[8], "profile-restart");
    value_u64(&values[10], APROXY_ENGINE_ABI_VERSION);
    value_string(&values[11], "c-abi-struct");
    const char *const keys[] = {
        "engineId", "engineVersion", "configSchema", "schemaVersion",
        "inbounds", "outbounds", "routingRules", "security",
        "reloadMode", "features", "engineAbiVersion", "valueEncoding"};
    aproxy_object_entry_t entries[12];
    for (size_t i = 0u; i < 12u; i++) {
        object_entry(&entries[i], keys[i], &values[i]);
    }
    aproxy_value_t root;
    value_object(&root, entries, 12u);
    return sink(sink_context, &root);
}

static int queue_command(aproxy_engine_t *engine,
                         command_kind_t kind,
                         uint64_t operation_id,
                         owned_config_t *config,
                         char *selection_id)
{
    if (engine == NULL || !engine->handles_initialized ||
        (kind != COMMAND_SHUTDOWN && operation_id == 0u)) {
        owned_config_free(config);
        free(selection_id);
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int rc = APROXY_OK;
    uv_mutex_lock(&engine->mutex);
    const uint32_t state = engine->state;
    if (engine->pending.kind != COMMAND_NONE) {
        rc = APROXY_ERR_BUSY;
    } else if (kind == COMMAND_START &&
               state != APROXY_ENGINE_IDLE &&
               state != APROXY_ENGINE_STOPPED &&
               state != APROXY_ENGINE_ERROR) {
        rc = APROXY_ERR_BUSY;
    } else if (kind == COMMAND_RELOAD &&
               state != APROXY_ENGINE_RUNNING) {
        rc = APROXY_ERR_BUSY;
    } else if ((kind == COMMAND_SELECT_NODE ||
                kind == COMMAND_SELECT_ROUTING) &&
               state != APROXY_ENGINE_RUNNING) {
        rc = APROXY_ERR_BUSY;
    } else {
        engine->pending.kind = kind;
        engine->pending.operation_id = operation_id;
        engine->pending.config = config;
        engine->pending.selection_id = selection_id;
        config = NULL;
        selection_id = NULL;
    }
    uv_mutex_unlock(&engine->mutex);
    owned_config_free(config);
    free(selection_id);
    if (rc == APROXY_OK) {
        const int uv_rc = uv_async_send(&engine->command_async);
        if (uv_rc != 0) {
            rc = uv_rc;
        }
    }
    return rc;
}

static int queue_config_command(aproxy_engine_t *engine,
                                command_kind_t kind,
                                uint64_t operation_id,
                                const aproxy_engine_config_v2_t *config)
{
    owned_config_t *copy = NULL;
    const int rc = owned_config_new(config, &copy);
    return rc == APROXY_OK
               ? queue_command(engine, kind, operation_id, copy, NULL)
               : rc;
}

static int engine_validate(aproxy_engine_t *engine,
                           uint64_t operation_id,
                           const aproxy_engine_config_v2_t *config)
{
    return queue_config_command(engine, COMMAND_VALIDATE,
                                operation_id, config);
}

static int engine_start(aproxy_engine_t *engine,
                        uint64_t operation_id,
                        const aproxy_engine_config_v2_t *config)
{
    return queue_config_command(engine, COMMAND_START,
                                operation_id, config);
}

static int engine_reload(aproxy_engine_t *engine,
                         uint64_t operation_id,
                         const aproxy_engine_config_v2_t *config)
{
    return queue_config_command(engine, COMMAND_RELOAD,
                                operation_id, config);
}

static int engine_stop(aproxy_engine_t *engine, uint64_t operation_id)
{
    return queue_command(engine, COMMAND_STOP, operation_id, NULL, NULL);
}

static int engine_queue_selection(aproxy_engine_t *engine,
                                  command_kind_t kind,
                                  uint64_t operation_id,
                                  aproxy_string_view_t selection)
{
    if (selection.data == NULL || selection.len == 0u ||
        selection.len > ENGINE_MAX_OUTBOUND_TAG_BYTES ||
        memchr(selection.data, '\0', selection.len) != NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    char *copy = (char *)malloc(selection.len + 1u);
    if (copy == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    memcpy(copy, selection.data, selection.len);
    copy[selection.len] = '\0';
    return queue_command(engine, kind, operation_id, NULL, copy);
}

static int engine_select_node(aproxy_engine_t *engine,
                              uint64_t operation_id,
                              aproxy_string_view_t node_tag)
{
    return engine_queue_selection(engine, COMMAND_SELECT_NODE,
                                  operation_id, node_tag);
}

static int engine_select_routing(aproxy_engine_t *engine,
                                 uint64_t operation_id,
                                 aproxy_string_view_t routing_id)
{
    return engine_queue_selection(engine, COMMAND_SELECT_ROUTING,
                                  operation_id, routing_id);
}

static int engine_submit_tun_packets(aproxy_engine_t *engine,
                                     const aproxy_bytes_view_t *packets,
                                     size_t packet_count)
{
#if !defined(APROXY_ENABLE_TUN)
    (void)engine;
    (void)packets;
    (void)packet_count;
    return APROXY_ERR_UNSUPPORTED;
#else
    if (engine == NULL || packets == NULL || packet_count == 0u ||
        packet_count > ENGINE_TUN_MAX_BATCH || !engine->handles_initialized) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    size_t encoded_size = 0u;
    uint64_t payload_size = 0u;
    for (size_t i = 0u; i < packet_count; i++) {
        if (packets[i].data == NULL || packets[i].len == 0u ||
            packets[i].len > ENGINE_TUN_MAX_PACKET_SIZE) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        const size_t record_size =
            ENGINE_TUN_PACKET_HEADER_SIZE + packets[i].len;
        if (record_size > ENGINE_TUN_INGRESS_LIMIT - encoded_size) {
            return APROXY_ERR_BUFFER_TOO_SMALL;
        }
        encoded_size += record_size;
        payload_size += packets[i].len;
    }

    int rc = APROXY_OK;
    uv_mutex_lock(&engine->mutex);
    const size_t queued = aproxy_ring_size(&engine->tun_ingress);
    if (engine->state != APROXY_ENGINE_RUNNING ||
        !engine->inbound_is_tun || engine->host.write_tun_packets == NULL) {
        rc = APROXY_ERR_BUSY;
    } else if (queued > ENGINE_TUN_INGRESS_LIMIT - encoded_size) {
        rc = APROXY_ERR_BUFFER_TOO_SMALL;
        engine->tun_packets_dropped += packet_count;
    } else {
        rc = aproxy_ring_reserve(&engine->tun_ingress,
                                 queued + encoded_size);
        const size_t original_size = engine->tun_ingress.len;
        for (size_t i = 0u; rc == APROXY_OK && i < packet_count; i++) {
            uint8_t header[ENGINE_TUN_PACKET_HEADER_SIZE];
            encode_tun_packet_length(header, packets[i].len);
            rc = aproxy_ring_write(&engine->tun_ingress,
                                   header, sizeof(header));
            if (rc == APROXY_OK) {
                rc = aproxy_ring_write(&engine->tun_ingress,
                                       packets[i].data, packets[i].len);
            }
        }
        if (rc == APROXY_OK) {
            engine->tun_packets_submitted += packet_count;
            engine->tun_bytes_submitted += payload_size;
        } else {
            engine->tun_ingress.len = original_size;
            engine->tun_packets_dropped += packet_count;
        }
    }
    uv_mutex_unlock(&engine->mutex);
    if (rc != APROXY_OK) {
        return rc;
    }
    return uv_async_send(&engine->command_async);
#endif
}

static int engine_get_status(aproxy_engine_t *engine,
                             aproxy_engine_status_sink_cb sink,
                             void *sink_context)
{
    if (engine == NULL || sink == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    char error[ENGINE_ERROR_SIZE];
    char active_node[ENGINE_MAX_OUTBOUND_TAG_BYTES + 1u];
    char active_routing[65u];
    aproxy_engine_status_v2_t status;
    memset(&status, 0, sizeof(status));
    status.abi_version = APROXY_ENGINE_ABI_VERSION;
    status.struct_size = sizeof(status);
    uv_mutex_lock(&engine->mutex);
    status.state = engine->state;
    status.last_status = engine->last_status;
    status.config_revision = engine->config_revision;
    copy_error(error, sizeof(error), engine->last_error);
    copy_error(active_node, sizeof(active_node), engine->active_node);
    copy_error(active_routing, sizeof(active_routing),
               engine->active_routing);
    uv_mutex_unlock(&engine->mutex);
    status.engine_id.data = ENGINE_ID;
    status.engine_id.len = strlen(ENGINE_ID);
    status.engine_version.data = APROXY_LIBRARY_VERSION;
    status.engine_version.len = strlen(APROXY_LIBRARY_VERSION);
    status.last_error.data = error;
    status.last_error.len = strlen(error);
    status.active_node.data = active_node;
    status.active_node.len = strlen(active_node);
    status.active_routing.data = active_routing;
    status.active_routing.len = strlen(active_routing);
    return sink(sink_context, &status);
}

static int engine_get_stats(aproxy_engine_t *engine,
                            aproxy_engine_value_sink_cb sink,
                            void *sink_context)
{
    if (engine == NULL || sink == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_socks5_udp_stats_t udp;
    aproxy_memory_stats_t memory;
    size_t process_memory = 0u;
    uint16_t bound_port = 0u;
    uint64_t started_at = 0u;
    uint64_t tun_packets_submitted = 0u;
    uint64_t tun_bytes_submitted = 0u;
    uint64_t tun_packets_dropped = 0u;
    size_t tun_ingress_queued = 0u;
    uint64_t tun_udp_native_packets_out = 0u;
    uint64_t tun_udp_native_payload_bytes_out = 0u;
    uint64_t tun_udp_native_send_batches = 0u;
    uint64_t tun_udp_native_send_batch_packets = 0u;
    uint64_t tun_sniff_attempts = 0u;
    uint64_t tun_sniff_matches = 0u;
    uint64_t tun_sniff_http_matches = 0u;
    uint64_t tun_sniff_tls_matches = 0u;
    uint64_t tun_sniff_quic_matches = 0u;
    uint64_t tun_sniff_fallbacks = 0u;
    uint64_t tun_sniff_timeouts = 0u;
    uv_mutex_lock(&engine->mutex);
    udp = engine->udp_stats;
    memory = engine->memory_stats;
    process_memory = engine->process_memory_bytes;
    bound_port = engine->bound_port;
    started_at = engine->started_at_ms;
#if defined(APROXY_ENABLE_TUN)
    tun_packets_submitted = engine->tun_packets_submitted;
    tun_bytes_submitted = engine->tun_bytes_submitted;
    tun_packets_dropped = engine->tun_packets_dropped;
    tun_ingress_queued = aproxy_ring_size(&engine->tun_ingress);
    tun_udp_native_packets_out = engine->packet_udp_stats.native_packets_out;
    tun_udp_native_payload_bytes_out =
        engine->packet_udp_stats.native_payload_bytes_out;
    tun_udp_native_send_batches =
        engine->packet_udp_stats.native_send_batches;
    tun_udp_native_send_batch_packets =
        engine->packet_udp_stats.native_send_batch_packets;
    tun_sniff_attempts = engine->packet_tcp_stats.sniff_attempts +
                         engine->packet_udp_stats.sniff_attempts;
    tun_sniff_matches = engine->packet_tcp_stats.sniff_matches +
                        engine->packet_udp_stats.sniff_matches;
    tun_sniff_http_matches = engine->packet_tcp_stats.sniff_http_matches;
    tun_sniff_tls_matches = engine->packet_tcp_stats.sniff_tls_matches;
    tun_sniff_quic_matches = engine->packet_udp_stats.sniff_quic_matches;
    tun_sniff_fallbacks = engine->packet_tcp_stats.sniff_fallbacks +
                          engine->packet_udp_stats.sniff_fallbacks;
    tun_sniff_timeouts = engine->packet_tcp_stats.sniff_timeouts;
#endif
    uv_mutex_unlock(&engine->mutex);
    const uint64_t now = uv_hrtime() / 1000000u;
    const uint64_t uptime =
        started_at != 0u && now >= started_at ? now - started_at : 0u;
    const uint64_t numbers[] = {
        bound_port,
        uptime,
        process_memory,
        memory.dynamic_current_bytes,
        memory.dynamic_peak_bytes,
        memory.dynamic_limit_bytes,
        memory.rejected_reservations,
        udp.packets_received,
        udp.packets_relayed,
        udp.packets_sent,
        udp.bytes_received,
        udp.bytes_sent,
        udp.dropped_partial,
        udp.dropped_fragments,
        udp.dropped_invalid,
        udp.dropped_foreign_client,
        udp.dropped_pending_limit,
        udp.rx_limit_closes,
        udp.send_errors,
        udp.send_in_flight,
        udp.send_in_flight_peak,
        tun_packets_submitted,
        tun_bytes_submitted,
        tun_packets_dropped,
        tun_ingress_queued,
        tun_udp_native_packets_out,
        tun_udp_native_payload_bytes_out,
        tun_udp_native_send_batches,
        tun_udp_native_send_batch_packets,
        tun_sniff_attempts,
        tun_sniff_matches,
        tun_sniff_http_matches,
        tun_sniff_tls_matches,
        tun_sniff_quic_matches,
        tun_sniff_fallbacks,
        tun_sniff_timeouts,
    };
    const char *const keys[] = {
        "boundPort",
        "uptimeMs",
        "processMemoryBytes",
        "dynamicMemoryBytes",
        "dynamicMemoryPeakBytes",
        "dynamicMemoryLimitBytes",
        "rejectedMemoryReservations",
        "udpPacketsReceived",
        "udpPacketsRelayed",
        "udpPacketsSent",
        "udpBytesReceived",
        "udpBytesSent",
        "udpDroppedPartial",
        "udpDroppedFragments",
        "udpDroppedInvalid",
        "udpDroppedForeignClient",
        "udpDroppedPendingLimit",
        "udpRxLimitCloses",
        "udpSendErrors",
        "udpSendInFlight",
        "udpSendInFlightPeak",
        "tunPacketsSubmitted",
        "tunBytesSubmitted",
        "tunPacketsDropped",
        "tunIngressQueuedBytes",
        "tunUdpNativePacketsOut",
        "tunUdpNativePayloadBytesOut",
        "tunUdpNativeSendBatches",
        "tunUdpNativeSendBatchPackets",
        "tunSniffAttempts",
        "tunSniffMatches",
        "tunSniffHttpMatches",
        "tunSniffTlsMatches",
        "tunSniffQuicMatches",
        "tunSniffFallbacks",
        "tunSniffTimeouts",
    };
    _Static_assert(sizeof(numbers) / sizeof(numbers[0]) ==
                       sizeof(keys) / sizeof(keys[0]),
                   "engine stats key/value count mismatch");
    aproxy_value_t values[sizeof(numbers) / sizeof(numbers[0])];
    aproxy_object_entry_t entries[sizeof(numbers) / sizeof(numbers[0])];
    for (size_t i = 0u; i < sizeof(numbers) / sizeof(numbers[0]); i++) {
        value_u64(&values[i], numbers[i]);
        object_entry(&entries[i], keys[i], &values[i]);
    }
    aproxy_value_t root;
    value_object(&root, entries, sizeof(entries) / sizeof(entries[0]));
    return sink(sink_context, &root);
}

static void engine_destroy(aproxy_engine_t *engine)
{
    if (engine == NULL) {
        return;
    }
    uv_mutex_lock(&engine->mutex);
    command_payload_free(&engine->pending);
    memset(&engine->pending, 0, sizeof(engine->pending));
    engine->pending.kind = COMMAND_SHUTDOWN;
    uv_mutex_unlock(&engine->mutex);
    if (engine->handles_initialized) {
        (void)uv_async_send(&engine->command_async);
    }
    if (engine->thread_started) {
        uv_thread_join(&engine->thread);
    }
    engine_socket_protect_request_t *request = engine->protect_pending;
    while (request != NULL) {
        engine_socket_protect_request_t *next = request->next;
        free(request);
        request = next;
    }
    request = engine->protect_completed_head;
    while (request != NULL) {
        engine_socket_protect_request_t *next = request->next;
        free(request);
        request = next;
    }
    uv_sem_destroy(&engine->ready);
    uv_mutex_destroy(&engine->mutex);
#if defined(APROXY_ENABLE_TUN)
    aproxy_ring_free(&engine->tun_ingress);
    aproxy_ring_free(&engine->tun_ingress_drain);
    aproxy_buffer_free(&engine->tun_packet_scratch);
#endif
    free(engine);
}

static const aproxy_engine_api_v2_t ENGINE_API = {
    .abi_version = APROXY_ENGINE_ABI_VERSION,
    .struct_size = sizeof(aproxy_engine_api_v2_t),
    .create = engine_create,
    .get_capabilities = engine_get_capabilities,
    .validate_config = engine_validate,
    .start = engine_start,
    .reload = engine_reload,
    .stop = engine_stop,
    .get_status = engine_get_status,
    .get_stats = engine_get_stats,
    .destroy = engine_destroy,
    .complete_socket_protect = engine_complete_socket_protect,
    .select_node = engine_select_node,
    .select_routing = engine_select_routing,
    .submit_tun_packets = engine_submit_tun_packets,
};

int aproxy_engine_get_api(uint32_t requested_abi_version,
                          const aproxy_engine_api_v2_t **out_api)
{
    if (out_api == NULL ||
        requested_abi_version != APROXY_ENGINE_ABI_VERSION) {
        return APROXY_ERR_UNSUPPORTED;
    }
    *out_api = &ENGINE_API;
    return APROXY_OK;
}
