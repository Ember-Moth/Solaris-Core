#ifndef APROXY_ENGINE_H
#define APROXY_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define APROXY_ENGINE_ABI_VERSION 2u

#if defined(_WIN32)
#define APROXY_ENGINE_EXPORT __declspec(dllexport)
#else
#define APROXY_ENGINE_EXPORT __attribute__((visibility("default")))
#endif

typedef struct aproxy_engine aproxy_engine_t;

typedef struct aproxy_string_view {
    const char *data;
    size_t len;
} aproxy_string_view_t;

typedef struct aproxy_bytes_view {
    const uint8_t *data;
    size_t len;
} aproxy_bytes_view_t;

typedef struct aproxy_value aproxy_value_t;

typedef struct aproxy_array_view {
    const aproxy_value_t *values;
    size_t count;
} aproxy_array_view_t;

typedef struct aproxy_object_entry {
    aproxy_string_view_t key;
    const aproxy_value_t *value;
} aproxy_object_entry_t;

typedef struct aproxy_object_view {
    const aproxy_object_entry_t *entries;
    size_t count;
} aproxy_object_view_t;

typedef enum aproxy_value_type {
    APROXY_VALUE_NULL = 0,
    APROXY_VALUE_BOOL = 1,
    APROXY_VALUE_I64 = 2,
    APROXY_VALUE_U64 = 3,
    APROXY_VALUE_F64 = 4,
    APROXY_VALUE_STRING = 5,
    APROXY_VALUE_BYTES = 6,
    APROXY_VALUE_ARRAY = 7,
    APROXY_VALUE_OBJECT = 8
} aproxy_value_type_t;

struct aproxy_value {
    uint32_t struct_size;
    uint32_t type;
    union {
        int boolean;
        int64_t i64;
        uint64_t u64;
        double f64;
        aproxy_string_view_t string;
        aproxy_bytes_view_t bytes;
        aproxy_array_view_t array;
        aproxy_object_view_t object;
    } as;
};

typedef struct aproxy_engine_config_v2 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t schema_version;
    uint32_t reserved0;
    uint64_t revision;
    aproxy_string_view_t schema_id;
    const aproxy_value_t *root;
    uint64_t reserved[4];
} aproxy_engine_config_v2_t;

typedef enum aproxy_engine_state {
    APROXY_ENGINE_IDLE = 0,
    APROXY_ENGINE_STARTING = 1,
    APROXY_ENGINE_RUNNING = 2,
    APROXY_ENGINE_RELOADING = 3,
    APROXY_ENGINE_STOPPING = 4,
    APROXY_ENGINE_STOPPED = 5,
    APROXY_ENGINE_ERROR = 6
} aproxy_engine_state_t;

typedef enum aproxy_engine_event_type {
    APROXY_ENGINE_EVENT_STATE = 1,
    APROXY_ENGINE_EVENT_OPERATION = 2,
    APROXY_ENGINE_EVENT_WARNING = 3,
    APROXY_ENGINE_EVENT_LOG = 4
} aproxy_engine_event_type_t;

typedef struct aproxy_engine_event_v2 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t type;
    uint32_t state;
    uint64_t operation_id;
    int32_t status;
    uint32_t reserved0;
    aproxy_string_view_t message;
    const aproxy_value_t *details;
    uint64_t reserved[4];
} aproxy_engine_event_v2_t;

typedef struct aproxy_engine_status_v2 {
    uint32_t abi_version;
    uint32_t struct_size;
    uint32_t state;
    int32_t last_status;
    uint64_t config_revision;
    aproxy_string_view_t engine_id;
    aproxy_string_view_t engine_version;
    aproxy_string_view_t last_error;
    aproxy_string_view_t active_node;
    aproxy_string_view_t active_routing;
    uint64_t reserved[2];
} aproxy_engine_status_v2_t;

/* Every borrowed pointer is valid only for the duration of its callback. */
typedef void (*aproxy_engine_event_cb)(
    void *context,
    const aproxy_engine_event_v2_t *event);
typedef int (*aproxy_engine_value_sink_cb)(
    void *context,
    const aproxy_value_t *value);
typedef int (*aproxy_engine_status_sink_cb)(
    void *context,
    const aproxy_engine_status_v2_t *status);

typedef int (*aproxy_engine_protect_socket_cb)(void *context,
                                               intptr_t socket_handle);
/*
 * Accepts a borrowed native socket handle for asynchronous protection.
 * Returning zero transfers one completion obligation to the host. The host
 * later calls api.complete_socket_protect() exactly once with the same
 * request id. On Unix this value is a file descriptor; on Windows it is the
 * pointer-width SOCKET value.
 */
typedef int (*aproxy_engine_submit_socket_protect_cb)(
    void *context,
    uint64_t request_id,
    intptr_t socket_handle);
/*
 * Returns a borrowed TUN descriptor owned by the platform host. The host must
 * keep it open until the engine has completed stop/reload/destroy.
 */
typedef int (*aproxy_engine_get_tun_fd_cb)(void *context, int *out_fd);
/*
 * Accepts borrowed packets produced by the engine owner thread. The host must
 * copy or fully consume every packet before this callback returns.
 */
typedef int (*aproxy_engine_write_tun_packets_cb)(
    void *context,
    const aproxy_bytes_view_t *packets,
    size_t packet_count);

typedef struct aproxy_engine_host_v2 {
    uint32_t abi_version;
    uint32_t struct_size;
    void *context;
    aproxy_engine_event_cb emit_event;
    /* Optional synchronous pre-connect socket policy/binding bridge. */
    aproxy_engine_protect_socket_cb protect_socket;
    /* Optional platform TUN descriptor bridge. */
    aproxy_engine_get_tun_fd_cb get_tun_fd;
    /* Non-blocking Android VpnService.protect() bridge. */
    aproxy_engine_submit_socket_protect_cb submit_socket_protect;
    /* Optional packet I/O bridge for platforms without a public TUN fd. */
    aproxy_engine_write_tun_packets_cb write_tun_packets;
    uint64_t reserved[3];
} aproxy_engine_host_v2_t;

/*
 * Lifecycle calls are thread-safe and non-blocking unless noted otherwise.
 * The engine owns its event loop and worker threads. destroy() blocks until
 * all callbacks have returned and all engine-owned threads have stopped.
 */
typedef struct aproxy_engine_api_v2 {
    uint32_t abi_version;
    uint32_t struct_size;

    int (*create)(const aproxy_engine_host_v2_t *host,
                  aproxy_engine_t **out_engine);
    int (*get_capabilities)(aproxy_engine_t *engine,
                            aproxy_engine_value_sink_cb sink,
                            void *sink_context);
    int (*validate_config)(aproxy_engine_t *engine,
                           uint64_t operation_id,
                           const aproxy_engine_config_v2_t *config);
    int (*start)(aproxy_engine_t *engine,
                 uint64_t operation_id,
                 const aproxy_engine_config_v2_t *config);
    int (*reload)(aproxy_engine_t *engine,
                  uint64_t operation_id,
                  const aproxy_engine_config_v2_t *config);
    int (*stop)(aproxy_engine_t *engine, uint64_t operation_id);
    int (*get_status)(aproxy_engine_t *engine,
                      aproxy_engine_status_sink_cb sink,
                      void *sink_context);
    int (*get_stats)(aproxy_engine_t *engine,
                     aproxy_engine_value_sink_cb sink,
                     void *sink_context);
    void (*destroy)(aproxy_engine_t *engine);

    /* Thread-safe, non-blocking host completion for socket protection. */
    int (*complete_socket_protect)(aproxy_engine_t *engine,
                                   uint64_t request_id,
                                   int status);

    /* Selects the logical proxy used by subsequently routed flows. */
    int (*select_node)(aproxy_engine_t *engine,
                       uint64_t operation_id,
                       aproxy_string_view_t node_tag);

    /* Selects a precompiled route profile for subsequently routed flows. */
    int (*select_routing)(aproxy_engine_t *engine,
                          uint64_t operation_id,
                          aproxy_string_view_t routing_id);

    /*
     * Thread-safe packet ingress. Packet bytes are copied before return and
     * later consumed on the engine's owner thread. A batch is all-or-nothing.
     */
    int (*submit_tun_packets)(aproxy_engine_t *engine,
                              const aproxy_bytes_view_t *packets,
                              size_t packet_count);

    uint64_t reserved[4];
} aproxy_engine_api_v2_t;

typedef int (*aproxy_engine_get_api_fn)(
    uint32_t requested_abi_version,
    const aproxy_engine_api_v2_t **out_api);

/* The only symbol required by the stable host shell. */
APROXY_ENGINE_EXPORT int aproxy_engine_get_api(
    uint32_t requested_abi_version,
    const aproxy_engine_api_v2_t **out_api);

#ifdef __cplusplus
}
#endif

#endif
