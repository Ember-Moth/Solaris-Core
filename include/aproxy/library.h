#ifndef APROXY_LIBRARY_H
#define APROXY_LIBRARY_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"

typedef struct aproxy_dns_resolver aproxy_dns_resolver_t;
typedef struct aproxy_outbound aproxy_outbound_t;
typedef struct aproxy_router aproxy_router_t;
typedef struct aproxy_direct_outbound_config aproxy_direct_outbound_config_t;
typedef struct anytls_outbound_config anytls_outbound_config_t;
typedef struct shadowsocks_outbound_config shadowsocks_outbound_config_t;
typedef struct vless_outbound_config vless_outbound_config_t;

#if defined(_WIN32) && defined(APROXY_BUILDING_LIBRARY)
#define APROXY_API __declspec(dllexport)
#elif defined(_WIN32)
#define APROXY_API __declspec(dllimport)
#else
#define APROXY_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define APROXY_LIBRARY_ABI_VERSION 1u
#define APROXY_LIBRARY_VERSION "0.1.0"

typedef struct aproxy_loop aproxy_loop_t;
typedef struct aproxy_node aproxy_node_t;
typedef struct aproxy_client_stream aproxy_client_stream_t;
typedef struct aproxy_client_packet_flow aproxy_client_packet_flow_t;

typedef enum aproxy_loop_run_mode {
    APROXY_LOOP_RUN_DEFAULT = 0,
    APROXY_LOOP_RUN_ONCE = 1,
    APROXY_LOOP_RUN_NOWAIT = 2
} aproxy_loop_run_mode_t;

/* All node and data-plane operations are confined to the loop's owner thread. */
APROXY_API uint32_t aproxy_library_abi_version(void);
APROXY_API const char *aproxy_library_version(void);
APROXY_API const char *aproxy_error_string(int status);

/* Creates and owns a uv_loop_t. */
APROXY_API int aproxy_loop_new(aproxy_loop_t **out);

/* Wraps a caller-owned uv_loop_t passed as an opaque pointer. */
APROXY_API int aproxy_loop_wrap(void *native_uv_loop, aproxy_loop_t **out);

/* Returns the wrapped uv_loop_t as an opaque pointer. */
APROXY_API void *aproxy_loop_native(aproxy_loop_t *loop);

APROXY_API int aproxy_loop_run(aproxy_loop_t *loop,
                               aproxy_loop_run_mode_t mode);
APROXY_API void aproxy_loop_stop(aproxy_loop_t *loop);
APROXY_API int aproxy_loop_alive(const aproxy_loop_t *loop);

/* fd may be -1 for backends which cannot expose a pollable descriptor. */
APROXY_API int aproxy_loop_backend_fd(const aproxy_loop_t *loop, int *fd);

/* timeout_ms follows uv_backend_timeout(): -1 means no timer is pending. */
APROXY_API int aproxy_loop_backend_timeout(const aproxy_loop_t *loop,
                                           int *timeout_ms);

/* Returns APROXY_ERR_BUSY while nodes or native handles still use the loop. */
APROXY_API int aproxy_loop_free(aproxy_loop_t *loop);

typedef struct aproxy_node_options {
    uint32_t abi_version;
    uint32_t struct_size;
    aproxy_loop_t *loop;
    /* Optional callback-based resolver. The node creates libuv DNS if NULL. */
    aproxy_dns_resolver_t *resolver;
    int take_resolver_ownership;
    uint32_t reserved0;
    uint64_t dns_max_cache_entries;
    uint64_t dns_cache_ttl_ms;
    uint64_t dns_negative_cache_ttl_ms;
    uint64_t dns_max_pending_requests;
    uint64_t dns_max_waiters_per_request;
    uint64_t reserved[4];
} aproxy_node_options_t;

APROXY_API void aproxy_node_options_init(aproxy_node_options_t *options,
                                         aproxy_loop_t *loop);
APROXY_API int aproxy_node_new(const aproxy_node_options_t *options,
                               aproxy_node_t **out);

APROXY_API aproxy_dns_resolver_t *aproxy_node_resolver(aproxy_node_t *node);
APROXY_API aproxy_router_t *aproxy_node_router(aproxy_node_t *node);
APROXY_API aproxy_outbound_t *aproxy_node_find_outbound(
    aproxy_node_t *node,
    const char *tag);

/* Ownership transfers only when this function succeeds. */
APROXY_API int aproxy_node_add_outbound(aproxy_node_t *node,
                                        aproxy_outbound_t *outbound,
                                        int take_ownership);

/* Typed helpers override loop/resolver with the node's shared instances. */
APROXY_API int aproxy_node_add_direct(
    aproxy_node_t *node,
    const aproxy_direct_outbound_config_t *config);
APROXY_API int aproxy_node_add_block(aproxy_node_t *node, const char *tag);
APROXY_API int aproxy_node_add_anytls(
    aproxy_node_t *node,
    const anytls_outbound_config_t *config);
APROXY_API int aproxy_node_add_shadowsocks(
    aproxy_node_t *node,
    const shadowsocks_outbound_config_t *config);
APROXY_API int aproxy_node_add_vless(
    aproxy_node_t *node,
    const vless_outbound_config_t *config);

typedef void (*aproxy_node_outbound_status_cb)(aproxy_node_t *node,
                                                const char *tag,
                                                int status,
                                                void *user_data);

APROXY_API int aproxy_node_connect_outbound(aproxy_node_t *node,
                                            const char *tag);
APROXY_API int aproxy_node_connect_all(
    aproxy_node_t *node,
    aproxy_node_outbound_status_cb callback,
    void *user_data);

APROXY_API int aproxy_node_set_default_outbound(aproxy_node_t *node,
                                                const char *outbound_tag);
APROXY_API int aproxy_node_add_domain_exact_route(aproxy_node_t *node,
                                                  const char *domain,
                                                  const char *outbound_tag);
APROXY_API int aproxy_node_add_domain_suffix_route(aproxy_node_t *node,
                                                   const char *suffix,
                                                   const char *outbound_tag);
APROXY_API int aproxy_node_add_ipv4_cidr_route(aproxy_node_t *node,
                                               const uint8_t network[4],
                                               uint8_t prefix_len,
                                               const char *outbound_tag);
APROXY_API int aproxy_node_add_ipv6_cidr_route(aproxy_node_t *node,
                                               const uint8_t network[16],
                                               uint8_t prefix_len,
                                               const char *outbound_tag);
APROXY_API int aproxy_node_add_geoip_route(aproxy_node_t *node,
                                           const char *dat_path,
                                           const char *country_code,
                                           const char *outbound_tag);
APROXY_API int aproxy_node_add_geoip_route_to(
    aproxy_node_t *node,
    aproxy_router_t *router,
    const char *dat_path,
    const char *country_code,
    const char *outbound_tag,
    int use_selected_proxy);
APROXY_API int aproxy_node_add_geosite_route(aproxy_node_t *node,
                                             const char *dat_path,
                                             const char *selector,
                                             const char *outbound_tag);
APROXY_API int aproxy_node_add_geosite_route_to(
    aproxy_node_t *node,
    aproxy_router_t *router,
    const char *dat_path,
    const char *selector,
    const char *outbound_tag,
    int use_selected_proxy);

/* Releases mapped Geo indexes and unused route capacity. Compiled routes
 * remain valid; later route additions grow/reopen storage as needed. */
APROXY_API void aproxy_node_release_route_databases(aproxy_node_t *node);

typedef struct aproxy_stream_callbacks {
    uint32_t abi_version;
    uint32_t struct_size;
    void (*on_open)(aproxy_client_stream_t *stream,
                    int status,
                    void *user_data);
    /* data is a zero-copy borrowed view valid only during this callback. */
    void (*on_data)(aproxy_client_stream_t *stream,
                    const uint8_t *data,
                    size_t len,
                    void *user_data);
    void (*on_close)(aproxy_client_stream_t *stream,
                     int status,
                     void *user_data);
} aproxy_stream_callbacks_t;

APROXY_API void aproxy_stream_callbacks_init(
    aproxy_stream_callbacks_t *callbacks);

/* Completion callbacks may run synchronously before this function returns. */
APROXY_API int aproxy_node_open_stream(
    aproxy_node_t *node,
    const aproxy_addr_t *destination,
    const aproxy_stream_callbacks_t *callbacks,
    void *user_data,
    aproxy_client_stream_t **out);
APROXY_API int aproxy_node_open_stream_host(
    aproxy_node_t *node,
    const char *host,
    uint16_t port,
    const aproxy_stream_callbacks_t *callbacks,
    void *user_data,
    aproxy_client_stream_t **out);

APROXY_API int aproxy_client_stream_write(aproxy_client_stream_t *stream,
                                          const uint8_t *data,
                                          size_t len);
APROXY_API int aproxy_client_stream_close(aproxy_client_stream_t *stream);
APROXY_API const char *aproxy_client_stream_outbound_tag(
    const aproxy_client_stream_t *stream);

/* Safe in any stream callback; destruction is deferred until it returns. */
APROXY_API void aproxy_client_stream_free(aproxy_client_stream_t *stream);

typedef struct aproxy_packet_flow_callbacks {
    uint32_t abi_version;
    uint32_t struct_size;
    void (*on_open)(aproxy_client_packet_flow_t *flow,
                    int status,
                    void *user_data);
    /* source and data are borrowed only for the duration of the callback. */
    void (*on_packet)(aproxy_client_packet_flow_t *flow,
                      const aproxy_addr_t *source,
                      const uint8_t *data,
                      size_t len,
                      void *user_data);
    void (*on_close)(aproxy_client_packet_flow_t *flow,
                     int status,
                     void *user_data);
} aproxy_packet_flow_callbacks_t;

APROXY_API void aproxy_packet_flow_callbacks_init(
    aproxy_packet_flow_callbacks_t *callbacks);
APROXY_API int aproxy_node_open_packet_flow(
    aproxy_node_t *node,
    const aproxy_addr_t *initial_destination,
    const aproxy_packet_flow_callbacks_t *callbacks,
    void *user_data,
    aproxy_client_packet_flow_t **out);
APROXY_API int aproxy_node_open_packet_flow_host(
    aproxy_node_t *node,
    const char *initial_host,
    uint16_t initial_port,
    const aproxy_packet_flow_callbacks_t *callbacks,
    void *user_data,
    aproxy_client_packet_flow_t **out);
APROXY_API int aproxy_client_packet_flow_send(
    aproxy_client_packet_flow_t *flow,
    const aproxy_addr_t *destination,
    const uint8_t *data,
    size_t len);
APROXY_API int aproxy_client_packet_flow_send_host(
    aproxy_client_packet_flow_t *flow,
    const char *host,
    uint16_t port,
    const uint8_t *data,
    size_t len);
APROXY_API int aproxy_client_packet_flow_close(
    aproxy_client_packet_flow_t *flow);
APROXY_API const char *aproxy_client_packet_flow_outbound_tag(
    const aproxy_client_packet_flow_t *flow);
APROXY_API void aproxy_client_packet_flow_free(
    aproxy_client_packet_flow_t *flow);

/* Starts closing all managed flows and registered outbounds. */
APROXY_API void aproxy_node_close(aproxy_node_t *node);

/*
 * Returns APROXY_ERR_BUSY until managed flows are freed. For the last node on
 * an owned loop, native DNS/transport close requests must also be drained.
 */
APROXY_API int aproxy_node_free(aproxy_node_t *node);

#ifdef __cplusplus
}
#endif

#endif
