#ifndef APROXY_XHTTP_H
#define APROXY_XHTTP_H

#include <stddef.h>
#include <stdint.h>

#include <uv.h>

#include "aproxy/error.h"
#include "aproxy/dns.h"
#include "aproxy/reality.h"
#include "aproxy/socket_protect.h"
#include "aproxy/stream.h"
#include "aproxy/tls.h"

typedef enum aproxy_xhttp_mode {
    APROXY_XHTTP_MODE_AUTO = 0,
    APROXY_XHTTP_MODE_PACKET_UP,
    APROXY_XHTTP_MODE_STREAM_UP,
    APROXY_XHTTP_MODE_STREAM_ONE,
} aproxy_xhttp_mode_t;

typedef enum aproxy_xhttp_http_version {
    APROXY_XHTTP_HTTP_AUTO = 0,
    APROXY_XHTTP_HTTP_1_1,
    APROXY_XHTTP_HTTP_2,
    APROXY_XHTTP_HTTP_3,
} aproxy_xhttp_http_version_t;

typedef enum aproxy_xhttp_placement {
    APROXY_XHTTP_PLACEMENT_AUTO = 0,
    APROXY_XHTTP_PLACEMENT_PATH,
    APROXY_XHTTP_PLACEMENT_QUERY,
    APROXY_XHTTP_PLACEMENT_HEADER,
    APROXY_XHTTP_PLACEMENT_COOKIE,
    APROXY_XHTTP_PLACEMENT_BODY,
    APROXY_XHTTP_PLACEMENT_QUERY_IN_HEADER,
} aproxy_xhttp_placement_t;

typedef enum aproxy_xhttp_padding_method {
    APROXY_XHTTP_PADDING_REPEAT_X = 0,
    APROXY_XHTTP_PADDING_TOKENISH,
} aproxy_xhttp_padding_method_t;

typedef struct aproxy_xhttp_range {
    int32_t from;
    int32_t to;
} aproxy_xhttp_range_t;

typedef struct aproxy_xhttp_header {
    const char *name;
    const char *value;
} aproxy_xhttp_header_t;

typedef struct aproxy_xmux_config {
    aproxy_xhttp_range_t max_concurrency;
    aproxy_xhttp_range_t max_connections;
    aproxy_xhttp_range_t c_max_reuse_times;
    aproxy_xhttp_range_t h_max_request_times;
    aproxy_xhttp_range_t h_max_reusable_secs;
    int64_t h_keep_alive_period;
} aproxy_xmux_config_t;

typedef struct aproxy_xhttp_config {
    uv_loop_t *loop;
    const char *server_host;
    const char *server_port;
    const char *host;
    const char *path;
    const char *sni;
    /* Borrowed; it must outlive this client. */
    aproxy_dns_resolver_t *resolver;
    int tls_enabled;
    int insecure_skip_verify;
    aproxy_reality_config_t reality;
    aproxy_ech_config_t ech;
    aproxy_xhttp_mode_t mode;
    aproxy_xhttp_http_version_t http_version;

    const aproxy_xhttp_header_t *headers;
    size_t header_count;
    aproxy_xhttp_range_t x_padding_bytes;
    int x_padding_obfs_mode;
    const char *x_padding_key;
    const char *x_padding_header;
    aproxy_xhttp_placement_t x_padding_placement;
    aproxy_xhttp_padding_method_t x_padding_method;

    const char *uplink_http_method;
    aproxy_xhttp_placement_t session_id_placement;
    const char *session_id_key;
    const char *session_id_table;
    aproxy_xhttp_range_t session_id_length;
    aproxy_xhttp_placement_t seq_placement;
    const char *seq_key;
    aproxy_xhttp_placement_t uplink_data_placement;
    const char *uplink_data_key;
    aproxy_xhttp_range_t uplink_chunk_size;
    int no_grpc_header;
    int no_sse_header;

    aproxy_xhttp_range_t max_each_post_bytes;
    aproxy_xhttp_range_t min_posts_interval_ms;
    int32_t max_buffered_posts;
    int64_t max_buffered_bytes;
    aproxy_xmux_config_t xmux;
    aproxy_socket_protector_t socket_protector;
} aproxy_xhttp_config_t;

typedef struct aproxy_xhttp_client aproxy_xhttp_client_t;

int aproxy_xhttp_range_parse(const char *text, aproxy_xhttp_range_t *out);
int aproxy_xhttp_config_normalize(aproxy_xhttp_config_t *config);

int aproxy_xhttp_client_new(const aproxy_xhttp_config_t *config,
                            aproxy_xhttp_client_t **out);

int aproxy_xhttp_client_open_stream(aproxy_xhttp_client_t *client,
                                    aproxy_stream_data_cb on_data,
                                    aproxy_stream_event_cb on_open,
                                    aproxy_stream_event_cb on_close,
                                    void *user_data,
                                    aproxy_stream_t **out);

void aproxy_xhttp_client_close(aproxy_xhttp_client_t *client);
void aproxy_xhttp_client_free(aproxy_xhttp_client_t *client);

#endif
