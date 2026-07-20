#include "aproxy/library.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "anytls/outbound.h"
#include "aproxy/block_outbound.h"
#include "aproxy/direct_outbound.h"
#include "aproxy/dns.h"
#include "aproxy/geoip.h"
#include "aproxy/geosite.h"
#include "aproxy/outbound.h"
#include "aproxy/packet_flow.h"
#include "aproxy/router.h"
#include "aproxy/stream.h"
#include "platform.h"
#include "shadowsocks/outbound.h"
#include "vless/outbound.h"

typedef struct node_outbound {
    aproxy_outbound_t *outbound;
    int owned;
} node_outbound_t;

typedef struct node_geoip {
    aproxy_geoip_set_t *set;
    struct node_geoip *next;
    char path[];
} node_geoip_t;

typedef struct node_geoip_db {
    char *path;
    aproxy_geoip_db_t *db;
    struct node_geoip_db *next;
} node_geoip_db_t;

typedef struct node_geosite {
    aproxy_geosite_set_t *set;
    struct node_geosite *next;
    char path[];
} node_geosite_t;

typedef struct node_geosite_db {
    char *path;
    aproxy_geosite_db_t *db;
    struct node_geosite_db *next;
} node_geosite_db_t;

struct aproxy_loop {
    uv_loop_t owned_loop;
    uv_loop_t *native;
    size_t node_refs;
    int owns_native;
};

struct aproxy_node {
    aproxy_loop_t *loop;
    aproxy_dns_resolver_t *resolver;
    aproxy_router_t *router;
    node_outbound_t *outbounds;
    size_t outbound_count;
    size_t outbound_capacity;
    node_geoip_t *geoip_sets;
    node_geoip_db_t *geoip_dbs;
    node_geosite_t *geosite_sets;
    node_geosite_db_t *geosite_dbs;
    aproxy_client_stream_t *streams;
    aproxy_client_packet_flow_t *packet_flows;
    unsigned int callback_depth;
    int owns_resolver;
    int closing;
};

struct aproxy_client_stream {
    aproxy_node_t *node;
    aproxy_stream_t *native;
    aproxy_outbound_t *outbound;
    aproxy_addr_t destination;
    aproxy_stream_callbacks_t callbacks;
    void *user_data;
    struct aproxy_client_stream *prev;
    struct aproxy_client_stream *next;
    unsigned int callback_depth;
    unsigned int lifecycle_depth;
    int dns_pending;
    int open_reported;
    int close_reported;
    int closing;
    int closed;
    int released;
};

struct aproxy_client_packet_flow {
    aproxy_node_t *node;
    aproxy_packet_flow_t *native;
    aproxy_outbound_t *outbound;
    aproxy_addr_t initial_destination;
    aproxy_packet_flow_callbacks_t callbacks;
    void *user_data;
    struct aproxy_client_packet_flow *prev;
    struct aproxy_client_packet_flow *next;
    unsigned int callback_depth;
    unsigned int lifecycle_depth;
    int dns_pending;
    int open_reported;
    int close_reported;
    int closing;
    int closed;
    int released;
};

static char *copy_string(const char *value)
{
    if (value == NULL) {
        return NULL;
    }
    const size_t len = strlen(value);
    char *copy = (char *)malloc(len + 1u);
    if (copy != NULL) {
        memcpy(copy, value, len + 1u);
    }
    return copy;
}

static int ascii_string_equal_fold(const char *left, const char *right)
{
    if (left == NULL || right == NULL) {
        return 0;
    }
    for (;; left++, right++) {
        const unsigned char a = (unsigned char)*left;
        const unsigned char b = (unsigned char)*right;
        const unsigned char lower_a =
            a >= 'A' && a <= 'Z' ? (unsigned char)(a + ('a' - 'A')) : a;
        const unsigned char lower_b =
            b >= 'A' && b <= 'Z' ? (unsigned char)(b + ('a' - 'A')) : b;
        if (lower_a != lower_b) {
            return 0;
        }
        if (a == '\0') {
            return 1;
        }
    }
}

static int address_from_host(const char *host,
                             uint16_t port,
                             aproxy_addr_t *out)
{
    if (host == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uint8_t address[16];
    if (inet_pton(AF_INET, host, address) == 1) {
        aproxy_addr_set_ipv4(out, address, port);
        return APROXY_OK;
    }
    if (inet_pton(AF_INET6, host, address) == 1) {
        aproxy_addr_set_ipv6(out, address, port);
        return APROXY_OK;
    }
    return aproxy_addr_set_fqdn(out, host, port);
}

uint32_t aproxy_library_abi_version(void)
{
    return APROXY_LIBRARY_ABI_VERSION;
}

const char *aproxy_library_version(void)
{
    return APROXY_LIBRARY_VERSION;
}

const char *aproxy_error_string(int status)
{
    switch (status) {
    case APROXY_OK:
        return "success";
    case APROXY_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case APROXY_ERR_INVALID_FRAME:
        return "invalid frame";
    case APROXY_ERR_FRAME_TOO_LARGE:
        return "frame too large";
    case APROXY_ERR_NO_MEMORY:
        return "out of memory";
    case APROXY_ERR_PARSE:
        return "parse error";
    case APROXY_ERR_BUFFER_TOO_SMALL:
        return "buffer or queue limit reached";
    case APROXY_ERR_UNSUPPORTED:
        return "unsupported";
    case APROXY_ERR_CRYPTO:
        return "cryptographic error";
    case APROXY_ERR_BUSY:
        return "resource busy";
    case APROXY_ERR_CLOSED:
        return "resource closed";
    default:
        return status < 0 ? uv_strerror(status) : "unknown error";
    }
}

int aproxy_loop_new(aproxy_loop_t **out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_loop_t *loop = (aproxy_loop_t *)calloc(1u, sizeof(*loop));
    if (loop == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    const int rc = uv_loop_init(&loop->owned_loop);
    if (rc != 0) {
        free(loop);
        return rc;
    }
    loop->native = &loop->owned_loop;
    loop->owns_native = 1;
    *out = loop;
    return APROXY_OK;
}

int aproxy_loop_wrap(void *native_uv_loop, aproxy_loop_t **out)
{
    if (native_uv_loop == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_loop_t *loop = (aproxy_loop_t *)calloc(1u, sizeof(*loop));
    if (loop == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    loop->native = (uv_loop_t *)native_uv_loop;
    *out = loop;
    return APROXY_OK;
}

void *aproxy_loop_native(aproxy_loop_t *loop)
{
    return loop == NULL ? NULL : loop->native;
}

int aproxy_loop_run(aproxy_loop_t *loop, aproxy_loop_run_mode_t mode)
{
    if (loop == NULL || loop->native == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uv_run_mode uv_mode;
    switch (mode) {
    case APROXY_LOOP_RUN_DEFAULT:
        uv_mode = UV_RUN_DEFAULT;
        break;
    case APROXY_LOOP_RUN_ONCE:
        uv_mode = UV_RUN_ONCE;
        break;
    case APROXY_LOOP_RUN_NOWAIT:
        uv_mode = UV_RUN_NOWAIT;
        break;
    default:
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    (void)uv_run(loop->native, uv_mode);
    return APROXY_OK;
}

void aproxy_loop_stop(aproxy_loop_t *loop)
{
    if (loop != NULL && loop->native != NULL) {
        uv_stop(loop->native);
    }
}

int aproxy_loop_alive(const aproxy_loop_t *loop)
{
    return loop != NULL && loop->native != NULL
               ? uv_loop_alive(loop->native)
               : 0;
}

int aproxy_loop_backend_fd(const aproxy_loop_t *loop, int *fd)
{
    if (loop == NULL || loop->native == NULL || fd == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *fd = uv_backend_fd(loop->native);
    return APROXY_OK;
}

int aproxy_loop_backend_timeout(const aproxy_loop_t *loop, int *timeout_ms)
{
    if (loop == NULL || loop->native == NULL || timeout_ms == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *timeout_ms = uv_backend_timeout(loop->native);
    return APROXY_OK;
}

int aproxy_loop_free(aproxy_loop_t *loop)
{
    if (loop == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (loop->node_refs != 0u) {
        return APROXY_ERR_BUSY;
    }
    if (loop->owns_native) {
        const int rc = uv_loop_close(loop->native);
        if (rc == UV_EBUSY) {
            return APROXY_ERR_BUSY;
        }
        if (rc != 0) {
            return rc;
        }
    }
    free(loop);
    return APROXY_OK;
}

void aproxy_node_options_init(aproxy_node_options_t *options,
                              aproxy_loop_t *loop)
{
    if (options == NULL) {
        return;
    }
    memset(options, 0, sizeof(*options));
    options->abi_version = APROXY_LIBRARY_ABI_VERSION;
    options->struct_size = (uint32_t)sizeof(*options);
    options->loop = loop;
    options->dns_max_cache_entries = 256u;
    options->dns_cache_ttl_ms = 60000u;
    options->dns_negative_cache_ttl_ms = 5000u;
    options->dns_max_pending_requests =
        APROXY_DNS_DEFAULT_MAX_PENDING_REQUESTS;
    options->dns_max_waiters_per_request =
        APROXY_DNS_DEFAULT_MAX_WAITERS_PER_REQUEST;
}

static int node_options_valid(const aproxy_node_options_t *options)
{
    return options != NULL &&
           options->abi_version == APROXY_LIBRARY_ABI_VERSION &&
           options->struct_size >= sizeof(*options) && options->loop != NULL &&
           options->loop->native != NULL &&
           options->dns_max_cache_entries <= SIZE_MAX &&
           options->dns_max_pending_requests <= SIZE_MAX &&
           options->dns_max_waiters_per_request <= SIZE_MAX;
}

int aproxy_node_new(const aproxy_node_options_t *options, aproxy_node_t **out)
{
    if (!node_options_valid(options) || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_node_t *node = (aproxy_node_t *)calloc(1u, sizeof(*node));
    if (node == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    node->loop = options->loop;
    int rc = aproxy_router_new(&node->router);
    if (rc != APROXY_OK) {
        free(node);
        return rc;
    }
    node->resolver = options->resolver;
    node->owns_resolver = options->resolver != NULL &&
                          options->take_resolver_ownership != 0;
    if (node->resolver == NULL) {
        const aproxy_dns_libuv_config_t config = {
            .loop = node->loop->native,
            .max_cache_entries =
                (size_t)options->dns_max_cache_entries,
            .cache_ttl_ms = options->dns_cache_ttl_ms,
            .negative_cache_ttl_ms = options->dns_negative_cache_ttl_ms,
            .max_pending_requests =
                (size_t)options->dns_max_pending_requests,
            .max_waiters_per_request =
                (size_t)options->dns_max_waiters_per_request,
        };
        rc = aproxy_dns_resolver_new_libuv(&config, &node->resolver);
        if (rc != APROXY_OK) {
            aproxy_router_free(node->router);
            free(node);
            return rc;
        }
        node->owns_resolver = 1;
    }
    node->loop->node_refs++;
    *out = node;
    return APROXY_OK;
}

aproxy_dns_resolver_t *aproxy_node_resolver(aproxy_node_t *node)
{
    return node == NULL ? NULL : node->resolver;
}

aproxy_router_t *aproxy_node_router(aproxy_node_t *node)
{
    return node == NULL ? NULL : node->router;
}

aproxy_outbound_t *aproxy_node_find_outbound(aproxy_node_t *node,
                                             const char *tag)
{
    if (node == NULL || tag == NULL) {
        return NULL;
    }
    for (size_t i = 0u; i < node->outbound_count; i++) {
        aproxy_outbound_t *outbound = node->outbounds[i].outbound;
        if (outbound != NULL && outbound->tag != NULL &&
            strcmp(outbound->tag, tag) == 0) {
            return outbound;
        }
    }
    return NULL;
}

static int reserve_outbounds(aproxy_node_t *node)
{
    if (node->outbound_count < node->outbound_capacity) {
        return APROXY_OK;
    }
    const size_t capacity = node->outbound_capacity == 0u
                                ? 8u
                                : node->outbound_capacity * 2u;
    if (capacity < node->outbound_capacity ||
        capacity > SIZE_MAX / sizeof(*node->outbounds)) {
        return APROXY_ERR_NO_MEMORY;
    }
    node_outbound_t *entries = (node_outbound_t *)realloc(
        node->outbounds, capacity * sizeof(*entries));
    if (entries == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    node->outbounds = entries;
    node->outbound_capacity = capacity;
    return APROXY_OK;
}

int aproxy_node_add_outbound(aproxy_node_t *node,
                             aproxy_outbound_t *outbound,
                             int take_ownership)
{
    if (node == NULL || outbound == NULL || outbound->tag == NULL ||
        outbound->tag[0] == '\0' || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (aproxy_node_find_outbound(node, outbound->tag) != NULL) {
        return APROXY_ERR_BUSY;
    }
    const int rc = reserve_outbounds(node);
    if (rc != APROXY_OK) {
        return rc;
    }
    node->outbounds[node->outbound_count].outbound = outbound;
    node->outbounds[node->outbound_count].owned = take_ownership != 0;
    node->outbound_count++;
    return APROXY_OK;
}

static int add_owned_outbound(aproxy_node_t *node,
                              aproxy_outbound_t *outbound,
                              int status)
{
    if (status != APROXY_OK) {
        return status;
    }
    status = aproxy_node_add_outbound(node, outbound, 1);
    if (status != APROXY_OK) {
        aproxy_outbound_free(outbound);
    }
    return status;
}

int aproxy_node_add_direct(aproxy_node_t *node,
                           const aproxy_direct_outbound_config_t *config)
{
    if (node == NULL || config == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_direct_outbound_config_t copy = *config;
    copy.loop = node->loop->native;
    copy.resolver = node->resolver;
    aproxy_outbound_t *outbound = NULL;
    const int rc = aproxy_direct_outbound_new(&copy, &outbound);
    return add_owned_outbound(node, outbound, rc);
}

int aproxy_node_add_block(aproxy_node_t *node, const char *tag)
{
    if (node == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_outbound_t *outbound = NULL;
    const int rc = aproxy_block_outbound_new(tag, &outbound);
    return add_owned_outbound(node, outbound, rc);
}

int aproxy_node_add_anytls(aproxy_node_t *node,
                           const anytls_outbound_config_t *config)
{
    if (node == NULL || config == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    anytls_outbound_config_t copy = *config;
    copy.client.loop = node->loop->native;
    copy.client.resolver = node->resolver;
    aproxy_outbound_t *outbound = NULL;
    const int rc = anytls_outbound_new(&copy, &outbound);
    return add_owned_outbound(node, outbound, rc);
}

int aproxy_node_add_shadowsocks(
    aproxy_node_t *node,
    const shadowsocks_outbound_config_t *config)
{
    if (node == NULL || config == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    shadowsocks_outbound_config_t copy = *config;
    copy.loop = node->loop->native;
    copy.resolver = node->resolver;
    aproxy_outbound_t *outbound = NULL;
    const int rc = shadowsocks_outbound_new(&copy, &outbound);
    return add_owned_outbound(node, outbound, rc);
}

int aproxy_node_add_vless(aproxy_node_t *node,
                          const vless_outbound_config_t *config)
{
    if (node == NULL || config == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    vless_outbound_config_t copy = *config;
    copy.loop = node->loop->native;
    copy.resolver = node->resolver;
    aproxy_outbound_t *outbound = NULL;
    const int rc = vless_outbound_new(&copy, &outbound);
    return add_owned_outbound(node, outbound, rc);
}

int aproxy_node_connect_outbound(aproxy_node_t *node, const char *tag)
{
    aproxy_outbound_t *outbound = aproxy_node_find_outbound(node, tag);
    if (outbound == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return aproxy_outbound_connect(outbound);
}

int aproxy_node_connect_all(aproxy_node_t *node,
                            aproxy_node_outbound_status_cb callback,
                            void *user_data)
{
    if (node == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    int first_error = APROXY_OK;
    const size_t count = node->outbound_count;
    for (size_t i = 0u; i < count; i++) {
        aproxy_outbound_t *outbound = node->outbounds[i].outbound;
        const int rc = aproxy_outbound_connect(outbound);
        if (first_error == APROXY_OK && rc != APROXY_OK) {
            first_error = rc;
        }
        if (callback != NULL) {
            node->callback_depth++;
            callback(node, outbound->tag, rc, user_data);
            node->callback_depth--;
        }
        if (node->closing) {
            break;
        }
    }
    return first_error;
}

static aproxy_outbound_t *route_outbound(aproxy_node_t *node,
                                         const char *tag)
{
    return node == NULL || node->closing
               ? NULL
               : aproxy_node_find_outbound(node, tag);
}

int aproxy_node_set_default_outbound(aproxy_node_t *node,
                                     const char *outbound_tag)
{
    aproxy_outbound_t *outbound = route_outbound(node, outbound_tag);
    return outbound == NULL
               ? APROXY_ERR_INVALID_ARGUMENT
               : aproxy_router_set_default(node->router, outbound);
}

int aproxy_node_add_domain_exact_route(aproxy_node_t *node,
                                       const char *domain,
                                       const char *outbound_tag)
{
    aproxy_outbound_t *outbound = route_outbound(node, outbound_tag);
    return outbound == NULL
               ? APROXY_ERR_INVALID_ARGUMENT
               : aproxy_router_add_domain_exact(node->router, domain,
                                                outbound);
}

int aproxy_node_add_domain_suffix_route(aproxy_node_t *node,
                                        const char *suffix,
                                        const char *outbound_tag)
{
    aproxy_outbound_t *outbound = route_outbound(node, outbound_tag);
    return outbound == NULL
               ? APROXY_ERR_INVALID_ARGUMENT
               : aproxy_router_add_domain_suffix(node->router, suffix,
                                                 outbound);
}

int aproxy_node_add_ipv4_cidr_route(aproxy_node_t *node,
                                    const uint8_t network[4],
                                    uint8_t prefix_len,
                                    const char *outbound_tag)
{
    aproxy_outbound_t *outbound = route_outbound(node, outbound_tag);
    return outbound == NULL
               ? APROXY_ERR_INVALID_ARGUMENT
               : aproxy_router_add_ipv4_cidr(node->router, network,
                                             prefix_len, outbound);
}

int aproxy_node_add_ipv6_cidr_route(aproxy_node_t *node,
                                    const uint8_t network[16],
                                    uint8_t prefix_len,
                                    const char *outbound_tag)
{
    aproxy_outbound_t *outbound = route_outbound(node, outbound_tag);
    return outbound == NULL
               ? APROXY_ERR_INVALID_ARGUMENT
               : aproxy_router_add_ipv6_cidr(node->router, network,
                                             prefix_len, outbound);
}

static int geoip_db_get(aproxy_node_t *node,
                        const char *path,
                        aproxy_geoip_db_t **out)
{
    for (node_geoip_db_t *entry = node->geoip_dbs; entry != NULL;
         entry = entry->next) {
        if (strcmp(entry->path, path) == 0) {
            *out = entry->db;
            return APROXY_OK;
        }
    }
    node_geoip_db_t *entry =
        (node_geoip_db_t *)calloc(1u, sizeof(*entry));
    if (entry == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    entry->path = copy_string(path);
    int rc = entry->path == NULL
                 ? APROXY_ERR_NO_MEMORY
                 : aproxy_geoip_db_open_v2ray_dat(path, &entry->db);
    if (rc != APROXY_OK) {
        free(entry->path);
        free(entry);
        return rc;
    }
    entry->next = node->geoip_dbs;
    node->geoip_dbs = entry;
    *out = entry->db;
    return APROXY_OK;
}

static aproxy_geoip_set_t *find_geoip_set(const aproxy_node_t *node,
                                          const char *path,
                                          const char *country_code)
{
    for (const node_geoip_t *entry = node->geoip_sets; entry != NULL;
         entry = entry->next) {
        if (strcmp(entry->path, path) == 0 &&
            ascii_string_equal_fold(aproxy_geoip_set_code(entry->set),
                                    country_code)) {
            return entry->set;
        }
    }
    return NULL;
}

static node_geoip_t *new_geoip_owner(aproxy_geoip_set_t *set,
                                     const char *path)
{
    const size_t path_len = strlen(path);
    if (path_len == SIZE_MAX ||
        path_len + 1u > SIZE_MAX - sizeof(node_geoip_t)) {
        return NULL;
    }
    node_geoip_t *entry = (node_geoip_t *)malloc(
        sizeof(*entry) + path_len + 1u);
    if (entry == NULL) {
        return NULL;
    }
    entry->set = set;
    entry->next = NULL;
    memcpy(entry->path, path, path_len + 1u);
    return entry;
}

int aproxy_node_add_geoip_route(aproxy_node_t *node,
                                const char *dat_path,
                                const char *country_code,
                                const char *outbound_tag)
{
    return aproxy_node_add_geoip_route_to(
        node, node == NULL ? NULL : node->router, dat_path, country_code,
        outbound_tag, 0);
}

int aproxy_node_add_geoip_route_to(aproxy_node_t *node,
                                   aproxy_router_t *router,
                                   const char *dat_path,
                                   const char *country_code,
                                   const char *outbound_tag,
                                   int use_selected_proxy)
{
    aproxy_outbound_t *outbound = use_selected_proxy
                                      ? NULL
                                      : route_outbound(node, outbound_tag);
    if (node == NULL || router == NULL ||
        (!use_selected_proxy && outbound == NULL) || dat_path == NULL ||
        country_code == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_geoip_set_t *set =
        find_geoip_set(node, dat_path, country_code);
    if (set != NULL) {
        return use_selected_proxy
                   ? aproxy_router_add_geoip_proxy(router, set)
                   : aproxy_router_add_geoip(router, set, outbound);
    }
    aproxy_geoip_db_t *db = NULL;
    int rc = geoip_db_get(node, dat_path, &db);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = aproxy_geoip_db_load(db, country_code, &set);
    if (rc != APROXY_OK) {
        return rc;
    }
    node_geoip_t *entry = new_geoip_owner(set, dat_path);
    if (entry == NULL) {
        aproxy_geoip_set_free(set);
        return APROXY_ERR_NO_MEMORY;
    }
    rc = use_selected_proxy
             ? aproxy_router_add_geoip_proxy(router, set)
             : aproxy_router_add_geoip(router, set, outbound);
    if (rc != APROXY_OK) {
        aproxy_geoip_set_free(set);
        free(entry);
        return rc;
    }
    entry->set = set;
    entry->next = node->geoip_sets;
    node->geoip_sets = entry;
    return APROXY_OK;
}

static int geosite_db_get(aproxy_node_t *node,
                          const char *path,
                          aproxy_geosite_db_t **out)
{
    for (node_geosite_db_t *entry = node->geosite_dbs; entry != NULL;
         entry = entry->next) {
        if (strcmp(entry->path, path) == 0) {
            *out = entry->db;
            return APROXY_OK;
        }
    }
    node_geosite_db_t *entry =
        (node_geosite_db_t *)calloc(1u, sizeof(*entry));
    if (entry == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    entry->path = copy_string(path);
    int rc = entry->path == NULL
                 ? APROXY_ERR_NO_MEMORY
                 : aproxy_geosite_db_open_v2ray_dat(path, &entry->db);
    if (rc != APROXY_OK) {
        free(entry->path);
        free(entry);
        return rc;
    }
    entry->next = node->geosite_dbs;
    node->geosite_dbs = entry;
    *out = entry->db;
    return APROXY_OK;
}

static aproxy_geosite_set_t *find_geosite_set(const aproxy_node_t *node,
                                              const char *path,
                                              const char *selector)
{
    for (const node_geosite_t *entry = node->geosite_sets; entry != NULL;
         entry = entry->next) {
        if (strcmp(entry->path, path) == 0 &&
            ascii_string_equal_fold(
                aproxy_geosite_set_selector(entry->set), selector)) {
            return entry->set;
        }
    }
    return NULL;
}

static node_geosite_t *new_geosite_owner(aproxy_geosite_set_t *set,
                                         const char *path)
{
    const size_t path_len = strlen(path);
    if (path_len == SIZE_MAX ||
        path_len + 1u > SIZE_MAX - sizeof(node_geosite_t)) {
        return NULL;
    }
    node_geosite_t *entry = (node_geosite_t *)malloc(
        sizeof(*entry) + path_len + 1u);
    if (entry == NULL) {
        return NULL;
    }
    entry->set = set;
    entry->next = NULL;
    memcpy(entry->path, path, path_len + 1u);
    return entry;
}

int aproxy_node_add_geosite_route(aproxy_node_t *node,
                                  const char *dat_path,
                                  const char *selector,
                                  const char *outbound_tag)
{
    return aproxy_node_add_geosite_route_to(
        node, node == NULL ? NULL : node->router, dat_path, selector,
        outbound_tag, 0);
}

int aproxy_node_add_geosite_route_to(aproxy_node_t *node,
                                     aproxy_router_t *router,
                                     const char *dat_path,
                                     const char *selector,
                                     const char *outbound_tag,
                                     int use_selected_proxy)
{
    aproxy_outbound_t *outbound = use_selected_proxy
                                      ? NULL
                                      : route_outbound(node, outbound_tag);
    if (node == NULL || router == NULL ||
        (!use_selected_proxy && outbound == NULL) || dat_path == NULL ||
        selector == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_geosite_set_t *set =
        find_geosite_set(node, dat_path, selector);
    if (set != NULL) {
        return use_selected_proxy
                   ? aproxy_router_add_geosite_proxy(router, set)
                   : aproxy_router_add_geosite(router, set, outbound);
    }
    aproxy_geosite_db_t *db = NULL;
    int rc = geosite_db_get(node, dat_path, &db);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = aproxy_geosite_db_load(db, selector, &set);
    if (rc != APROXY_OK) {
        return rc;
    }
    node_geosite_t *entry = new_geosite_owner(set, dat_path);
    if (entry == NULL) {
        aproxy_geosite_set_free(set);
        return APROXY_ERR_NO_MEMORY;
    }
    rc = use_selected_proxy
             ? aproxy_router_add_geosite_proxy(router, set)
             : aproxy_router_add_geosite(router, set, outbound);
    if (rc != APROXY_OK) {
        aproxy_geosite_set_free(set);
        free(entry);
        return rc;
    }
    entry->set = set;
    entry->next = node->geosite_sets;
    node->geosite_sets = entry;
    return APROXY_OK;
}

static void release_geoip_dbs(aproxy_node_t *node)
{
    while (node->geoip_dbs != NULL) {
        node_geoip_db_t *entry = node->geoip_dbs;
        node->geoip_dbs = entry->next;
        aproxy_geoip_db_free(entry->db);
        free(entry->path);
        free(entry);
    }
}

static void release_geosite_dbs(aproxy_node_t *node)
{
    while (node->geosite_dbs != NULL) {
        node_geosite_db_t *entry = node->geosite_dbs;
        node->geosite_dbs = entry->next;
        aproxy_geosite_db_free(entry->db);
        free(entry->path);
        free(entry);
    }
}

void aproxy_node_release_route_databases(aproxy_node_t *node)
{
    if (node == NULL) {
        return;
    }
    release_geoip_dbs(node);
    release_geosite_dbs(node);
    aproxy_router_compact(node->router);
}

void aproxy_stream_callbacks_init(aproxy_stream_callbacks_t *callbacks)
{
    if (callbacks == NULL) {
        return;
    }
    memset(callbacks, 0, sizeof(*callbacks));
    callbacks->abi_version = APROXY_LIBRARY_ABI_VERSION;
    callbacks->struct_size = (uint32_t)sizeof(*callbacks);
}

static int stream_callbacks_valid(const aproxy_stream_callbacks_t *callbacks)
{
    return callbacks != NULL &&
           callbacks->abi_version == APROXY_LIBRARY_ABI_VERSION &&
           callbacks->struct_size >= sizeof(*callbacks);
}

static void stream_list_add(aproxy_node_t *node,
                            aproxy_client_stream_t *stream)
{
    stream->next = node->streams;
    if (node->streams != NULL) {
        node->streams->prev = stream;
    }
    node->streams = stream;
}

static void stream_list_remove(aproxy_client_stream_t *stream)
{
    aproxy_node_t *node = stream->node;
    if (stream->prev != NULL) {
        stream->prev->next = stream->next;
    } else if (node != NULL && node->streams == stream) {
        node->streams = stream->next;
    }
    if (stream->next != NULL) {
        stream->next->prev = stream->prev;
    }
    stream->prev = NULL;
    stream->next = NULL;
}

static void stream_maybe_destroy(aproxy_client_stream_t *stream)
{
    if (stream != NULL && stream->released && stream->native == NULL &&
        !stream->dns_pending && stream->callback_depth == 0u &&
        stream->lifecycle_depth == 0u) {
        stream_list_remove(stream);
        free(stream);
    }
}

static void stream_report_open(aproxy_client_stream_t *stream, int status)
{
    if (stream->open_reported) {
        return;
    }
    stream->open_reported = 1;
    if (!stream->released && stream->callbacks.on_open != NULL) {
        stream->callback_depth++;
        stream->callbacks.on_open(stream, status, stream->user_data);
        stream->callback_depth--;
    }
}

static void stream_report_close(aproxy_client_stream_t *stream, int status)
{
    if (stream->close_reported) {
        return;
    }
    stream->close_reported = 1;
    if (!stream->released && stream->callbacks.on_close != NULL) {
        stream->callback_depth++;
        stream->callbacks.on_close(stream, status, stream->user_data);
        stream->callback_depth--;
    }
}

static void stream_fail(aproxy_client_stream_t *stream, int status)
{
    stream_report_open(stream, status);
    stream->closing = 1;
    stream->closed = 1;
    stream_report_close(stream, status);
}

static void native_stream_data_cb(aproxy_stream_t *native,
                                  const uint8_t *data,
                                  size_t len,
                                  void *user_data)
{
    (void)native;
    aproxy_client_stream_t *stream =
        (aproxy_client_stream_t *)user_data;
    if (stream == NULL || stream->released || stream->closing ||
        stream->callbacks.on_data == NULL) {
        return;
    }
    stream->lifecycle_depth++;
    stream->callback_depth++;
    stream->callbacks.on_data(stream, data, len, stream->user_data);
    stream->callback_depth--;
    stream->lifecycle_depth--;
    stream_maybe_destroy(stream);
}

static void native_stream_open_cb(aproxy_stream_t *native,
                                  int status,
                                  void *user_data)
{
    aproxy_client_stream_t *stream =
        (aproxy_client_stream_t *)user_data;
    if (stream == NULL) {
        return;
    }
    stream->lifecycle_depth++;
    if (stream->native == NULL) {
        stream->native = native;
    }
    stream_report_open(stream, status);
    if (status != APROXY_OK && !stream->closing) {
        (void)aproxy_client_stream_close(stream);
    }
    stream->lifecycle_depth--;
    stream_maybe_destroy(stream);
}

static void native_stream_close_cb(aproxy_stream_t *native,
                                   int status,
                                   void *user_data)
{
    aproxy_client_stream_t *stream =
        (aproxy_client_stream_t *)user_data;
    if (stream == NULL) {
        aproxy_stream_free(native);
        return;
    }
    stream->lifecycle_depth++;
    if (stream->native == native) {
        stream->native = NULL;
    }
    aproxy_stream_free(native);
    stream->closing = 1;
    stream->closed = 1;
    if (!stream->open_reported) {
        stream_report_open(stream, status == APROXY_OK
                                       ? APROXY_ERR_CLOSED
                                       : status);
    }
    stream_report_close(stream, status);
    stream->lifecycle_depth--;
    stream_maybe_destroy(stream);
}

static void stream_open_outbound(aproxy_client_stream_t *stream,
                                 aproxy_outbound_t *outbound)
{
    if (outbound == NULL) {
        stream_fail(stream, APROXY_ERR_INVALID_ARGUMENT);
        return;
    }
    stream->outbound = outbound;
    stream->lifecycle_depth++;
    aproxy_stream_t *native = NULL;
    const int rc = aproxy_outbound_open_stream(
        outbound, &stream->destination, native_stream_data_cb,
        native_stream_open_cb, native_stream_close_cb, stream, &native);
    if (stream->native == NULL) {
        stream->native = native;
    }
    if (rc != APROXY_OK) {
        if (stream->native != NULL) {
            aproxy_stream_t *failed = stream->native;
            stream->native = NULL;
            (void)aproxy_stream_close(failed);
            aproxy_stream_free(failed);
        }
        stream_fail(stream, rc);
    } else if (stream->native == NULL && !stream->closed) {
        stream_fail(stream, APROXY_ERR_INVALID_ARGUMENT);
    }
    stream->lifecycle_depth--;
    stream_maybe_destroy(stream);
}

static void stream_route_dns_cb(aproxy_dns_resolver_t *resolver,
                                int status,
                                const aproxy_addr_t *addresses,
                                size_t count,
                                void *user_data)
{
    (void)resolver;
    aproxy_client_stream_t *stream =
        (aproxy_client_stream_t *)user_data;
    if (stream == NULL) {
        return;
    }
    stream->lifecycle_depth++;
    stream->dns_pending = 0;
    if (!stream->closing && !stream->closed && !stream->released) {
        aproxy_outbound_t *outbound = aproxy_router_pick_resolved(
            stream->node->router, &stream->destination,
            status == APROXY_OK ? addresses : NULL,
            status == APROXY_OK ? count : 0u);
        stream_open_outbound(stream, outbound);
    }
    stream->lifecycle_depth--;
    stream_maybe_destroy(stream);
}

int aproxy_node_open_stream(aproxy_node_t *node,
                            const aproxy_addr_t *destination,
                            const aproxy_stream_callbacks_t *callbacks,
                            void *user_data,
                            aproxy_client_stream_t **out)
{
    if (node == NULL || destination == NULL ||
        !stream_callbacks_valid(callbacks) || out == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_client_stream_t *stream =
        (aproxy_client_stream_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    stream->node = node;
    stream->destination = *destination;
    stream->callbacks = *callbacks;
    stream->user_data = user_data;
    stream->lifecycle_depth++;
    stream_list_add(node, stream);
    *out = stream;

    if (node->resolver != NULL &&
        aproxy_router_needs_resolution(node->router, destination)) {
        stream->dns_pending = 1;
        const int rc = aproxy_dns_resolve(
            node->resolver, destination->fqdn, destination->port,
            stream_route_dns_cb, stream);
        if (rc != APROXY_OK && stream->dns_pending) {
            stream->dns_pending = 0;
            stream_fail(stream, rc);
        }
    } else {
        stream_open_outbound(
            stream, aproxy_router_pick(node->router, destination));
    }
    stream->lifecycle_depth--;
    stream_maybe_destroy(stream);
    return APROXY_OK;
}

int aproxy_node_open_stream_host(
    aproxy_node_t *node,
    const char *host,
    uint16_t port,
    const aproxy_stream_callbacks_t *callbacks,
    void *user_data,
    aproxy_client_stream_t **out)
{
    aproxy_addr_t destination;
    const int rc = address_from_host(host, port, &destination);
    return rc == APROXY_OK
               ? aproxy_node_open_stream(node, &destination, callbacks,
                                         user_data, out)
               : rc;
}

int aproxy_client_stream_write(aproxy_client_stream_t *stream,
                               const uint8_t *data,
                               size_t len)
{
    if (stream == NULL || (data == NULL && len != 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (stream->released || stream->closing || stream->closed) {
        return APROXY_ERR_CLOSED;
    }
    if (stream->native == NULL) {
        return APROXY_ERR_BUSY;
    }
    return aproxy_stream_write(stream->native, data, len);
}

int aproxy_client_stream_close(aproxy_client_stream_t *stream)
{
    if (stream == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (stream->closing || stream->closed) {
        return APROXY_OK;
    }
    stream->lifecycle_depth++;
    stream->closing = 1;
    if (!stream->open_reported) {
        stream_report_open(stream, APROXY_ERR_CLOSED);
    }
    int rc = APROXY_OK;
    if (stream->native != NULL) {
        rc = aproxy_stream_close(stream->native);
        if (rc != APROXY_OK && stream->native != NULL) {
            aproxy_stream_t *native = stream->native;
            stream->native = NULL;
            aproxy_stream_free(native);
            stream->closed = 1;
            stream_report_close(stream, rc);
        }
    } else {
        stream->closed = 1;
        stream_report_close(stream, APROXY_OK);
    }
    stream->lifecycle_depth--;
    stream_maybe_destroy(stream);
    return rc;
}

const char *aproxy_client_stream_outbound_tag(
    const aproxy_client_stream_t *stream)
{
    return stream == NULL || stream->outbound == NULL
               ? NULL
               : stream->outbound->tag;
}

void aproxy_client_stream_free(aproxy_client_stream_t *stream)
{
    if (stream == NULL || stream->released) {
        return;
    }
    stream->lifecycle_depth++;
    stream->released = 1;
    memset(&stream->callbacks, 0, sizeof(stream->callbacks));
    if (!stream->closing && !stream->closed) {
        (void)aproxy_client_stream_close(stream);
    }
    stream->lifecycle_depth--;
    stream_maybe_destroy(stream);
}

void aproxy_packet_flow_callbacks_init(
    aproxy_packet_flow_callbacks_t *callbacks)
{
    if (callbacks == NULL) {
        return;
    }
    memset(callbacks, 0, sizeof(*callbacks));
    callbacks->abi_version = APROXY_LIBRARY_ABI_VERSION;
    callbacks->struct_size = (uint32_t)sizeof(*callbacks);
}

static int packet_callbacks_valid(
    const aproxy_packet_flow_callbacks_t *callbacks)
{
    return callbacks != NULL &&
           callbacks->abi_version == APROXY_LIBRARY_ABI_VERSION &&
           callbacks->struct_size >= sizeof(*callbacks);
}

static void packet_list_add(aproxy_node_t *node,
                            aproxy_client_packet_flow_t *flow)
{
    flow->next = node->packet_flows;
    if (node->packet_flows != NULL) {
        node->packet_flows->prev = flow;
    }
    node->packet_flows = flow;
}

static void packet_list_remove(aproxy_client_packet_flow_t *flow)
{
    aproxy_node_t *node = flow->node;
    if (flow->prev != NULL) {
        flow->prev->next = flow->next;
    } else if (node != NULL && node->packet_flows == flow) {
        node->packet_flows = flow->next;
    }
    if (flow->next != NULL) {
        flow->next->prev = flow->prev;
    }
    flow->prev = NULL;
    flow->next = NULL;
}

static void packet_maybe_destroy(aproxy_client_packet_flow_t *flow)
{
    if (flow != NULL && flow->released && flow->native == NULL &&
        !flow->dns_pending && flow->callback_depth == 0u &&
        flow->lifecycle_depth == 0u) {
        packet_list_remove(flow);
        free(flow);
    }
}

static void packet_report_open(aproxy_client_packet_flow_t *flow, int status)
{
    if (flow->open_reported) {
        return;
    }
    flow->open_reported = 1;
    if (!flow->released && flow->callbacks.on_open != NULL) {
        flow->callback_depth++;
        flow->callbacks.on_open(flow, status, flow->user_data);
        flow->callback_depth--;
    }
}

static void packet_report_close(aproxy_client_packet_flow_t *flow, int status)
{
    if (flow->close_reported) {
        return;
    }
    flow->close_reported = 1;
    if (!flow->released && flow->callbacks.on_close != NULL) {
        flow->callback_depth++;
        flow->callbacks.on_close(flow, status, flow->user_data);
        flow->callback_depth--;
    }
}

static void packet_fail(aproxy_client_packet_flow_t *flow, int status)
{
    packet_report_open(flow, status);
    flow->closing = 1;
    flow->closed = 1;
    packet_report_close(flow, status);
}

static void native_packet_data_cb(aproxy_packet_flow_t *native,
                                  const aproxy_addr_t *source,
                                  const uint8_t *data,
                                  size_t len,
                                  void *user_data)
{
    (void)native;
    aproxy_client_packet_flow_t *flow =
        (aproxy_client_packet_flow_t *)user_data;
    if (flow == NULL || flow->released || flow->closing ||
        flow->callbacks.on_packet == NULL) {
        return;
    }
    flow->lifecycle_depth++;
    flow->callback_depth++;
    flow->callbacks.on_packet(flow, source, data, len, flow->user_data);
    flow->callback_depth--;
    flow->lifecycle_depth--;
    packet_maybe_destroy(flow);
}

static void native_packet_open_cb(aproxy_packet_flow_t *native,
                                  int status,
                                  void *user_data)
{
    aproxy_client_packet_flow_t *flow =
        (aproxy_client_packet_flow_t *)user_data;
    if (flow == NULL) {
        return;
    }
    flow->lifecycle_depth++;
    if (flow->native == NULL) {
        flow->native = native;
    }
    packet_report_open(flow, status);
    if (status != APROXY_OK && !flow->closing) {
        (void)aproxy_client_packet_flow_close(flow);
    }
    flow->lifecycle_depth--;
    packet_maybe_destroy(flow);
}

static void native_packet_close_cb(aproxy_packet_flow_t *native,
                                   int status,
                                   void *user_data)
{
    aproxy_client_packet_flow_t *flow =
        (aproxy_client_packet_flow_t *)user_data;
    if (flow == NULL) {
        aproxy_packet_flow_free(native);
        return;
    }
    flow->lifecycle_depth++;
    if (flow->native == native) {
        flow->native = NULL;
    }
    aproxy_packet_flow_free(native);
    flow->closing = 1;
    flow->closed = 1;
    if (!flow->open_reported) {
        packet_report_open(flow, status == APROXY_OK
                                     ? APROXY_ERR_CLOSED
                                     : status);
    }
    packet_report_close(flow, status);
    flow->lifecycle_depth--;
    packet_maybe_destroy(flow);
}

static void packet_open_outbound(aproxy_client_packet_flow_t *flow,
                                 aproxy_outbound_t *outbound)
{
    if (outbound == NULL) {
        packet_fail(flow, APROXY_ERR_INVALID_ARGUMENT);
        return;
    }
    flow->outbound = outbound;
    flow->lifecycle_depth++;
    aproxy_packet_flow_t *native = NULL;
    const int rc = aproxy_outbound_open_packet(
        outbound, &flow->initial_destination, native_packet_data_cb,
        native_packet_open_cb, native_packet_close_cb, flow, &native);
    if (flow->native == NULL) {
        flow->native = native;
    }
    if (rc != APROXY_OK) {
        if (flow->native != NULL) {
            aproxy_packet_flow_t *failed = flow->native;
            flow->native = NULL;
            (void)aproxy_packet_flow_close(failed);
            aproxy_packet_flow_free(failed);
        }
        packet_fail(flow, rc);
    } else if (flow->native == NULL && !flow->closed) {
        packet_fail(flow, APROXY_ERR_INVALID_ARGUMENT);
    }
    flow->lifecycle_depth--;
    packet_maybe_destroy(flow);
}

static void packet_route_dns_cb(aproxy_dns_resolver_t *resolver,
                                int status,
                                const aproxy_addr_t *addresses,
                                size_t count,
                                void *user_data)
{
    (void)resolver;
    aproxy_client_packet_flow_t *flow =
        (aproxy_client_packet_flow_t *)user_data;
    if (flow == NULL) {
        return;
    }
    flow->lifecycle_depth++;
    flow->dns_pending = 0;
    if (!flow->closing && !flow->closed && !flow->released) {
        aproxy_outbound_t *outbound = aproxy_router_pick_resolved(
            flow->node->router, &flow->initial_destination,
            status == APROXY_OK ? addresses : NULL,
            status == APROXY_OK ? count : 0u);
        packet_open_outbound(flow, outbound);
    }
    flow->lifecycle_depth--;
    packet_maybe_destroy(flow);
}

int aproxy_node_open_packet_flow(
    aproxy_node_t *node,
    const aproxy_addr_t *initial_destination,
    const aproxy_packet_flow_callbacks_t *callbacks,
    void *user_data,
    aproxy_client_packet_flow_t **out)
{
    if (node == NULL || initial_destination == NULL ||
        !packet_callbacks_valid(callbacks) || out == NULL || node->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    aproxy_client_packet_flow_t *flow =
        (aproxy_client_packet_flow_t *)calloc(1u, sizeof(*flow));
    if (flow == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    flow->node = node;
    flow->initial_destination = *initial_destination;
    flow->callbacks = *callbacks;
    flow->user_data = user_data;
    flow->lifecycle_depth++;
    packet_list_add(node, flow);
    *out = flow;

    if (node->resolver != NULL && aproxy_router_needs_resolution(
                                      node->router, initial_destination)) {
        flow->dns_pending = 1;
        const int rc = aproxy_dns_resolve(
            node->resolver, initial_destination->fqdn,
            initial_destination->port, packet_route_dns_cb, flow);
        if (rc != APROXY_OK && flow->dns_pending) {
            flow->dns_pending = 0;
            packet_fail(flow, rc);
        }
    } else {
        packet_open_outbound(
            flow, aproxy_router_pick(node->router, initial_destination));
    }
    flow->lifecycle_depth--;
    packet_maybe_destroy(flow);
    return APROXY_OK;
}

int aproxy_node_open_packet_flow_host(
    aproxy_node_t *node,
    const char *initial_host,
    uint16_t initial_port,
    const aproxy_packet_flow_callbacks_t *callbacks,
    void *user_data,
    aproxy_client_packet_flow_t **out)
{
    aproxy_addr_t destination;
    const int rc = address_from_host(initial_host, initial_port, &destination);
    return rc == APROXY_OK
               ? aproxy_node_open_packet_flow(node, &destination, callbacks,
                                              user_data, out)
               : rc;
}

int aproxy_client_packet_flow_send(aproxy_client_packet_flow_t *flow,
                                   const aproxy_addr_t *destination,
                                   const uint8_t *data,
                                   size_t len)
{
    if (flow == NULL || destination == NULL ||
        (data == NULL && len != 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (flow->released || flow->closing || flow->closed) {
        return APROXY_ERR_CLOSED;
    }
    if (flow->native == NULL) {
        return APROXY_ERR_BUSY;
    }
    return aproxy_packet_flow_send(flow->native, destination, data, len);
}

int aproxy_client_packet_flow_send_host(aproxy_client_packet_flow_t *flow,
                                        const char *host,
                                        uint16_t port,
                                        const uint8_t *data,
                                        size_t len)
{
    aproxy_addr_t destination;
    const int rc = address_from_host(host, port, &destination);
    return rc == APROXY_OK
               ? aproxy_client_packet_flow_send(flow, &destination, data, len)
               : rc;
}

int aproxy_client_packet_flow_close(aproxy_client_packet_flow_t *flow)
{
    if (flow == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (flow->closing || flow->closed) {
        return APROXY_OK;
    }
    flow->lifecycle_depth++;
    flow->closing = 1;
    if (!flow->open_reported) {
        packet_report_open(flow, APROXY_ERR_CLOSED);
    }
    int rc = APROXY_OK;
    if (flow->native != NULL) {
        rc = aproxy_packet_flow_close(flow->native);
        if (rc != APROXY_OK && flow->native != NULL) {
            aproxy_packet_flow_t *native = flow->native;
            flow->native = NULL;
            aproxy_packet_flow_free(native);
            flow->closed = 1;
            packet_report_close(flow, rc);
        }
    } else {
        flow->closed = 1;
        packet_report_close(flow, APROXY_OK);
    }
    flow->lifecycle_depth--;
    packet_maybe_destroy(flow);
    return rc;
}

const char *aproxy_client_packet_flow_outbound_tag(
    const aproxy_client_packet_flow_t *flow)
{
    return flow == NULL || flow->outbound == NULL
               ? NULL
               : flow->outbound->tag;
}

void aproxy_client_packet_flow_free(aproxy_client_packet_flow_t *flow)
{
    if (flow == NULL || flow->released) {
        return;
    }
    flow->lifecycle_depth++;
    flow->released = 1;
    memset(&flow->callbacks, 0, sizeof(flow->callbacks));
    if (!flow->closing && !flow->closed) {
        (void)aproxy_client_packet_flow_close(flow);
    }
    flow->lifecycle_depth--;
    packet_maybe_destroy(flow);
}

void aproxy_node_close(aproxy_node_t *node)
{
    if (node == NULL || node->closing) {
        return;
    }
    node->closing = 1;
    for (;;) {
        aproxy_client_stream_t *stream = node->streams;
        while (stream != NULL && stream->closing) {
            stream = stream->next;
        }
        if (stream == NULL) {
            break;
        }
        (void)aproxy_client_stream_close(stream);
    }
    for (;;) {
        aproxy_client_packet_flow_t *flow = node->packet_flows;
        while (flow != NULL && flow->closing) {
            flow = flow->next;
        }
        if (flow == NULL) {
            break;
        }
        (void)aproxy_client_packet_flow_close(flow);
    }
    for (size_t i = 0u; i < node->outbound_count; i++) {
        aproxy_outbound_close(node->outbounds[i].outbound);
    }
}

int aproxy_node_free(aproxy_node_t *node)
{
    if (node == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (node->callback_depth != 0u) {
        return APROXY_ERR_BUSY;
    }
    aproxy_node_close(node);
    if (node->streams != NULL || node->packet_flows != NULL) {
        return APROXY_ERR_BUSY;
    }
    if (node->loop != NULL && node->loop->owns_native &&
        node->loop->node_refs == 1u && uv_loop_alive(node->loop->native)) {
        return APROXY_ERR_BUSY;
    }

    /* Destruction frees the router immediately, so do not spend work
     * compacting its builder capacity first. */
    release_geoip_dbs(node);
    release_geosite_dbs(node);
    aproxy_router_free(node->router);
    for (node_geoip_t *entry = node->geoip_sets; entry != NULL;) {
        node_geoip_t *next = entry->next;
        aproxy_geoip_set_free(entry->set);
        free(entry);
        entry = next;
    }
    for (node_geosite_t *entry = node->geosite_sets; entry != NULL;) {
        node_geosite_t *next = entry->next;
        aproxy_geosite_set_free(entry->set);
        free(entry);
        entry = next;
    }
    for (size_t i = 0u; i < node->outbound_count; i++) {
        if (node->outbounds[i].owned) {
            aproxy_outbound_free(node->outbounds[i].outbound);
        }
    }
    if (node->owns_resolver) {
        aproxy_dns_resolver_free(node->resolver);
    }
    free(node->outbounds);
    if (node->loop != NULL && node->loop->node_refs > 0u) {
        node->loop->node_refs--;
    }
    free(node);
    return APROXY_OK;
}
