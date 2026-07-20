#include "aproxy/dns.h"

#if !defined(_WIN32)
#include <netdb.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"

typedef struct dns_cache_entry {
    char *host;
    uint16_t port;
    uint64_t expires_at_ms;
    int status;
    aproxy_addr_t *addresses;
    size_t count;
    uint64_t hash;
    struct dns_cache_entry *prev;
    struct dns_cache_entry *next;
    struct dns_cache_entry *hash_next;
} dns_cache_entry_t;

typedef struct dns_libuv_impl dns_libuv_impl_t;

typedef struct dns_waiter {
    aproxy_dns_result_cb cb;
    void *user_data;
    struct dns_waiter *next;
} dns_waiter_t;

typedef struct dns_request {
    uv_getaddrinfo_t req;
    dns_libuv_impl_t *impl;
    char *host;
    uint16_t port;
    dns_waiter_t *waiters;
    dns_waiter_t *waiter_tail;
    size_t waiter_count;
    uint64_t hash;
    struct dns_request *prev;
    struct dns_request *next;
    struct dns_request *hash_next;
} dns_request_t;

struct dns_libuv_impl {
    uv_loop_t *loop;
    aproxy_dns_resolver_t *owner;
    size_t max_cache_entries;
    size_t cache_count;
    uint64_t cache_ttl_ms;
    uint64_t negative_cache_ttl_ms;
    size_t max_pending_requests;
    size_t max_waiters_per_request;
    size_t request_count;
    dns_cache_entry_t *cache;
    dns_cache_entry_t *cache_tail;
    dns_cache_entry_t **cache_buckets;
    size_t cache_bucket_count;
    dns_request_t *requests;
    dns_request_t **request_buckets;
    size_t request_bucket_count;
    int closing;
    int callback_depth;
};

#define DNS_INITIAL_REQUEST_BUCKETS 64u

static uint64_t dns_key_hash(const char *host, uint16_t port)
{
    uint64_t hash = UINT64_C(1469598103934665603);
    for (const unsigned char *p = (const unsigned char *)host; *p != 0u; p++) {
        hash ^= *p;
        hash *= UINT64_C(1099511628211);
    }
    hash ^= (uint8_t)(port >> 8u);
    hash *= UINT64_C(1099511628211);
    hash ^= (uint8_t)port;
    hash *= UINT64_C(1099511628211);
    hash ^= hash >> 32u;
    return hash;
}

static size_t dns_bucket_count(size_t entries)
{
    size_t count = 16u;
    while (count < entries && count <= SIZE_MAX / 2u) {
        count *= 2u;
    }
    return count;
}

static char *copy_string(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    const size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, len + 1u);
    return copy;
}

static uint64_t dns_now_ms(dns_libuv_impl_t *impl)
{
    if (impl == NULL || impl->loop == NULL) {
        return 0u;
    }
    uv_update_time(impl->loop);
    return uv_now(impl->loop);
}

static uint64_t dns_deadline(uint64_t now, uint64_t ttl)
{
    return ttl > UINT64_MAX - now ? UINT64_MAX : now + ttl;
}

static void cache_entry_free(dns_cache_entry_t *entry)
{
    if (entry == NULL) {
        return;
    }
    free(entry->host);
    free(entry->addresses);
    free(entry);
}

static void cache_clear(dns_libuv_impl_t *impl)
{
    if (impl == NULL) {
        return;
    }
    dns_cache_entry_t *entry = impl->cache;
    while (entry != NULL) {
        dns_cache_entry_t *next = entry->next;
        cache_entry_free(entry);
        entry = next;
    }
    impl->cache = NULL;
    impl->cache_tail = NULL;
    impl->cache_count = 0u;
    if (impl->cache_buckets != NULL) {
        memset(impl->cache_buckets, 0,
               impl->cache_bucket_count * sizeof(*impl->cache_buckets));
    }
}

static int cache_key_equal(const dns_cache_entry_t *entry,
                           const char *host,
                           uint16_t port)
{
    return entry != NULL && host != NULL && entry->port == port &&
           strcmp(entry->host, host) == 0;
}

static void cache_remove(dns_libuv_impl_t *impl, dns_cache_entry_t *entry)
{
    if (impl == NULL || entry == NULL) {
        return;
    }
    if (entry->prev != NULL) {
        entry->prev->next = entry->next;
    } else {
        impl->cache = entry->next;
    }
    if (entry->next != NULL) {
        entry->next->prev = entry->prev;
    } else {
        impl->cache_tail = entry->prev;
    }
    const size_t bucket = (size_t)entry->hash &
                          (impl->cache_bucket_count - 1u);
    dns_cache_entry_t **cursor = &impl->cache_buckets[bucket];
    while (*cursor != NULL && *cursor != entry) {
        cursor = &(*cursor)->hash_next;
    }
    if (*cursor == entry) {
        *cursor = entry->hash_next;
    }
    if (impl->cache_count > 0u) {
        impl->cache_count--;
    }
    cache_entry_free(entry);
}

static dns_cache_entry_t *cache_lookup(dns_libuv_impl_t *impl,
                                       const char *host,
                                       uint16_t port)
{
    if (impl == NULL || impl->max_cache_entries == 0u || host == NULL) {
        return NULL;
    }

    const uint64_t now = dns_now_ms(impl);
    const uint64_t hash = dns_key_hash(host, port);
    const size_t bucket = (size_t)hash & (impl->cache_bucket_count - 1u);
    for (dns_cache_entry_t *entry = impl->cache_buckets[bucket]; entry != NULL;
         entry = entry->hash_next) {
        if (entry->hash != hash || !cache_key_equal(entry, host, port)) {
            continue;
        }
        if (entry->expires_at_ms != UINT64_MAX && now >= entry->expires_at_ms) {
            cache_remove(impl, entry);
            return NULL;
        }
        if (entry != impl->cache) {
            if (entry->prev != NULL) {
                entry->prev->next = entry->next;
            }
            if (entry->next != NULL) {
                entry->next->prev = entry->prev;
            } else {
                impl->cache_tail = entry->prev;
            }
            entry->prev = NULL;
            entry->next = impl->cache;
            impl->cache->prev = entry;
            impl->cache = entry;
        }
        return entry;
    }
    return NULL;
}

static void cache_evict_tail(dns_libuv_impl_t *impl)
{
    if (impl == NULL || impl->cache == NULL) {
        return;
    }
    cache_remove(impl, impl->cache_tail);
}

static void cache_store_result(dns_libuv_impl_t *impl,
                               const char *host,
                               uint16_t port,
                               int status,
                               const aproxy_addr_t *addresses,
                               size_t count)
{
    if (impl == NULL || impl->max_cache_entries == 0u || host == NULL) {
        return;
    }
    if (status == APROXY_OK) {
        if (addresses == NULL || count == 0u) {
            return;
        }
    } else if (impl->negative_cache_ttl_ms == 0u) {
        return;
    }

    aproxy_addr_t *copy = NULL;
    if (status == APROXY_OK) {
        copy = (aproxy_addr_t *)malloc(sizeof(*copy) * count);
        if (copy == NULL) {
            return;
        }
        memcpy(copy, addresses, sizeof(*copy) * count);
    }

    dns_cache_entry_t *entry = cache_lookup(impl, host, port);
    if (entry == NULL) {
        entry = (dns_cache_entry_t *)calloc(1u, sizeof(*entry));
        if (entry == NULL) {
            free(copy);
            return;
        }
        entry->host = copy_string(host);
        if (entry->host == NULL) {
            free(copy);
            cache_entry_free(entry);
            return;
        }
        entry->port = port;
        entry->hash = dns_key_hash(host, port);
        entry->prev = NULL;
        entry->next = impl->cache;
        if (impl->cache != NULL) {
            impl->cache->prev = entry;
        } else {
            impl->cache_tail = entry;
        }
        impl->cache = entry;
        const size_t bucket = (size_t)entry->hash &
                              (impl->cache_bucket_count - 1u);
        entry->hash_next = impl->cache_buckets[bucket];
        impl->cache_buckets[bucket] = entry;
        impl->cache_count++;
    }

    free(entry->addresses);
    entry->status = status;
    entry->addresses = copy;
    entry->count = status == APROXY_OK ? count : 0u;
    if (status == APROXY_OK) {
        entry->expires_at_ms =
            impl->cache_ttl_ms == 0u
                ? UINT64_MAX
                : dns_deadline(dns_now_ms(impl), impl->cache_ttl_ms);
    } else {
        entry->expires_at_ms = dns_deadline(dns_now_ms(impl),
                                             impl->negative_cache_ttl_ms);
    }

    while (impl->cache_count > impl->max_cache_entries) {
        cache_evict_tail(impl);
    }
}

static void request_add(dns_libuv_impl_t *impl, dns_request_t *request)
{
    if (impl == NULL || request == NULL) {
        return;
    }
    request->prev = NULL;
    request->next = impl->requests;
    if (impl->requests != NULL) {
        impl->requests->prev = request;
    }
    impl->requests = request;
    const size_t bucket = (size_t)request->hash &
                          (impl->request_bucket_count - 1u);
    request->hash_next = impl->request_buckets[bucket];
    impl->request_buckets[bucket] = request;
    impl->request_count++;
}

static void request_remove(dns_libuv_impl_t *impl, dns_request_t *request)
{
    if (impl == NULL || request == NULL) {
        return;
    }
    if (request->prev != NULL) {
        request->prev->next = request->next;
    } else if (impl->requests == request) {
        impl->requests = request->next;
    }
    if (request->next != NULL) {
        request->next->prev = request->prev;
    }
    const size_t bucket = (size_t)request->hash &
                          (impl->request_bucket_count - 1u);
    dns_request_t **cursor = &impl->request_buckets[bucket];
    while (*cursor != NULL && *cursor != request) {
        cursor = &(*cursor)->hash_next;
    }
    if (*cursor == request) {
        *cursor = request->hash_next;
    }
    if (impl->request_count > 0u) {
        impl->request_count--;
    }
    request->prev = NULL;
    request->next = NULL;
    request->hash_next = NULL;
}

static dns_request_t *request_find(dns_libuv_impl_t *impl,
                                   const char *host,
                                   uint16_t port)
{
    if (impl == NULL || host == NULL) {
        return NULL;
    }
    const uint64_t hash = dns_key_hash(host, port);
    const size_t bucket = (size_t)hash & (impl->request_bucket_count - 1u);
    for (dns_request_t *request = impl->request_buckets[bucket];
         request != NULL; request = request->hash_next) {
        if (request->hash == hash && request->port == port &&
            strcmp(request->host, host) == 0) {
            return request;
        }
    }
    return NULL;
}

static void dns_libuv_impl_free_now(dns_libuv_impl_t *impl)
{
    if (impl == NULL) {
        return;
    }
    cache_clear(impl);
    free(impl->cache_buckets);
    free(impl->request_buckets);
    free(impl);
}

static int request_add_waiter(dns_libuv_impl_t *impl,
                              dns_request_t *request,
                              aproxy_dns_result_cb cb,
                              void *user_data)
{
    if (impl == NULL || request == NULL || cb == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (request->waiter_count >= impl->max_waiters_per_request) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    dns_waiter_t *waiter = (dns_waiter_t *)calloc(1u, sizeof(*waiter));
    if (waiter == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    waiter->cb = cb;
    waiter->user_data = user_data;
    if (request->waiter_tail != NULL) {
        request->waiter_tail->next = waiter;
    } else {
        request->waiters = waiter;
    }
    request->waiter_tail = waiter;
    request->waiter_count++;
    return APROXY_OK;
}

static int sockaddr_to_addr(const struct sockaddr *sa, aproxy_addr_t *out)
{
    if (sa == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *addr = (const struct sockaddr_in *)sa;
        uint8_t ip[4];
        memcpy(ip, &addr->sin_addr.s_addr, sizeof(ip));
        aproxy_addr_set_ipv4(out, ip, ntohs(addr->sin_port));
        return APROXY_OK;
    }
    if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *addr = (const struct sockaddr_in6 *)sa;
        uint8_t ip[16];
        memcpy(ip, &addr->sin6_addr, sizeof(ip));
        aproxy_addr_set_ipv6(out, ip, ntohs(addr->sin6_port));
        return APROXY_OK;
    }
    return APROXY_ERR_UNSUPPORTED;
}

static size_t count_supported_addrinfo(const struct addrinfo *result)
{
    size_t count = 0u;
    for (const struct addrinfo *ai = result; ai != NULL; ai = ai->ai_next) {
        if (ai->ai_addr != NULL &&
            (ai->ai_addr->sa_family == AF_INET ||
             ai->ai_addr->sa_family == AF_INET6)) {
            count++;
        }
    }
    return count;
}

static int addrinfo_to_addresses(const struct addrinfo *result,
                                 aproxy_addr_t **out_addresses,
                                 size_t *out_count)
{
    if (out_addresses == NULL || out_count == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out_addresses = NULL;
    *out_count = 0u;

    const size_t supported = count_supported_addrinfo(result);
    if (supported == 0u) {
        return APROXY_ERR_PARSE;
    }

    aproxy_addr_t *addresses =
        (aproxy_addr_t *)calloc(supported, sizeof(*addresses));
    if (addresses == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }

    size_t count = 0u;
    for (const struct addrinfo *ai = result; ai != NULL; ai = ai->ai_next) {
        if (sockaddr_to_addr(ai->ai_addr, &addresses[count]) == APROXY_OK) {
            count++;
        }
    }
    if (count == 0u) {
        free(addresses);
        return APROXY_ERR_PARSE;
    }
    *out_addresses = addresses;
    *out_count = count;
    return APROXY_OK;
}

static void request_free(dns_request_t *request)
{
    if (request == NULL) {
        return;
    }
    dns_waiter_t *waiter = request->waiters;
    while (waiter != NULL) {
        dns_waiter_t *next = waiter->next;
        free(waiter);
        waiter = next;
    }
    free(request->host);
    free(request);
}

static void dns_getaddrinfo_cb(uv_getaddrinfo_t *req,
                               int status,
                               struct addrinfo *result)
{
    dns_request_t *request = (dns_request_t *)req->data;
    dns_libuv_impl_t *impl = request == NULL ? NULL : request->impl;
    if (impl != NULL) {
        request_remove(impl, request);
    }

    aproxy_addr_t *addresses = NULL;
    size_t count = 0u;
    int cb_status = status == 0 ? APROXY_OK : status;
    if (status == 0) {
        cb_status = addrinfo_to_addresses(result, &addresses, &count);
    }
    if (result != NULL) {
        uv_freeaddrinfo(result);
    }

    const int should_callback =
        impl != NULL && !impl->closing && impl->owner != NULL &&
        request != NULL && request->waiters != NULL;
    if (should_callback) {
        cache_store_result(impl, request->host, request->port, cb_status,
                           addresses, count);
    }

    if (should_callback) {
        impl->callback_depth++;
        dns_waiter_t *waiter = request->waiters;
        while (waiter != NULL && !impl->closing && impl->owner != NULL) {
            waiter->cb(impl->owner, cb_status, addresses, count,
                       waiter->user_data);
            waiter = waiter->next;
        }
        impl->callback_depth--;
    }
    const int free_impl = impl != NULL && impl->closing &&
                          impl->requests == NULL &&
                          impl->callback_depth == 0;
    free(addresses);
    request_free(request);
    if (free_impl) {
        dns_libuv_impl_free_now(impl);
    }
}

static int dns_libuv_resolve(void *impl_ptr,
                             const char *host,
                             uint16_t port,
                             aproxy_dns_result_cb cb,
                             void *user_data)
{
    dns_libuv_impl_t *impl = (dns_libuv_impl_t *)impl_ptr;
    if (impl == NULL || host == NULL || cb == NULL || impl->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }

    dns_cache_entry_t *cached = cache_lookup(impl, host, port);
    if (cached != NULL) {
        cb(impl->owner, cached->status, cached->addresses, cached->count,
           user_data);
        return APROXY_OK;
    }

    dns_request_t *existing = request_find(impl, host, port);
    if (existing != NULL) {
        return request_add_waiter(impl, existing, cb, user_data);
    }
    if (impl->request_count >= impl->max_pending_requests) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }

    dns_request_t *request =
        (dns_request_t *)calloc(1u, sizeof(*request));
    if (request == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    request->impl = impl;
    request->host = copy_string(host);
    request->port = port;
    request->hash = dns_key_hash(host, port);
    request->req.data = request;
    if (request->host == NULL ||
        request_add_waiter(impl, request, cb, user_data) != APROXY_OK) {
        request_free(request);
        return APROXY_ERR_NO_MEMORY;
    }

    char service[6];
    (void)snprintf(service, sizeof(service), "%u", (unsigned)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    const int rc = uv_getaddrinfo(impl->loop, &request->req,
                                  dns_getaddrinfo_cb, request->host,
                                  service, &hints);
    if (rc != 0) {
        request_free(request);
        return rc;
    }
    request_add(impl, request);
    return APROXY_OK;
}

static void dns_libuv_free(void *impl_ptr)
{
    dns_libuv_impl_t *impl = (dns_libuv_impl_t *)impl_ptr;
    if (impl == NULL) {
        return;
    }
    impl->closing = 1;
    impl->owner = NULL;
    cache_clear(impl);
    for (dns_request_t *request = impl->requests; request != NULL;
         request = request->next) {
        (void)uv_cancel((uv_req_t *)&request->req);
    }
    if (impl->requests == NULL && impl->callback_depth == 0) {
        dns_libuv_impl_free_now(impl);
    }
}

static const aproxy_dns_resolver_vtable_t dns_libuv_vtable = {
    .resolve = dns_libuv_resolve,
    .free = dns_libuv_free,
};

int aproxy_dns_resolve(aproxy_dns_resolver_t *resolver,
                       const char *host,
                       uint16_t port,
                       aproxy_dns_result_cb cb,
                       void *user_data)
{
    if (resolver == NULL || resolver->vtable == NULL ||
        resolver->vtable->resolve == NULL || host == NULL || cb == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    return resolver->vtable->resolve(resolver->impl, host, port, cb,
                                     user_data);
}

void aproxy_dns_resolver_free(aproxy_dns_resolver_t *resolver)
{
    if (resolver == NULL) {
        return;
    }
    if (resolver->vtable != NULL && resolver->vtable->free != NULL) {
        resolver->vtable->free(resolver->impl);
    }
    free(resolver);
}

int aproxy_dns_resolver_new_libuv(const aproxy_dns_libuv_config_t *config,
                                  aproxy_dns_resolver_t **out)
{
    if (config == NULL || config->loop == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    aproxy_dns_resolver_t *resolver =
        (aproxy_dns_resolver_t *)calloc(1u, sizeof(*resolver));
    if (resolver == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    dns_libuv_impl_t *impl =
        (dns_libuv_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        free(resolver);
        return APROXY_ERR_NO_MEMORY;
    }

    impl->loop = config->loop;
    impl->owner = resolver;
    impl->max_cache_entries = config->max_cache_entries;
    impl->cache_ttl_ms = config->cache_ttl_ms;
    impl->negative_cache_ttl_ms = config->negative_cache_ttl_ms;
    impl->max_pending_requests =
        config->max_pending_requests == 0u
            ? APROXY_DNS_DEFAULT_MAX_PENDING_REQUESTS
            : config->max_pending_requests;
    impl->max_waiters_per_request =
        config->max_waiters_per_request == 0u
            ? APROXY_DNS_DEFAULT_MAX_WAITERS_PER_REQUEST
            : config->max_waiters_per_request;
    impl->cache_bucket_count = dns_bucket_count(
        config->max_cache_entries > SIZE_MAX / 2u
            ? config->max_cache_entries
            : config->max_cache_entries * 2u);
    impl->request_bucket_count = DNS_INITIAL_REQUEST_BUCKETS;
    impl->cache_buckets = (dns_cache_entry_t **)calloc(
        impl->cache_bucket_count, sizeof(*impl->cache_buckets));
    impl->request_buckets = (dns_request_t **)calloc(
        impl->request_bucket_count, sizeof(*impl->request_buckets));
    if (impl->cache_buckets == NULL || impl->request_buckets == NULL) {
        free(impl->cache_buckets);
        free(impl->request_buckets);
        free(impl);
        free(resolver);
        return APROXY_ERR_NO_MEMORY;
    }

    resolver->vtable = &dns_libuv_vtable;
    resolver->impl = impl;
    *out = resolver;
    return APROXY_OK;
}
