#include "aproxy/router.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

typedef enum aproxy_route_rule_type {
    APROXY_ROUTE_DOMAIN_SUFFIX,
    APROXY_ROUTE_DOMAIN_EXACT,
    APROXY_ROUTE_IPV4_CIDR,
    APROXY_ROUTE_IPV6_CIDR,
    APROXY_ROUTE_GEOIP,
    APROXY_ROUTE_GEOSITE
} aproxy_route_rule_type_t;

typedef struct aproxy_route_rule {
    aproxy_route_rule_type_t type;
    aproxy_outbound_t *outbound;
    int use_selected_proxy;
    union {
        struct {
            char *value;
            size_t len;
        } domain;
        struct {
            uint8_t network[16];
            uint8_t prefix_len;
        } cidr;
        const aproxy_geoip_set_t *geoip;
        const aproxy_geosite_set_t *geosite;
    } match;
} aproxy_route_rule_t;

typedef struct domain_index_entry {
    const char *value;
    size_t len;
    uint64_t hash;
    size_t rule_index_plus_one;
} domain_index_entry_t;

typedef struct domain_index {
    domain_index_entry_t *entries;
    size_t count;
    size_t capacity;
} domain_index_t;

typedef struct cidr_index_node {
    uint32_t child[2];
    size_t rule_index_plus_one;
} cidr_index_node_t;

typedef struct cidr_index {
    cidr_index_node_t *nodes;
    size_t count;
    size_t capacity;
} cidr_index_t;

typedef struct router_profile {
    char *id;
    struct aproxy_router *router;
} router_profile_t;

struct aproxy_router {
    aproxy_outbound_t *default_outbound;
    aproxy_outbound_t *selected_proxy;
    int default_uses_selected_proxy;
    aproxy_route_rule_t *rules;
    size_t rule_count;
    size_t rule_capacity;
    domain_index_t exact_index;
    domain_index_t suffix_index;
    cidr_index_t ipv4_index;
    cidr_index_t ipv6_index;
    size_t *geo_rule_indices;
    size_t geo_rule_count;
    size_t geo_rule_capacity;
    int needs_lower_domain;
    int has_ip_rules;
    router_profile_t *profiles;
    size_t profile_count;
    size_t profile_capacity;
    aproxy_router_t *active_profile;
    const char *active_profile_id;
};

#define DOMAIN_INDEX_INITIAL_CAPACITY 16u
#define CIDR_INDEX_NO_CHILD UINT32_MAX
#define DOMAIN_HASH_OFFSET UINT64_C(1469598103934665603)
#define DOMAIN_HASH_PRIME UINT64_C(1099511628211)
#define ROUTER_RECENT_RULE_SCAN 4u

static uint64_t domain_hash_reverse(const char *value, size_t len)
{
    uint64_t hash = DOMAIN_HASH_OFFSET;
    for (size_t i = len; i > 0u; i--) {
        hash ^= (uint8_t)value[i - 1u];
        hash *= DOMAIN_HASH_PRIME;
    }
    return hash;
}

static domain_index_entry_t *domain_index_find_slot(
    const domain_index_t *index,
    const char *value,
    size_t len,
    uint64_t hash)
{
    if (index->capacity == 0u) {
        return NULL;
    }
    const size_t mask = index->capacity - 1u;
    size_t position = (size_t)hash & mask;
    for (;;) {
        domain_index_entry_t *entry = &index->entries[position];
        if (entry->value == NULL ||
            (entry->hash == hash && entry->len == len &&
             memcmp(entry->value, value, len) == 0)) {
            return entry;
        }
        position = (position + 1u) & mask;
    }
}

static int domain_index_rehash(domain_index_t *index, size_t capacity)
{
    if (capacity < DOMAIN_INDEX_INITIAL_CAPACITY ||
        (capacity & (capacity - 1u)) != 0u ||
        capacity > SIZE_MAX / sizeof(*index->entries)) {
        return APROXY_ERR_NO_MEMORY;
    }
    domain_index_entry_t *entries =
        (domain_index_entry_t *)calloc(capacity, sizeof(*entries));
    if (entries == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    domain_index_entry_t *old_entries = index->entries;
    const size_t old_capacity = index->capacity;
    index->entries = entries;
    index->capacity = capacity;
    index->count = 0u;
    for (size_t i = 0u; i < old_capacity; i++) {
        const domain_index_entry_t *old = &old_entries[i];
        if (old->value == NULL) {
            continue;
        }
        domain_index_entry_t *entry = domain_index_find_slot(
            index, old->value, old->len, old->hash);
        *entry = *old;
        index->count++;
    }
    free(old_entries);
    return APROXY_OK;
}

static int domain_index_insert(domain_index_t *index,
                               const char *value,
                               size_t len,
                               size_t rule_index)
{
    if (index->capacity == 0u ||
        index->count + 1u >
            index->capacity - index->capacity / 4u) {
        if (index->capacity > SIZE_MAX / 2u) {
            return APROXY_ERR_NO_MEMORY;
        }
        const size_t capacity = index->capacity == 0u
                                    ? DOMAIN_INDEX_INITIAL_CAPACITY
                                    : index->capacity * 2u;
        const int rc = domain_index_rehash(index, capacity);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    const uint64_t hash = domain_hash_reverse(value, len);
    domain_index_entry_t *entry =
        domain_index_find_slot(index, value, len, hash);
    if (entry->value == NULL) {
        entry->value = value;
        entry->len = len;
        entry->hash = hash;
        index->count++;
    }
    entry->rule_index_plus_one = rule_index + 1u;
    return APROXY_OK;
}

static size_t domain_index_lookup(const domain_index_t *index,
                                  const char *value,
                                  size_t len,
                                  uint64_t hash)
{
    domain_index_entry_t *entry =
        domain_index_find_slot(index, value, len, hash);
    return entry == NULL || entry->value == NULL
               ? 0u
               : entry->rule_index_plus_one;
}

static size_t suffix_index_lookup(const domain_index_t *index,
                                  const char *value,
                                  size_t len)
{
    uint64_t hash = DOMAIN_HASH_OFFSET;
    size_t best = 0u;
    for (size_t i = len; i > 0u; i--) {
        hash ^= (uint8_t)value[i - 1u];
        hash *= DOMAIN_HASH_PRIME;
        const size_t candidate =
            domain_index_lookup(index, value + i - 1u, len - i + 1u, hash);
        if (candidate > best) {
            best = candidate;
        }
    }
    return best;
}

static int cidr_index_reserve(cidr_index_t *index, size_t need)
{
    if (need <= index->capacity) {
        return APROXY_OK;
    }
    size_t capacity = index->capacity == 0u ? 64u : index->capacity;
    while (capacity < need) {
        if (capacity > SIZE_MAX / 2u) {
            return APROXY_ERR_NO_MEMORY;
        }
        capacity *= 2u;
    }
    if (capacity > UINT32_MAX ||
        capacity > SIZE_MAX / sizeof(*index->nodes)) {
        return APROXY_ERR_NO_MEMORY;
    }
    cidr_index_node_t *nodes = (cidr_index_node_t *)realloc(
        index->nodes, capacity * sizeof(*index->nodes));
    if (nodes == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    index->nodes = nodes;
    index->capacity = capacity;
    return APROXY_OK;
}

static int cidr_index_add_node(cidr_index_t *index, uint32_t *out)
{
    const int rc = cidr_index_reserve(index, index->count + 1u);
    if (rc != APROXY_OK) {
        return rc;
    }
    cidr_index_node_t *node = &index->nodes[index->count];
    node->child[0] = CIDR_INDEX_NO_CHILD;
    node->child[1] = CIDR_INDEX_NO_CHILD;
    node->rule_index_plus_one = 0u;
    *out = (uint32_t)index->count++;
    return APROXY_OK;
}

static int cidr_index_insert(cidr_index_t *index,
                             const uint8_t *network,
                             uint8_t prefix_len,
                             size_t rule_index)
{
    uint32_t node_index = 0u;
    if (index->count == 0u) {
        int rc = cidr_index_add_node(index, &node_index);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    for (uint8_t bit = 0u; bit < prefix_len; bit++) {
        const unsigned int branch =
            (network[bit / 8u] >> (7u - (bit % 8u))) & 1u;
        uint32_t child = index->nodes[node_index].child[branch];
        if (child == CIDR_INDEX_NO_CHILD) {
            int rc = cidr_index_add_node(index, &child);
            if (rc != APROXY_OK) {
                return rc;
            }
            index->nodes[node_index].child[branch] = child;
        }
        node_index = child;
    }
    index->nodes[node_index].rule_index_plus_one = rule_index + 1u;
    return APROXY_OK;
}

static size_t cidr_index_lookup(const cidr_index_t *index,
                                const uint8_t *address,
                                size_t bit_count)
{
    if (index->count == 0u) {
        return 0u;
    }
    uint32_t node_index = 0u;
    size_t best = index->nodes[0].rule_index_plus_one;
    for (size_t bit = 0u; bit < bit_count; bit++) {
        const unsigned int branch =
            (address[bit / 8u] >> (7u - (bit % 8u))) & 1u;
        node_index = index->nodes[node_index].child[branch];
        if (node_index == CIDR_INDEX_NO_CHILD) {
            break;
        }
        if (index->nodes[node_index].rule_index_plus_one > best) {
            best = index->nodes[node_index].rule_index_plus_one;
        }
    }
    return best;
}

static int append_geo_rule_index(aproxy_router_t *router, size_t rule_index)
{
    if (router->geo_rule_count == router->geo_rule_capacity) {
        size_t capacity = router->geo_rule_capacity == 0u
                              ? 8u
                              : router->geo_rule_capacity * 2u;
        if (capacity < router->geo_rule_capacity ||
            capacity > SIZE_MAX / sizeof(*router->geo_rule_indices)) {
            return APROXY_ERR_NO_MEMORY;
        }
        size_t *indices = (size_t *)realloc(
            router->geo_rule_indices, capacity * sizeof(*indices));
        if (indices == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        router->geo_rule_indices = indices;
        router->geo_rule_capacity = capacity;
    }
    router->geo_rule_indices[router->geo_rule_count++] = rule_index;
    return APROXY_OK;
}

static char *copy_domain_lower(const char *s, size_t *out_len)
{
    const size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    for (size_t i = 0u; i < len; i++) {
        const unsigned char c = (unsigned char)s[i];
        copy[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    copy[len] = '\0';
    *out_len = len;
    return copy;
}

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

static int has_suffix_lower(const char *value,
                            size_t value_len,
                            const char *suffix,
                            size_t suffix_len)
{
    if (suffix_len > value_len) {
        return 0;
    }
    return memcmp(value + value_len - suffix_len, suffix, suffix_len) == 0;
}

static int domain_exact_lower(const char *value,
                              size_t value_len,
                              const char *domain,
                              size_t domain_len)
{
    return value_len == domain_len &&
           memcmp(value, domain, domain_len) == 0;
}

static int cidr_match(const uint8_t *addr,
                      const uint8_t *network,
                      size_t bytes,
                      uint8_t prefix_len)
{
    if (addr == NULL || network == NULL || prefix_len > bytes * 8u) {
        return 0;
    }
    const size_t full_bytes = prefix_len / 8u;
    const uint8_t rem_bits = (uint8_t)(prefix_len % 8u);
    if (full_bytes > 0u && memcmp(addr, network, full_bytes) != 0) {
        return 0;
    }
    if (rem_bits == 0u) {
        return 1;
    }
    const uint8_t mask = (uint8_t)(0xffu << (8u - rem_bits));
    return (addr[full_bytes] & mask) == (network[full_bytes] & mask);
}

static int rule_matches(const aproxy_route_rule_t *rule,
                        const aproxy_addr_t *destination,
                        const char *lower_domain)
{
    if (rule == NULL || destination == NULL) {
        return 0;
    }
    switch (rule->type) {
    case APROXY_ROUTE_DOMAIN_SUFFIX:
        return lower_domain != NULL &&
               has_suffix_lower(lower_domain, destination->fqdn_len,
                                rule->match.domain.value,
                                rule->match.domain.len);
    case APROXY_ROUTE_DOMAIN_EXACT:
        return lower_domain != NULL &&
               domain_exact_lower(lower_domain, destination->fqdn_len,
                                  rule->match.domain.value,
                                  rule->match.domain.len);
    case APROXY_ROUTE_IPV4_CIDR:
        return destination->family == APROXY_ADDR_IPV4 &&
               cidr_match(destination->addr, rule->match.cidr.network, 4u,
                          rule->match.cidr.prefix_len);
    case APROXY_ROUTE_IPV6_CIDR:
        return destination->family == APROXY_ADDR_IPV6 &&
               cidr_match(destination->addr, rule->match.cidr.network, 16u,
                          rule->match.cidr.prefix_len);
    case APROXY_ROUTE_GEOIP:
        return aproxy_geoip_set_match(rule->match.geoip, destination);
    case APROXY_ROUTE_GEOSITE:
        return destination->family == APROXY_ADDR_FQDN &&
               lower_domain != NULL &&
               aproxy_geosite_set_match_domain_lower(
                   rule->match.geosite, lower_domain,
                   destination->fqdn_len);
    default:
        return 0;
    }
}

static void rule_destroy(aproxy_route_rule_t *rule)
{
    if (rule == NULL) {
        return;
    }
    if (rule->type == APROXY_ROUTE_DOMAIN_SUFFIX ||
        rule->type == APROXY_ROUTE_DOMAIN_EXACT) {
        free(rule->match.domain.value);
    }
}

static int router_append_rule(aproxy_router_t *router,
                              const aproxy_route_rule_t *rule)
{
    if (router == NULL || rule == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (router->rule_count == router->rule_capacity) {
        size_t next = router->rule_capacity == 0u
                          ? 16u
                          : router->rule_capacity * 2u;
        if (next < router->rule_capacity ||
            next > SIZE_MAX / sizeof(*router->rules)) {
            return APROXY_ERR_NO_MEMORY;
        }
        aproxy_route_rule_t *rules = (aproxy_route_rule_t *)realloc(
            router->rules, next * sizeof(*router->rules));
        if (rules == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        router->rules = rules;
        router->rule_capacity = next;
    }
    const size_t rule_index = router->rule_count;
    router->rules[router->rule_count++] = *rule;
    int rc = APROXY_OK;
    switch (rule->type) {
    case APROXY_ROUTE_DOMAIN_EXACT:
        rc = domain_index_insert(&router->exact_index,
                                 rule->match.domain.value,
                                 rule->match.domain.len, rule_index);
        break;
    case APROXY_ROUTE_DOMAIN_SUFFIX:
        rc = domain_index_insert(&router->suffix_index,
                                 rule->match.domain.value,
                                 rule->match.domain.len, rule_index);
        break;
    case APROXY_ROUTE_IPV4_CIDR:
        rc = cidr_index_insert(&router->ipv4_index,
                               rule->match.cidr.network,
                               rule->match.cidr.prefix_len, rule_index);
        break;
    case APROXY_ROUTE_IPV6_CIDR:
        rc = cidr_index_insert(&router->ipv6_index,
                               rule->match.cidr.network,
                               rule->match.cidr.prefix_len, rule_index);
        break;
    case APROXY_ROUTE_GEOIP:
    case APROXY_ROUTE_GEOSITE:
        rc = append_geo_rule_index(router, rule_index);
        break;
    default:
        rc = APROXY_ERR_INVALID_ARGUMENT;
        break;
    }
    if (rc != APROXY_OK) {
        router->rule_count--;
        return rc;
    }
    if (rule->type == APROXY_ROUTE_DOMAIN_SUFFIX ||
        rule->type == APROXY_ROUTE_DOMAIN_EXACT ||
        rule->type == APROXY_ROUTE_GEOSITE) {
        router->needs_lower_domain = 1;
    }
    if (rule->type == APROXY_ROUTE_IPV4_CIDR ||
        rule->type == APROXY_ROUTE_IPV6_CIDR ||
        rule->type == APROXY_ROUTE_GEOIP) {
        router->has_ip_rules = 1;
    }
    return APROXY_OK;
}

int aproxy_router_new(aproxy_router_t **out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_router_t *router = (aproxy_router_t *)calloc(1u, sizeof(*router));
    if (router == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    *out = router;
    return APROXY_OK;
}

void aproxy_router_free(aproxy_router_t *router)
{
    if (router == NULL) {
        return;
    }
    for (size_t i = 0u; i < router->rule_count; i++) {
        rule_destroy(&router->rules[i]);
    }
    free(router->exact_index.entries);
    free(router->suffix_index.entries);
    free(router->ipv4_index.nodes);
    free(router->ipv6_index.nodes);
    free(router->geo_rule_indices);
    free(router->rules);
    for (size_t i = 0u; i < router->profile_count; i++) {
        free(router->profiles[i].id);
        aproxy_router_free(router->profiles[i].router);
    }
    free(router->profiles);
    free(router);
}

void aproxy_router_compact(aproxy_router_t *router)
{
    if (router == NULL) {
        return;
    }
    for (size_t i = 0u; i < router->profile_count; i++) {
        aproxy_router_compact(router->profiles[i].router);
    }
    if (router->rule_count == 0u) {
        free(router->rules);
        router->rules = NULL;
        router->rule_capacity = 0u;
    } else if (router->rule_count < router->rule_capacity) {
        aproxy_route_rule_t *rules = (aproxy_route_rule_t *)realloc(
            router->rules, router->rule_count * sizeof(*router->rules));
        if (rules != NULL) {
            router->rules = rules;
            router->rule_capacity = router->rule_count;
        }
    }

    if (router->geo_rule_count == 0u) {
        free(router->geo_rule_indices);
        router->geo_rule_indices = NULL;
        router->geo_rule_capacity = 0u;
    } else if (router->geo_rule_count < router->geo_rule_capacity) {
        size_t *indices = (size_t *)realloc(
            router->geo_rule_indices,
            router->geo_rule_count * sizeof(*router->geo_rule_indices));
        if (indices != NULL) {
            router->geo_rule_indices = indices;
            router->geo_rule_capacity = router->geo_rule_count;
        }
    }

    cidr_index_t *indices[] = {
        &router->ipv4_index,
        &router->ipv6_index,
    };
    for (size_t i = 0u; i < sizeof(indices) / sizeof(indices[0]); i++) {
        cidr_index_t *index = indices[i];
        if (index->count == 0u) {
            free(index->nodes);
            index->nodes = NULL;
            index->capacity = 0u;
        } else if (index->count < index->capacity) {
            cidr_index_node_t *nodes = (cidr_index_node_t *)realloc(
                index->nodes, index->count * sizeof(*index->nodes));
            if (nodes != NULL) {
                index->nodes = nodes;
                index->capacity = index->count;
            }
        }
    }
}

int aproxy_router_set_default(aproxy_router_t *router,
                              aproxy_outbound_t *outbound)
{
    if (router == NULL || outbound == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    router->default_outbound = outbound;
    router->default_uses_selected_proxy = 0;
    return APROXY_OK;
}

int aproxy_router_set_selected_proxy(aproxy_router_t *router,
                                     aproxy_outbound_t *outbound)
{
    if (router == NULL || outbound == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    router->selected_proxy = outbound;
    return APROXY_OK;
}

int aproxy_router_set_default_proxy(aproxy_router_t *router)
{
    if (router == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    router->default_outbound = NULL;
    router->default_uses_selected_proxy = 1;
    return APROXY_OK;
}

int aproxy_router_add_profile(aproxy_router_t *router,
                              const char *profile_id,
                              aproxy_router_t *profile)
{
    if (router == NULL || profile_id == NULL || profile_id[0] == '\0' ||
        profile == NULL || profile == router || profile->profile_count != 0u) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    for (size_t i = 0u; i < router->profile_count; i++) {
        if (strcmp(router->profiles[i].id, profile_id) == 0) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
    }
    if (router->profile_count == router->profile_capacity) {
        size_t capacity = router->profile_capacity == 0u
                              ? 4u
                              : router->profile_capacity * 2u;
        if (capacity < router->profile_capacity ||
            capacity > SIZE_MAX / sizeof(*router->profiles)) {
            return APROXY_ERR_NO_MEMORY;
        }
        router_profile_t *profiles = (router_profile_t *)realloc(
            router->profiles, capacity * sizeof(*router->profiles));
        if (profiles == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        router->profiles = profiles;
        router->profile_capacity = capacity;
    }
    char *id = copy_string(profile_id);
    if (id == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    router_profile_t *entry = &router->profiles[router->profile_count++];
    entry->id = id;
    entry->router = profile;
    return APROXY_OK;
}

int aproxy_router_select_profile(aproxy_router_t *router,
                                 const char *profile_id)
{
    if (router == NULL || profile_id == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    for (size_t i = 0u; i < router->profile_count; i++) {
        router_profile_t *entry = &router->profiles[i];
        if (strcmp(entry->id, profile_id) == 0) {
            router->active_profile = entry->router;
            router->active_profile_id = entry->id;
            return APROXY_OK;
        }
    }
    return APROXY_ERR_INVALID_ARGUMENT;
}

const char *aproxy_router_active_profile(const aproxy_router_t *router)
{
    return router == NULL ? NULL : router->active_profile_id;
}

static int router_add_domain(aproxy_router_t *router,
                             const char *domain,
                             aproxy_outbound_t *outbound,
                             int use_selected_proxy,
                             aproxy_route_rule_type_t type)
{
    if (router == NULL || domain == NULL || domain[0] == '\0' ||
        (!use_selected_proxy && outbound == NULL)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_route_rule_t rule = {0};
    rule.type = type;
    rule.match.domain.value =
        copy_domain_lower(domain, &rule.match.domain.len);
    if (rule.match.domain.value == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    rule.outbound = outbound;
    rule.use_selected_proxy = use_selected_proxy;
    const int rc = router_append_rule(router, &rule);
    if (rc != APROXY_OK) {
        rule_destroy(&rule);
    }
    return rc;
}

int aproxy_router_add_domain_suffix(aproxy_router_t *router,
                                    const char *suffix,
                                    aproxy_outbound_t *outbound)
{
    return router_add_domain(router, suffix, outbound, 0,
                             APROXY_ROUTE_DOMAIN_SUFFIX);
}

int aproxy_router_add_domain_suffix_proxy(aproxy_router_t *router,
                                          const char *suffix)
{
    return router_add_domain(router, suffix, NULL, 1,
                             APROXY_ROUTE_DOMAIN_SUFFIX);
}

int aproxy_router_add_domain_exact(aproxy_router_t *router,
                                   const char *domain,
                                   aproxy_outbound_t *outbound)
{
    return router_add_domain(router, domain, outbound, 0,
                             APROXY_ROUTE_DOMAIN_EXACT);
}

int aproxy_router_add_domain_exact_proxy(aproxy_router_t *router,
                                         const char *domain)
{
    return router_add_domain(router, domain, NULL, 1,
                             APROXY_ROUTE_DOMAIN_EXACT);
}

static int router_add_cidr(aproxy_router_t *router,
                           const uint8_t *network,
                           uint8_t prefix_len,
                           aproxy_outbound_t *outbound,
                           int use_selected_proxy,
                           int ipv6)
{
    const uint8_t maximum = ipv6 ? 128u : 32u;
    if (router == NULL || network == NULL || prefix_len > maximum ||
        (!use_selected_proxy && outbound == NULL)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_route_rule_t rule = {0};
    rule.type = ipv6 ? APROXY_ROUTE_IPV6_CIDR : APROXY_ROUTE_IPV4_CIDR;
    memcpy(rule.match.cidr.network, network, ipv6 ? 16u : 4u);
    rule.match.cidr.prefix_len = prefix_len;
    rule.outbound = outbound;
    rule.use_selected_proxy = use_selected_proxy;
    return router_append_rule(router, &rule);
}

int aproxy_router_add_ipv4_cidr(aproxy_router_t *router,
                                const uint8_t network[4],
                                uint8_t prefix_len,
                                aproxy_outbound_t *outbound)
{
    return router_add_cidr(router, network, prefix_len, outbound, 0, 0);
}

int aproxy_router_add_ipv4_cidr_proxy(aproxy_router_t *router,
                                      const uint8_t network[4],
                                      uint8_t prefix_len)
{
    return router_add_cidr(router, network, prefix_len, NULL, 1, 0);
}

int aproxy_router_add_ipv6_cidr(aproxy_router_t *router,
                                const uint8_t network[16],
                                uint8_t prefix_len,
                                aproxy_outbound_t *outbound)
{
    return router_add_cidr(router, network, prefix_len, outbound, 0, 1);
}

int aproxy_router_add_ipv6_cidr_proxy(aproxy_router_t *router,
                                      const uint8_t network[16],
                                      uint8_t prefix_len)
{
    return router_add_cidr(router, network, prefix_len, NULL, 1, 1);
}

static int router_add_geo(aproxy_router_t *router,
                          const void *set,
                          aproxy_outbound_t *outbound,
                          int use_selected_proxy,
                          int geosite)
{
    if (router == NULL || set == NULL ||
        (!use_selected_proxy && outbound == NULL)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_route_rule_t rule = {0};
    rule.type = geosite ? APROXY_ROUTE_GEOSITE : APROXY_ROUTE_GEOIP;
    if (geosite) {
        rule.match.geosite = (const aproxy_geosite_set_t *)set;
    } else {
        rule.match.geoip = (const aproxy_geoip_set_t *)set;
    }
    rule.outbound = outbound;
    rule.use_selected_proxy = use_selected_proxy;
    return router_append_rule(router, &rule);
}

int aproxy_router_add_geoip(aproxy_router_t *router,
                            const aproxy_geoip_set_t *set,
                            aproxy_outbound_t *outbound)
{
    return router_add_geo(router, set, outbound, 0, 0);
}

int aproxy_router_add_geoip_proxy(aproxy_router_t *router,
                                  const aproxy_geoip_set_t *set)
{
    return router_add_geo(router, set, NULL, 1, 0);
}

int aproxy_router_add_geosite(aproxy_router_t *router,
                              const aproxy_geosite_set_t *set,
                              aproxy_outbound_t *outbound)
{
    return router_add_geo(router, set, outbound, 0, 1);
}

int aproxy_router_add_geosite_proxy(aproxy_router_t *router,
                                    const aproxy_geosite_set_t *set)
{
    return router_add_geo(router, set, NULL, 1, 1);
}

static size_t router_pick_rule_index_plus_one(
    const aproxy_router_t *router,
    const aproxy_addr_t *destination,
    size_t minimum)
{
    char lower_domain[APROXY_ADDR_MAX_FQDN + 1u];
    const char *domain = NULL;
    if (destination->family == APROXY_ADDR_FQDN &&
        router->needs_lower_domain) {
        if (destination->fqdn_len > APROXY_ADDR_MAX_FQDN) {
            return minimum;
        }
        for (size_t i = 0u; i < destination->fqdn_len; i++) {
            const unsigned char c =
                (unsigned char)destination->fqdn[i];
            lower_domain[i] =
                (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
        }
        lower_domain[destination->fqdn_len] = '\0';
        domain = lower_domain;
    }
    const size_t indexed_limit =
        router->rule_count > ROUTER_RECENT_RULE_SCAN
            ? router->rule_count - ROUTER_RECENT_RULE_SCAN
            : 0u;
    for (size_t i = router->rule_count;
         i > indexed_limit && i > minimum;
         i--) {
        const aproxy_route_rule_t *rule = &router->rules[i - 1u];
        if (rule_matches(rule, destination, domain)) {
            return i;
        }
    }
    if (indexed_limit == 0u || minimum >= indexed_limit) {
        return minimum;
    }
    size_t candidate = 0u;
    if (domain != NULL &&
        (router->exact_index.count != 0u ||
         router->suffix_index.count != 0u)) {
        const size_t exact = domain_index_lookup(
            &router->exact_index, domain, destination->fqdn_len,
            domain_hash_reverse(domain, destination->fqdn_len));
        const size_t suffix = suffix_index_lookup(
            &router->suffix_index, domain, destination->fqdn_len);
        candidate = exact > suffix ? exact : suffix;
    } else if (destination->family == APROXY_ADDR_IPV4) {
        candidate = cidr_index_lookup(
            &router->ipv4_index, destination->addr, 32u);
    } else if (destination->family == APROXY_ADDR_IPV6) {
        candidate = cidr_index_lookup(
            &router->ipv6_index, destination->addr, 128u);
    }
    size_t best = minimum;
    if (candidate <= indexed_limit && candidate > best) {
        best = candidate;
    }
    for (size_t i = router->geo_rule_count; i > 0u; i--) {
        const size_t rule_index = router->geo_rule_indices[i - 1u];
        if (rule_index >= indexed_limit) {
            continue;
        }
        if (rule_index + 1u <= best) {
            break;
        }
        const aproxy_route_rule_t *rule = &router->rules[rule_index];
        if ((destination->family == APROXY_ADDR_FQDN &&
             rule->type == APROXY_ROUTE_GEOIP) ||
            (destination->family != APROXY_ADDR_FQDN &&
             rule->type == APROXY_ROUTE_GEOSITE)) {
            continue;
        }
        if (rule_matches(rule, destination, domain)) {
            best = rule_index + 1u;
            break;
        }
    }
    return best;
}

aproxy_outbound_t *aproxy_router_pick(const aproxy_router_t *router,
                                      const aproxy_addr_t *destination)
{
    if (router == NULL || destination == NULL) {
        return NULL;
    }
    const aproxy_router_t *table = router->active_profile != NULL
                                       ? router->active_profile
                                       : router;
    const size_t rule_index = router_pick_rule_index_plus_one(
        table, destination, 0u);
    if (rule_index == 0u) {
        return table->default_uses_selected_proxy
                   ? router->selected_proxy
                   : table->default_outbound;
    }
    const aproxy_route_rule_t *rule = &table->rules[rule_index - 1u];
    return rule->use_selected_proxy ? router->selected_proxy
                                    : rule->outbound;
}

int aproxy_router_needs_resolution(const aproxy_router_t *router,
                                   const aproxy_addr_t *destination)
{
    const aproxy_router_t *table =
        router != NULL && router->active_profile != NULL
            ? router->active_profile
            : router;
    return table != NULL && destination != NULL &&
           destination->family == APROXY_ADDR_FQDN &&
           table->has_ip_rules;
}

int aproxy_router_has_domain_rules(const aproxy_router_t *router)
{
    const aproxy_router_t *table =
        router != NULL && router->active_profile != NULL
            ? router->active_profile
            : router;
    return table != NULL && table->needs_lower_domain;
}

aproxy_outbound_t *aproxy_router_pick_resolved(
    const aproxy_router_t *router,
    const aproxy_addr_t *destination,
    const aproxy_addr_t *addresses,
    size_t address_count)
{
    if (router == NULL || destination == NULL ||
        (addresses == NULL && address_count > 0u)) {
        return NULL;
    }
    if (destination->family != APROXY_ADDR_FQDN || address_count == 0u) {
        return aproxy_router_pick(router, destination);
    }
    const aproxy_router_t *table = router->active_profile != NULL
                                       ? router->active_profile
                                       : router;
    if (destination->fqdn_len > APROXY_ADDR_MAX_FQDN) {
        return table->default_uses_selected_proxy
                   ? router->selected_proxy
                   : table->default_outbound;
    }
    size_t best = router_pick_rule_index_plus_one(
        table, destination, 0u);
    for (size_t i = 0u; i < address_count && best < table->rule_count; i++) {
        if (addresses[i].family != APROXY_ADDR_IPV4 &&
            addresses[i].family != APROXY_ADDR_IPV6) {
            continue;
        }
        best = router_pick_rule_index_plus_one(
            table, &addresses[i], best);
    }
    if (best == 0u) {
        return table->default_uses_selected_proxy
                   ? router->selected_proxy
                   : table->default_outbound;
    }
    const aproxy_route_rule_t *rule = &table->rules[best - 1u];
    return rule->use_selected_proxy ? router->selected_proxy
                                    : rule->outbound;
}
