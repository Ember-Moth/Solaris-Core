#include "config/image/internal.h"
#include <stdio.h>
#include <string.h>

static int is_self_endpoint(const solaris_address_t *listener, const solaris_address_t *upstream) {
    static const uint8_t zero[16] = {0};
    static const uint8_t v6_loopback[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    static const uint8_t mapped_prefix[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
    if (listener->port != upstream->port)
        return 0;
    if (solaris_address_equal(listener, upstream))
        return 1;
    if (listener->family == SOLARIS_ADDRESS_IPV4) {
        const uint8_t *ip = upstream->ip;
        if (upstream->family == SOLARIS_ADDRESS_IPV6 && !memcmp(ip, mapped_prefix, sizeof(mapped_prefix)))
            ip += sizeof(mapped_prefix);
        else if (upstream->family != SOLARIS_ADDRESS_IPV4)
            return 0;
        return !memcmp(listener->ip, ip, 4) || (!memcmp(listener->ip, zero, 4) && ip[0] == 127);
    }
    return listener->family == SOLARIS_ADDRESS_IPV6 && upstream->family == SOLARIS_ADDRESS_IPV6 &&
           !memcmp(listener->ip, zero, sizeof(zero)) && !memcmp(upstream->ip, v6_loopback, sizeof(v6_loopback));
}

int solaris_config_dns_self_upstream(const solaris_config_dns_t *dns, const solaris_address_t *listener) {
    if (!dns || !listener || !listener->port)
        return 0;
    const size_t role = SOLARIS_DNS_CLIENT_QUERY - 1;
    for (size_t i = 0; i < dns->upstream_count[role]; ++i)
        if (is_self_endpoint(listener, &dns->upstreams[role][i].address))
            return 1;
    return 0;
}

static int numeric_endpoint(const char *text, solaris_dns_upstream_t *out) {
    const char *host = text;
    out->transport = SOLARIS_DNS_TRANSPORT_UDP;
    if (!strncmp(host, "udp://", 6))
        host += 6;
    else if (!strncmp(host, "tcp://", 6)) {
        host += 6;
        out->transport = SOLARIS_DNS_TRANSPORT_TCP;
    } else if (strstr(host, "://"))
        return 0;
    if (!*host || strchr(host, '#') || strchr(host, '?') || strchr(host, '/') || strchr(host, '@'))
        return 0;
    if (solaris_address_parse(host, 53, &out->address) == SOLARIS_OK && out->address.family != SOLARIS_ADDRESS_DOMAIN)
        return 1;
    char address[64];
    const char *port = NULL;
    size_t size;
    if (*host == '[') {
        const char *end = strchr(host, ']');
        if (!end || end[1] != ':' || !end[2])
            return 0;
        size = (size_t)(end - host - 1);
        ++host;
        port = end + 2;
    } else {
        const char *colon = strrchr(host, ':');
        if (!colon || strchr(host, ':') != colon)
            return 0;
        size = (size_t)(colon - host);
        port = colon + 1;
    }
    if (!size || size >= sizeof(address) || !*port)
        return 0;
    memcpy(address, host, size);
    address[size] = 0;
    unsigned value = 0;
    for (const char *p = port; *p; ++p) {
        if (*p < '0' || *p > '9' || value > (65535u - (unsigned)(*p - '0')) / 10u)
            return 0;
        value = value * 10u + (unsigned)(*p - '0');
    }
    return value && solaris_address_parse(address, (uint16_t)value, &out->address) == SOLARIS_OK &&
           out->address.family != SOLARIS_ADDRESS_DOMAIN;
}
static void upstreams(cfg_context_t *c, cfg_node_t *map, const char *field, const solaris_dns_upstream_t **out,
                      size_t *count) {
    cfg_node_t *list = cfg_field(map, field);
    if (!list || cfg_is_null(list))
        return;
    char path[256];
    (void)snprintf(path, sizeof(path), "DNS.%s", field);
    if (list->kind != CFG_SEQUENCE) {
        cfg_fail(c, list, path, SOLARIS_EINVAL, "expected a DNS upstream sequence");
        return;
    }
    if (list->count > SOLARIS_DNS_MAX_UPSTREAMS) {
        cfg_fail(c, list, path, SOLARIS_EOVERFLOW, "DNS upstream count exceeds limit");
        return;
    }
    if (!list->count)
        return;
    solaris_dns_upstream_t *items = cfg_alloc(&c->image->arena, list->count * sizeof(*items));
    if (!items) {
        cfg_fail(c, list, path, SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    *out = items;
    *count = list->count;
    size_t index = 0;
    for (cfg_node_t *item = list->children; item; item = item->next, ++index) {
        (void)snprintf(path, sizeof(path), "DNS.%s[%zu]", field, index);
        const char *text = cfg_string_value(c, item, path, 512, 0);
        if (!text)
            continue;
        items[index].id = index + 1;
        if (!numeric_endpoint(text, &items[index]))
            cfg_fail(
                c, item, path, SOLARIS_ENOTSUP,
                "DNS upstream requires numeric UDP/TCP endpoint; bootstrap and encrypted URI are not yet configured");
    }
}
static void hosts(cfg_context_t *c, cfg_node_t *map, solaris_config_dns_t *dns) {
    if (!map || cfg_is_null(map))
        return;
    if (map->kind != CFG_MAP) {
        cfg_fail(c, map, "Host", SOLARIS_EINVAL, "expected a hosts map");
        return;
    }
    if (map->count / 2 > SOLARIS_HOSTS_DEFAULT_ENTRIES) {
        cfg_fail(c, map, "Host", SOLARIS_EOVERFLOW, "hosts count exceeds limit");
        return;
    }
    size_t count = map->count / 2;
    solaris_hosts_entry_t *entries = count ? cfg_alloc(&c->image->arena, count * sizeof(*entries)) : NULL;
    if (count && !entries) {
        cfg_fail(c, map, "Host", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    dns->hosts = entries;
    dns->host_count = count;
    size_t index = 0;
    for (cfg_node_t *key = map->children; key && key->next; key = key->next->next, ++index) {
        char path[256];
        (void)snprintf(path, sizeof(path), "Host[%zu]", index);
        entries[index].name = cfg_string_value(c, key, path, 253, 0);
        cfg_node_t *value = key->next;
        size_t n = value->kind == CFG_SEQUENCE ? value->count : 1;
        if (!n || n > SOLARIS_HOSTS_MAX_ADDRESSES) {
            cfg_fail(c, value, path, SOLARIS_EOVERFLOW, "host address count exceeds limit");
            continue;
        }
        solaris_address_t *addresses = cfg_alloc(&c->image->arena, n * sizeof(*addresses));
        if (!addresses) {
            cfg_fail(c, value, path, SOLARIS_ENOMEM, "configuration memory budget exhausted");
            continue;
        }
        entries[index].kind = SOLARIS_HOSTS_ADDRESSES;
        entries[index].addresses = addresses;
        entries[index].address_count = n;
        cfg_node_t *item = value->kind == CFG_SEQUENCE ? value->children : value;
        for (size_t i = 0; i < n; ++i, item = item->next) {
            const char *text = cfg_string_value(c, item, path, 253, 0);
            if (!text)
                continue;
            solaris_status_t status = solaris_address_parse(text, 0, &addresses[i]);
            if (status == SOLARIS_OK && addresses[i].family != SOLARIS_ADDRESS_DOMAIN && !addresses[i].scope_id)
                continue;
            if (value->kind != CFG_SEQUENCE && status == SOLARIS_OK && addresses[i].family == SOLARIS_ADDRESS_DOMAIN) {
                entries[index].kind = SOLARIS_HOSTS_ALIAS;
                entries[index].alias = text;
                entries[index].addresses = NULL;
                entries[index].address_count = 0;
            } else
                cfg_fail(c, item, path, SOLARIS_EINVAL, "hosts list requires numeric unscoped addresses");
        }
    }
}
void cfg_dns_compile(cfg_context_t *c, cfg_node_t *root) {
    cfg_node_t *map = cfg_field(root, "DNS"), *host_map = cfg_field(root, "Host");
    if (!map && !host_map)
        return;
    solaris_config_dns_t *dns = cfg_alloc(&c->image->arena, sizeof(*dns));
    if (!dns) {
        cfg_fail(c, root, "DNS", SOLARIS_ENOMEM, "configuration memory budget exhausted");
        return;
    }
    c->image->dns = dns;
    dns->use_hosts = dns->use_system_hosts = 1;
    dns->ipv6_wait_ms = 100;
    hosts(c, host_map, dns);
    if (map && !cfg_is_null(map)) {
        const char *fields[] = {"enabled",
                                "ipv6",
                                "ipv6-wait-ms",
                                "use-hosts",
                                "use-system-hosts",
                                "upstream",
                                "route-upstream",
                                "bootstrap-upstream",
                                "proxy-upstream",
                                "direct-upstream",
                                "listen",
                                "mode",
                                "cache-algorithm",
                                "cache-size"};
        cfg_fields(c, map, "DNS", fields, sizeof(fields) / sizeof(*fields));
        if (map->kind != CFG_MAP)
            return;
        dns->enabled = (uint32_t)cfg_bool(c, map, "enabled", "DNS", 0);
        dns->ipv6 = (uint32_t)cfg_bool(c, map, "ipv6", "DNS", 0);
        dns->use_hosts = (uint32_t)cfg_bool(c, map, "use-hosts", "DNS", 1);
        dns->use_system_hosts = (uint32_t)cfg_bool(c, map, "use-system-hosts", "DNS", 1);
        dns->ipv6_wait_ms = (uint32_t)cfg_uint(c, map, "ipv6-wait-ms", "DNS", 100, 0, 10000, 0);
        const char *listen = cfg_text(c, map, "listen", "DNS", 0, 512, 1);
        const char *mode = cfg_text(c, map, "mode", "DNS", 0, 32, 0);
        const char *algorithm = cfg_text(c, map, "cache-algorithm", "DNS", 0, 32, 0);
        uint64_t cache_size = cfg_uint(c, map, "cache-size", "DNS", 0, 0, 65536, 0);
        if (mode && strcmp(mode, "normal"))
            cfg_fail(c, cfg_field(map, "mode"), "DNS.mode", SOLARIS_ENOTSUP,
                     "Fake-IP DNS answer activation is not yet implemented");
        if (algorithm && strcmp(algorithm, "lru"))
            cfg_fail(c, cfg_field(map, "cache-algorithm"), "DNS.cache-algorithm", SOLARIS_ENOTSUP,
                     "only LRU DNS cache is implemented");
        if (cache_size && cache_size != 4096)
            cfg_fail(c, cfg_field(map, "cache-size"), "DNS.cache-size", SOLARIS_ENOTSUP,
                     "DNS cache currently uses the bounded 4096-entry service default");
        upstreams(c, map, "upstream", &dns->upstreams[SOLARIS_DNS_CLIENT_QUERY - 1],
                  &dns->upstream_count[SOLARIS_DNS_CLIENT_QUERY - 1]);
        upstreams(c, map, "route-upstream", &dns->upstreams[SOLARIS_DNS_ROUTE_TARGET - 1],
                  &dns->upstream_count[SOLARIS_DNS_ROUTE_TARGET - 1]);
        upstreams(c, map, "direct-upstream", &dns->upstreams[SOLARIS_DNS_DIRECT_TARGET - 1],
                  &dns->upstream_count[SOLARIS_DNS_DIRECT_TARGET - 1]);
        upstreams(c, map, "proxy-upstream", &dns->upstreams[SOLARIS_DNS_PROXY_SERVER - 1],
                  &dns->upstream_count[SOLARIS_DNS_PROXY_SERVER - 1]);
        upstreams(c, map, "bootstrap-upstream", &dns->upstreams[SOLARIS_DNS_BOOTSTRAP - 1],
                  &dns->upstream_count[SOLARIS_DNS_BOOTSTRAP - 1]);
        if (dns->enabled && !dns->upstream_count[SOLARIS_DNS_CLIENT_QUERY - 1])
            cfg_fail(c, map, "DNS.upstream", SOLARIS_EINVAL,
                     "enabled DNS requires explicit numeric upstreams; no implicit public resolvers");
        for (size_t role = 0; role < SOLARIS_DNS_ROLE_COUNT; ++role) {
            if (!dns->upstream_count[role]) {
                dns->upstreams[role] = dns->upstreams[SOLARIS_DNS_CLIENT_QUERY - 1];
                dns->upstream_count[role] = dns->upstream_count[SOLARIS_DNS_CLIENT_QUERY - 1];
            }
            dns->upstream_set_id[role] = role + 1;
        }
        if (!c->errors && listen && *listen && strcmp(listen, "off")) {
            cfg_node_t *location = cfg_field(map, "listen");
            if (!dns->enabled)
                cfg_fail(c, location, "DNS.listen", SOLARIS_EINVAL, "DNS listener requires enabled=true");
            else
                cfg_add_dns_listener(c, location, listen);
        }
        if (dns->upstream_count[SOLARIS_DNS_CLIENT_QUERY - 1] > 1)
            cfg_diagnostic(c, map, "DNS.upstream", SOLARIS_DIAGNOSTIC_WARNING, SOLARIS_CONFIG_NORMALIZE, SOLARIS_OK,
                           "DNS upstreams currently use ordered transport failover, not parallel racing");
    }
    if (c->errors)
        return;
    solaris_hosts_t *compiled = NULL;
    solaris_hosts_diagnostic_t diagnostic;
    solaris_status_t rc =
        solaris_hosts_build(c->budget, dns->hosts, dns->host_count, NULL, 0, NULL, &compiled, &diagnostic);
    if (rc != SOLARIS_OK) {
        char path[256];
        (void)snprintf(path, sizeof(path), "Host[%zu]", diagnostic.entry_index);
        cfg_node_t *location = host_map ? host_map : root;
        if (host_map && diagnostic.entry_index < host_map->count / 2) {
            location = host_map->children;
            for (size_t i = 0; i < diagnostic.entry_index; ++i)
                location = location->next->next;
        }
        cfg_fail(c, location, path, rc, diagnostic.message);
    } else
        dns->validated_hosts = compiled;
}
