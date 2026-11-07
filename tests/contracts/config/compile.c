#include <solaris/config.h>
#include "config/image/internal.h"
#include "solaris_builtin_modules.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x)                                                                                                       \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
static const char sample[] =
    "x-node: &node\n  type: socks5\n  server: 127.0.0.1\n  port: 1080\n  udp: false\n"
    "proxies:\n  - <<: *node\n    name: proxy\n    udp: true\n"
    "proxy-groups:\n  - name: select\n    type: select\n    proxies: [proxy, DIRECT, REJECT]\n"
    "rules:\n  - DOMAIN-SUFFIX,example.com,select\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - MATCH,REJECT\n"
    "mode: global\nport: 0\nsocks-port: 0\nmixed-port: 0\n";
static solaris_config_t *valid(const char *yaml)
{
    solaris_config_t *image = NULL;
    solaris_diagnostics_t *d = NULL;
    solaris_error_t e;
    solaris_status_t rc = solaris_config_compile_bytes(yaml, strlen(yaml), NULL, &image, &d, &e);
    if (rc != SOLARIS_OK) {
        fprintf(stderr, "compile failed: %d %s\n", rc, e.message);
        for (size_t i = 0; i < solaris_diagnostics_count(d); ++i) {
            solaris_config_diagnostic_t x;
            solaris_diagnostics_get(d, i, &x);
            fprintf(stderr, "%u:%u %s %s\n", x.line, x.column, x.path, x.message);
        }
    }
    CHECK(rc == SOLARIS_OK && image);
    solaris_diagnostics_release(d);
    return image;
}
static void invalid(const char *yaml, solaris_status_t expected)
{
    solaris_config_t *image = (void *)1;
    solaris_diagnostics_t *d = NULL;
    solaris_error_t e;
    solaris_status_t actual = solaris_config_compile_bytes(yaml, strlen(yaml), NULL, &image, &d, &e);
    if (actual != expected)
        fprintf(stderr, "invalid fixture expected=%d actual=%d YAML=%.100s\n", expected, actual, yaml);
    CHECK(actual == expected);
    CHECK(!image && e.code == expected);
    CHECK(solaris_diagnostics_count(d) > 0);
    solaris_config_diagnostic_t item;
    CHECK(solaris_diagnostics_get(d, 0, &item) == SOLARIS_OK && item.path[0] && item.source[0]);
    CHECK(!strstr(item.message, "SECRET-CREDENTIAL") && !strstr(e.message, "SECRET-CREDENTIAL"));
    solaris_diagnostics_retain(d);
    solaris_diagnostics_release(d);
    solaris_diagnostics_release(d);
}
static void basics(void)
{
    solaris_config_t *c = valid(sample);
    solaris_config_snapshot_t s;
    CHECK(solaris_config_get_snapshot(c, &s) == SOLARIS_OK);
    CHECK(s.mode == SOLARIS_MODE_GLOBAL && s.node_count == 3 && s.group_count == 2 && s.rule_count == 3 &&
          !s.listener_count);
    solaris_config_node_info_t node;
    CHECK(solaris_config_get_node(c, 2, &node) == SOLARIS_OK && !strcmp(node.name, "proxy") && node.udp_enabled);
    uint64_t stable = node.id;
    size_t count;
    const solaris_config_node_t *nodes = solaris_config_nodes(c, &count);
    CHECK(count == 3 && !solaris_config_get(nodes[2].fields, "name") && !solaris_config_get(nodes[2].fields, "type") &&
          !solaris_config_get(nodes[2].fields, "udp"));
    CHECK(solaris_config_get(nodes[2].fields, "port")->value.integer == 1080);
    const solaris_config_group_t *groups = solaris_config_groups(c, &count);
    CHECK(count == 2 && groups[0].selected_id == stable && groups[0].member_count == 3);
    const solaris_route_rule_t *rules = solaris_config_rules(c, &count);
    CHECK(count == 3 && rules[0].target_id == groups[0].id && rules[1].no_resolve);
    CHECK(solaris_config_direct_target(c) == nodes[0].id && solaris_config_global_target(c) == groups[1].id);
    solaris_config_retain(c);
    solaris_config_release(c);
    solaris_config_release(c);
    c = valid("proxies: [{name: proxy, type: socks5, server: 127.0.0.1, port: 1080}]\n");
    CHECK(solaris_config_get_node(c, 2, &node) == SOLARIS_OK && node.id == stable && !node.udp_enabled);
    solaris_config_release(c);
    c = valid("x-a: &a {type: socks5, server: 127.0.0.1, port: 1080}\nx-b: &b {port: 2080}\nproxies: [{name: proxy, "
              "<<: [*a, *b]}]\n");
    nodes = solaris_config_nodes(c, &count);
    CHECK(solaris_config_get(nodes[2].fields, "port")->value.integer == 1080);
    solaris_config_release(c);
    invalid("port: 1\nport: 2\n", SOLARIS_EINVAL);
    invalid("x: &a [*a]\n", SOLARIS_EINVAL);
    invalid("x: *missing\n", SOLARIS_EINVAL);
    invalid("--- {}\n--- {}\n", SOLARIS_ENOTSUP);
    invalid("!!python/object:Thing {}", SOLARIS_ENOTSUP);
    invalid("{123: value}", SOLARIS_EINVAL);
    invalid("{true: value}", SOLARIS_EINVAL);
    invalid("{null: value}", SOLARIS_EINVAL);
    invalid("{[one, two]: value}", SOLARIS_EINVAL);
    invalid("proxies: [{name: p, type: socks5, server: 127.0.0.1, port: 1080, password: SECRET-CREDENTIAL}]",
            SOLARIS_EINVAL);
    invalid("proxies: [{name: DIRECT, type: socks5, server: 127.0.0.1, port: 1080}]", SOLARIS_EINVAL);
    invalid("proxies: [{name: p, type: socks5, server: 127.0.0.1, port: 1080, network: ws}]", SOLARIS_ENOTSUP);
    invalid("proxy-groups: [{name: a, type: select, proxies: [b]}, {name: b, type: select, proxies: [a]}]",
            SOLARIS_EINVAL);
    invalid("rules: [MATCH,UNKNOWN]", SOLARIS_EINVAL);
    invalid("dns: {enable: true}", SOLARIS_ENOTSUP);
    invalid("proxies: [{name: p, type: socks5, server: x, port: 1080, ca-pem: SECRET-CREDENTIAL}]", SOLARIS_ENOTSUP);
    c = valid("x: &a {port: 123}\n!!str <<: *a");
    CHECK(solaris_config_get_snapshot(c, &s) == SOLARIS_OK && !s.listener_count);
    solaris_config_release(c);
    c = valid("x: &a {port: 0}\n!!merge <<: *a\n");
    solaris_config_release(c);
}
static const solaris_config_view_t *node_field(solaris_config_t *c, const char *name)
{
    size_t count;
    const solaris_config_node_t *nodes = solaris_config_nodes(c, &count);
    CHECK(count == 3);
    return solaris_config_get(nodes[2].fields, name);
}
static void protocol_mapping(void)
{
    solaris_config_t *builtins = valid("proxies: [{name: named-direct, type: direct}, "
        "{name: named-reject, type: reject}, {name: tcp-direct, type: direct, udp: false}]");
    size_t builtin_count;
    const solaris_config_node_t *builtin_nodes = solaris_config_nodes(builtins, &builtin_count);
    CHECK(builtin_count == 5 && !strcmp(builtin_nodes[2].type, "direct") && builtin_nodes[2].udp_enabled);
    CHECK(!strcmp(builtin_nodes[3].type, "block") && builtin_nodes[3].udp_enabled);
    CHECK(!builtin_nodes[4].udp_enabled);
    solaris_config_release(builtins);
    invalid("proxies: [{name: p, type: block}]", SOLARIS_ENOTSUP);
    invalid("proxies: [{name: p, type: shadowsocks, server: x, port: 443, cipher: aes-128-gcm, password: secret}]",
            SOLARIS_ENOTSUP);
    solaris_config_t *c;
#if SOLARIS_HAS_SHADOWSOCKS
    invalid("proxies: [{name: p, type: ss, server: example.com, port: 443, cipher: aes-128-gcm, password: secret, "
            "udp-over-tcp: true}]",
            SOLARIS_ENOTSUP);
    c = valid("proxies: [{name: p, type: ss, server: example.com, port: 443, cipher: aes-128-gcm, password: secret, "
              "udp: true, udp-over-tcp: true, udp-over-tcp-version: 2}]");
    CHECK(node_field(c, "udp-over-tcp")->value.boolean && !node_field(c, "udp-over-tcp-version"));
    solaris_config_release(c);
    invalid("proxies: [{name: p, type: ss, server: x, port: 443, cipher: wrong, password: SECRET-CREDENTIAL}]",
            SOLARIS_EINVAL);
#else
    invalid("proxies: [{name: p, type: ss, server: x, port: 443, cipher: aes-128-gcm, password: secret}]",
            SOLARIS_ENOTSUP);
#endif
#if SOLARIS_HAS_VLESS
    c = valid(
        "proxies: [{name: p, type: vless, server: example.com, port: 443, uuid: 00000000-0000-0000-0000-000000000001, "
        "tls: true, servername: sni.example, flow: xtls-rprx-vision, encryption: none, packet-encoding: xudp}]");
    CHECK(node_field(c, "tls")->value.boolean &&
          !strcmp(node_field(c, "servername")->value.string.data, "sni.example") && !node_field(c, "ca-pem") &&
          !node_field(c, "encryption"));
    solaris_config_release(c);
    c = valid("proxies: [{name: p, type: vless, server: example.com, port: 443, uuid: "
              "00000000-0000-0000-0000-000000000001, flow: xtls-rprx-vision, encryption: "
              "mlkem768x25519plus.native.1rtt.hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo}]");
    CHECK(node_field(c, "encryption") && !node_field(c, "tls")->value.boolean);
    solaris_config_release(c);
    invalid("proxies: [{name: p, type: vless, server: x, port: 443, uuid: invalid}]", SOLARIS_EINVAL);
    invalid("proxies: [{name: p, type: vless, server: x, port: 443, uuid: 00000000-0000-0000-0000-000000000001, flow: "
            "xtls-rprx-vision}]",
            SOLARIS_EINVAL);
    invalid("proxies: [{name: p, type: vless, server: x, port: 443, uuid: 00000000-0000-0000-0000-000000000001, "
            "packet-encoding: packetaddr}]",
            SOLARIS_ENOTSUP);
#else
    invalid("proxies: [{name: p, type: vless, server: x, port: 443, uuid: 00000000-0000-0000-0000-000000000001}]",
            SOLARIS_ENOTSUP);
#endif
#if SOLARIS_HAS_ANYTLS
    c = valid("proxies: [{name: p, type: anytls, server: example.com, port: 443, password: secret, sni: sni.example, "
              "idle-session-timeout: 17, idle-session-check-interval: 3, min-idle-session: 2}]");
    CHECK(node_field(c, "tls")->value.boolean && node_field(c, "idle-session-timeout-ms")->value.integer == 17000 &&
          node_field(c, "idle-session-check-interval-ms")->value.integer == 30000 &&
          node_field(c, "min-idle-session")->value.integer == 2);
    solaris_config_release(c);
    c = valid("proxies: [{name: p, type: anytls, server: x, port: 443, password: secret, idle-session-timeout: 0, "
              "idle-session-check-interval: 0}]");
    CHECK(node_field(c, "idle-session-timeout-ms")->value.integer == 30000 &&
          node_field(c, "idle-session-check-interval-ms")->value.integer == 30000);
    solaris_config_release(c);
    c = valid("proxies: [{name: p, type: anytls, server: x, port: 443, password: secret}]");
    CHECK(node_field(c, "idle-session-timeout-ms")->value.integer == 30000 &&
          node_field(c, "idle-session-check-interval-ms")->value.integer == 30000);
    solaris_config_release(c);
    for (unsigned seconds = 1; seconds <= 6; ++seconds) {
        char yaml[256];
        (void)snprintf(yaml, sizeof(yaml), "proxies: [{name: p, type: anytls, server: x, port: 443, password: secret, "
            "idle-session-timeout: %u, idle-session-check-interval: %u}]", seconds, seconds);
        c = valid(yaml);
        int64_t milliseconds = seconds <= 5 ? 30000 : 6000;
        CHECK(node_field(c, "idle-session-timeout-ms")->value.integer == milliseconds &&
              node_field(c, "idle-session-check-interval-ms")->value.integer == milliseconds);
        solaris_config_release(c);
    }
    invalid("proxies: [{name: p, type: anytls, server: x, port: 443, password: secret, idle-session-timeout: -1}]",
            SOLARIS_EINVAL);
    invalid("proxies: [{name: p, type: anytls, server: x, port: 443, password: secret, certificate: client.pem}]",
            SOLARIS_ENOTSUP);
#else
    invalid("proxies: [{name: p, type: anytls, server: x, port: 443, password: secret}]", SOLARIS_ENOTSUP);
#endif
    c = valid("proxies: [{name: p, type: socks5, server: x, port: 1080, username: _123, password: _456}]");
    CHECK(!strcmp(node_field(c, "username")->value.string.data, "_123") &&
          !strcmp(node_field(c, "password")->value.string.data, "_456"));
    solaris_config_release(c);
    c = valid(
        "proxies: [{name: p, type: socks5, server: x, port: '010', username: 00123, password: !!str null, udp: 1}]");
    CHECK(node_field(c, "port")->value.integer == 8 && !strcmp(node_field(c, "username")->value.string.data, "83") &&
          !strcmp(node_field(c, "password")->value.string.data, "null"));
    solaris_config_release(c);
    c = valid("proxies: [{name: p, type: socks5, server: x, port: 1080, username: nan, password: Inf}]");
    CHECK(!strcmp(node_field(c, "username")->value.string.data, "nan") &&
          !strcmp(node_field(c, "password")->value.string.data, "Inf"));
    solaris_config_release(c);
    c = valid("proxies: [{name: p, type: socks5, server: x, port: 1080, username: tRuE, password: 0x1p3}]");
    CHECK(!strcmp(node_field(c, "username")->value.string.data, "tRuE") &&
          !strcmp(node_field(c, "password")->value.string.data, "0x1p3"));
    solaris_config_release(c);
    c = valid("x-template: &template {tRuE: value, nan: value, Inf: value, 0x1p3: value}\n");
    solaris_config_release(c);
    invalid("proxies: [{name: p, type: socks5, server: x, port: 1080, username: .nan, password: secret}]",
            SOLARIS_ENOTSUP);
    invalid("proxies: [{name: p, type: socks5, server: x, port: 1080, username: 08, password: secret}]",
            SOLARIS_ENOTSUP);
    invalid("port: _7890", SOLARIS_EINVAL);
    invalid("port: '7890'", SOLARIS_EINVAL);
    invalid("port: !!str 7890", SOLARIS_EINVAL);
    invalid("mode: !!int direct", SOLARIS_EINVAL);
    invalid("mode: !!seq direct", SOLARIS_EINVAL);
    invalid("x: !!null nope", SOLARIS_EINVAL);
    invalid("x: !!bool tRuE", SOLARIS_EINVAL);
    invalid("proxies: [{name: p, type: socks5, server: x, port: 1080, udp: tRuE}]", SOLARIS_EINVAL);
    invalid("proxies: [{name: p, type: socks5, server: x, port: 1080, udp: 'true'}]", SOLARIS_EINVAL);
    invalid("proxies: [{name: p, type: socks5, server: x, port: 1080, username: true, password: secret}]",
            SOLARIS_EINVAL);
}
static void limits_and_locations(void)
{
    solaris_config_options_t o;
    solaris_config_options_init(&o);
    o.source_name = "source.yml";
    const char *bad = "x: &a {type: socks5, server: x, port: bad}\nproxies: [{<<: *a, name: proxy}]\n";
    solaris_config_t *c;
    solaris_diagnostics_t *d;
    CHECK(solaris_config_compile_bytes(bad, strlen(bad), &o, &c, &d, NULL) == SOLARIS_EINVAL);
    int related = 0;
    for (size_t i = 0; i < solaris_diagnostics_count(d); ++i) {
        solaris_config_diagnostic_t x;
        CHECK(solaris_diagnostics_get(d, i, &x) == SOLARIS_OK);
        if (x.severity == SOLARIS_DIAGNOSTIC_ERROR) {
            CHECK(strstr(x.path, "port"));
            related |= x.related_line == 1 && x.line == 2;
            CHECK(!strcmp(x.source, "source.yml"));
        }
    }
    CHECK(related);
    solaris_diagnostics_release(d);
    const char *alias = "x-a: &a [one,two,three,four]\nx-b: &b [*a,*a,*a,*a]\nx-c: [*b,*b,*b,*b]\n";
    o.alias_limit = 8;
    CHECK(solaris_config_compile_bytes(alias, strlen(alias), &o, &c, &d, NULL) == SOLARIS_EOVERFLOW);
    CHECK(!c);
    solaris_diagnostics_release(d);
    solaris_config_options_init(&o);
    o.depth_limit = 3;
    CHECK(solaris_config_compile_bytes("x: [[[[1]]]]", 12, &o, &c, &d, NULL) != SOLARIS_OK);
    solaris_diagnostics_release(d);
    solaris_config_options_init(&o);
    o.input_limit_bytes = 2;
    CHECK(solaris_config_compile_bytes(sample, strlen(sample), &o, &c, &d, NULL) == SOLARIS_EOVERFLOW);
    solaris_diagnostics_release(d);
    solaris_config_options_init(&o);
    o.memory_limit_bytes = 1024;
    CHECK(solaris_config_compile_bytes(sample, strlen(sample), &o, &c, &d, NULL) == SOLARIS_ENOMEM);
    solaris_diagnostics_release(d);
    char input[] = "mode: direct\n";
    char directory[] = "/not/read/by/compiler";
    o.base_directory = directory;
    o.memory_limit_bytes = 16777216;
    CHECK(solaris_config_compile_bytes(input, strlen(input), &o, &c, &d, NULL) == SOLARIS_OK);
    memset(input, 'x', strlen(input));
    memset(directory, 'y', strlen(directory));
    solaris_config_snapshot_t s;
    CHECK(solaris_config_get_snapshot(c, &s) == SOLARIS_OK && s.mode == SOLARIS_MODE_DIRECT &&
          !strcmp(solaris_config_base_directory(c), "/not/read/by/compiler"));
    solaris_config_release(c);
    solaris_diagnostics_release(d);
}
typedef struct allocation {
    size_t calls, fail, live;
} allocation_t;
static void *allocate(void *context, size_t size)
{
    allocation_t *a = context;
    if (++a->calls == a->fail)
        return NULL;
    void *p = malloc(size);
    if (p)
        a->live++;
    return p;
}
static void deallocate(void *context, void *pointer)
{
    allocation_t *a = context;
    CHECK(a->live);
    a->live--;
    free(pointer);
}
static void failure_input(const char *input)
{
    allocation_t a = {0};
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = &a;
    services.allocate = allocate;
    services.deallocate = deallocate;
    solaris_config_t *c;
    solaris_diagnostics_t *d;
    CHECK(solaris_config_compile_bytes_services(input, strlen(input), NULL, &services, &c, &d, NULL) == SOLARIS_OK);
    size_t count = a.calls;
    solaris_config_release(c);
    solaris_diagnostics_release(d);
    CHECK(!a.live);
    for (size_t fail = 1; fail <= count; ++fail) {
        a = (allocation_t){.fail = fail};
        solaris_status_t rc =
            solaris_config_compile_bytes_services(input, strlen(input), NULL, &services, &c, &d, NULL);
        CHECK(rc != SOLARIS_OK && !c);
        solaris_diagnostics_release(d);
        CHECK(!a.live);
    }
    printf("Injected failures at %zu allocation sites, including libyaml internals\n", count);
}
static void failures(void)
{
    failure_input(sample);
#if SOLARIS_HAS_PROXY_INBOUND
    failure_input("proxies: [{name: named-direct, type: direct}, {name: named-reject, type: reject}]\n"
                  "authentication: [user:pass]\n"
                  "listeners: [{name: inherited, type: http, port: '010'}, "
                  "{name: private, type: socks, port: 1080, users: [{username: client, password: synthetic}]}]\n");
#endif
}
static void worker(void *context)
{
    solaris_config_t *shared = context;
    for (unsigned i = 0; i < 24; ++i) {
        solaris_config_retain(shared);
        solaris_config_snapshot_t s;
        CHECK(solaris_config_get_snapshot(shared, &s) == SOLARIS_OK && s.node_count == 3);
        solaris_config_t *local = valid(sample);
        solaris_config_release(local);
        solaris_config_release(shared);
    }
}
static void concurrent(void)
{
    solaris_config_t *c = valid(sample);
    uv_thread_t threads[8];
    for (unsigned i = 0; i < 8; ++i)
        CHECK(!uv_thread_create(&threads[i], worker, c));
    for (unsigned i = 0; i < 8; ++i)
        CHECK(!uv_thread_join(&threads[i]));
    solaris_config_release(c);
}
static void listeners(void)
{
#if SOLARIS_HAS_PROXY_INBOUND
    solaris_config_t *c = valid(
        "mixed-port: 7890\nauthentication: [user:pass]\nlisteners:\n- {name: explicit, type: socks, listen: 127.0.0.1, "
        "port: 7891, udp: true, users: []}\n- {name: inherited, type: http, listen: 127.0.0.1, port: 7892}\n");
    size_t count;
    const solaris_config_listener_t *l = solaris_config_listeners(c, &count);
    CHECK(count == 3 && l[0].auth_count == 1 && !l[1].auth_count && l[2].auth_count == 1);
    CHECK(l[0].listen.port == 7890 && l[1].udp);
    solaris_config_release(c);
    c = valid("listeners: [{name: http, type: http, port: 7891}, "
              "{name: socks, type: socks, port: 7892}, {name: mixed, type: mixed, port: 7893}, "
              "{name: tcp-socks, type: socks, port: 7894, udp: false}, "
              "{name: tcp-mixed, type: mixed, port: 7895, udp: false}]");
    l = solaris_config_listeners(c, &count);
    CHECK(count == 5 && !l[0].udp && l[1].udp && l[2].udp && !l[3].udp && !l[4].udp);
    solaris_config_release(c);
    c = valid("listeners: [{name: decimal, type: http, port: '010'}, "
              "{name: octal, type: http, port: 010}]");
    l = solaris_config_listeners(c, &count);
    CHECK(count == 2 && l[0].listen.port == 10 && l[1].listen.port == 8);
    solaris_config_release(c);
    invalid("listeners: [{name: overflow, type: http, port: '65536'}]", SOLARIS_ENOTSUP);
    invalid("listeners: [{name: range, type: http, port: '80-81'}]", SOLARIS_ENOTSUP);
    invalid("port: 7890\nsocks-port: 7890", SOLARIS_EINVAL);
    invalid("listeners: [{name: ephemeral, type: http, port: 0}]", SOLARIS_ENOTSUP);
#else
    invalid("port: 7890", SOLARIS_ENOTSUP);
#endif
}
static int probe(void)
{
    size_t capacity = 1048577;
    char *input = malloc(capacity);
    CHECK(input);
    size_t length = fread(input, 1, capacity, stdin);
    solaris_config_t *c = NULL;
    solaris_diagnostics_t *d = NULL;
    solaris_status_t rc = solaris_config_compile_bytes(input, length, NULL, &c, &d, NULL);
    free(input);
    printf("{\"ok\":%s,\"status\":%d,\"inbound\":%d", rc == SOLARIS_OK ? "true" : "false", rc,
           SOLARIS_HAS_PROXY_INBOUND);
    if (c) {
        solaris_config_snapshot_t snapshot;
        CHECK(solaris_config_get_snapshot(c, &snapshot) == SOLARIS_OK);
        const char *mode = snapshot.mode == SOLARIS_MODE_RULE     ? "rule"
                           : snapshot.mode == SOLARIS_MODE_GLOBAL ? "global"
                                                                  : "direct";
        printf(",\"mode\":\"%s\",\"ports\":[", mode);
        size_t count;
        const solaris_config_listener_t *listeners = solaris_config_listeners(c, &count);
        for (size_t i = 0; i < count; ++i)
            printf("%s%u", i ? "," : "", listeners[i].listen.port);
        printf("],\"families\":[");
        for (size_t i = 0; i < count; ++i)
            printf("%s%u", i ? "," : "", listeners[i].listen.family);
        printf("]");
    }
    puts("}");
    solaris_config_release(c);
    solaris_diagnostics_release(d);
    return 0;
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--probe"))
        return probe();
#if !SOLARIS_HAS_DIRECT || !SOLARIS_HAS_BLOCK || !SOLARIS_HAS_SOCKS5
    (void)argc;
    (void)argv;
    return 77;
#else
    basics();
    protocol_mapping();
    limits_and_locations();
    failures();
    concurrent();
    listeners();
    if (argc > 1) {
        solaris_config_t *c;
        solaris_diagnostics_t *d;
        CHECK(solaris_config_compile_file(argv[1], NULL, &c, &d, NULL) == SOLARIS_OK);
        CHECK(solaris_config_base_directory(c));
        solaris_config_release(c);
        solaris_diagnostics_release(d);
    }
    puts("YAML image, source diagnostics, merge/alias budgets, failure rollback, listeners and concurrent ownership "
         "passed");
    return 0;
#endif
}
