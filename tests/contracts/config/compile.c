#include "config/image/internal.h"
#include "solaris_builtin_modules.h"
#include <solaris/config.h>
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
#define GENERAL "[General]\nconfig-version = 1\n"
#define DIRECT GENERAL "mode = direct\n"
#define FINAL "[Rule]\nFINAL,DIRECT\n"
static const char sample[] =
    GENERAL "mode = global\n"
            "[Proxy]\nproxy = socks5, 127.0.0.1, 1080, udp-relay=true\n"
            "[Proxy Group]\nselect = select, proxy, DIRECT, REJECT\n"
            "[Rule]\nDOMAIN-SUFFIX,example.com,select\nIP-CIDR,10.0.0.0/8,DIRECT,no-resolve\nFINAL,REJECT\n";
#if SOLARIS_HAS_PROXY_INBOUND
static const char listener_sample[] =
    GENERAL "mode = direct\nauthentication = Local\n"
            "http-listen = 127.0.0.1:7890\nsocks-listen = [::1]:7891\nmixed-listen = off\n"
            "[Authentication]\nLocal = user=pass, \"user:two\"=\"p,a=ss\\\"\\\\#; //\"\nPrivate = client=synthetic\n"
            "[Listener]\nprivate = socks5, 127.0.0.2, 1080, authentication=Private, udp-relay=false\n"
            "public = mixed, 127.0.0.3, 1081, authentication=\"\"\n";
#endif
static solaris_config_t *valid(const char *text) {
    solaris_config_t *image = NULL;
    solaris_diagnostics_t *d = NULL;
    solaris_error_t e;
    solaris_status_t rc = solaris_config_compile_bytes(text, strlen(text), NULL, &image, &d, &e);
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
static void invalid_bytes(const char *text, size_t size, solaris_status_t expected) {
    solaris_config_t *image = (void *)1;
    solaris_diagnostics_t *d = NULL;
    solaris_error_t e;
    solaris_status_t actual = solaris_config_compile_bytes(text, size, NULL, &image, &d, &e);
    if (actual != expected)
        fprintf(stderr, "fixture expected=%d actual=%d\n", expected, actual);
    CHECK(actual == expected && !image && e.code == expected && solaris_diagnostics_count(d));
    CHECK(!strstr(e.message, "SECRET-CREDENTIAL"));
    for (size_t i = 0; i < solaris_diagnostics_count(d); ++i) {
        solaris_config_diagnostic_t item;
        CHECK(solaris_diagnostics_get(d, i, &item) == SOLARIS_OK);
        CHECK(item.path[0] && item.source[0] && item.line && item.column);
        CHECK(!strstr(item.path, "SECRET-CREDENTIAL") && !strstr(item.message, "SECRET-CREDENTIAL"));
    }
    solaris_diagnostics_retain(d);
    solaris_diagnostics_release(d);
    solaris_diagnostics_release(d);
}
static void invalid(const char *text, solaris_status_t expected) { invalid_bytes(text, strlen(text), expected); }
static const solaris_config_view_t *node_field(solaris_config_t *c, const char *name) {
    size_t count;
    const solaris_config_node_t *nodes = solaris_config_nodes(c, &count);
    CHECK(count == 3);
    return solaris_config_get(nodes[2].fields, name);
}
static void basics(void) {
    solaris_config_t *c = valid(sample);
    solaris_config_snapshot_t s;
    solaris_config_node_info_t node;
    CHECK(solaris_config_get_snapshot(c, &s) == SOLARIS_OK && s.mode == SOLARIS_MODE_GLOBAL && s.node_count == 3 &&
          s.group_count == 2 && s.rule_count == 3 && !s.listener_count);
    CHECK(solaris_config_get_node(c, 2, &node) == SOLARIS_OK && !strcmp(node.name, "proxy") && node.udp_enabled);
    uint64_t stable = node.id;
    size_t count;
    const solaris_config_group_t *groups = solaris_config_groups(c, &count);
    CHECK(count == 2 && groups[0].selected_id == stable && groups[0].member_count == 3);
    const solaris_route_rule_t *rules = solaris_config_rules(c, &count);
    CHECK(count == 3 && rules[0].target_id == groups[0].id && rules[1].no_resolve);
    CHECK(solaris_config_global_target(c) == groups[1].id);
    CHECK(node_field(c, "port")->value.integer == 1080 && !node_field(c, "name") && !node_field(c, "udp-relay"));
    solaris_config_retain(c);
    solaris_config_release(c);
    solaris_config_release(c);
    c = valid(DIRECT "[Proxy]\nproxy = socks5, 127.0.0.1, 1080\n");
    CHECK(solaris_config_get_node(c, 2, &node) == SOLARIS_OK && node.id == stable && !node.udp_enabled);
    solaris_config_release(c);
    c = valid(DIRECT "[Proxy]\na = direct\nb = reject\nc = direct, udp-relay=false\n");
    const solaris_config_node_t *nodes = solaris_config_nodes(c, &count);
    CHECK(count == 5 && nodes[2].udp_enabled && nodes[3].udp_enabled && !nodes[4].udp_enabled);
    CHECK(!strcmp(nodes[2].type, "direct") && !strcmp(nodes[3].type, "block"));
    solaris_config_release(c);
    invalid(GENERAL, SOLARIS_EINVAL);
    invalid(DIRECT "[Rule]\nDOMAIN,example.com,DIRECT\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Rule]\nFINAL,DIRECT\nFINAL,REJECT\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Rule]\nFINAL,DIRECT\nDOMAIN,example.com,DIRECT\n", SOLARIS_EINVAL);
    invalid(GENERAL "[Rule]\nFINAL,MISSING\n", SOLARIS_EINVAL);
    invalid(GENERAL "[Rule]\nMATCH,DIRECT\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy]\nDIRECT = direct\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy]\na = direct\na = reject\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy]\na = direct\n[Proxy Group]\na = select, DIRECT\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy Group]\na = select, b\nb = select, a\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy Group]\na = select, DIRECT, DIRECT\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy Group]\na = select\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy Group]\na = url-test, DIRECT\n", SOLARIS_ENOTSUP);
    invalid(DIRECT "[Proxy]\na = socks5, x, 1, network=ws\n", SOLARIS_ENOTSUP);
    invalid(DIRECT "[Proxy]\na = socks5, x, 1, password=SECRET-CREDENTIAL\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy]\na = socks5, x, 1, ca-pem=SECRET-CREDENTIAL\n", SOLARIS_ENOTSUP);
}
static void lexical(void) {
    solaris_config_t *c = valid(
        "\xef\xbb\xbf[General]\r\nconfig-version = 1 # v1\r\nmode = direct ; mode\r\n"
        "[Proxy] // nodes\r\n\"\xe9\xa6\x99\xe6\xb8\xaf,= #; //\" = socks5, x, 0010, username=00123, password=\"p,a=ss\\\"\\\\#; //\"\r\n"
        "[Proxy Group]\r\n\"\xe5\x87\xba\xe5\x8f\xa3,=\" = select, \"\xe9\xa6\x99\xe6\xb8\xaf,= #; //\", DIRECT\r\n"
        "[Rule]\r\nFINAL,\"\xe5\x87\xba\xe5\x8f\xa3,=\"\r\n");
    CHECK(node_field(c, "port")->value.integer == 10);
    CHECK(!strcmp(node_field(c, "username")->value.string.data, "00123"));
    CHECK(!strcmp(node_field(c, "password")->value.string.data, "p,a=ss\"\\#; //"));
    size_t count;
    const solaris_config_node_t *nodes = solaris_config_nodes(c, &count);
    CHECK(!strcmp(nodes[2].name, "\xe9\xa6\x99\xe6\xb8\xaf,= #; //"));
    solaris_config_release(c);
    c = valid(DIRECT "[Proxy]\np = socks5, x, 1080, username=true, password=https://x/a#part;tail?x=a=b\n");
    CHECK(!strcmp(node_field(c, "username")->value.string.data, "true"));
    CHECK(!strcmp(node_field(c, "password")->value.string.data, "https://x/a#part;tail?x=a=b"));
    solaris_config_release(c);
    const char *bad[] = {"",
                         "{}",
                         "mode: direct\n",
                         "[General]\nmode=direct\n",
                         "[General]\nconfig-version=2\n",
                         GENERAL "mode=direct\nmode=global\n",
                         DIRECT "[General]\n",
                         DIRECT "[Proxy]\np=socks5,x,1,password=\"bad\\q\"\n",
                         DIRECT "[Proxy]\np=socks5,x,1,password=\"bad\n",
                         DIRECT "[Proxy]\np=socks5,x,1,password=\"a\"b\n",
                         DIRECT "[Proxy]\np=socks5,x,1,password=\"a\"\"b\"\n",
                         DIRECT "[Proxy]\np=socks5,x,1,\n",
                         DIRECT "[Proxy]\np=socks5,x,1,udp-relay=1\n",
                         DIRECT "[Proxy]\np=socks5,x,0x10\n",
                         DIRECT "[Proxy]\np=socks5,x,+10\n",
                         DIRECT "[Proxy]\np=socks5,x,1_000\n",
                         DIRECT "[Proxy]\np=socks5,x,1,udp-relay=yes\n",
                         DIRECT "[Proxy]\np=socks5,x,1,udp-relay=True\n",
                         DIRECT "[Proxy]\np=socks5,x,1,udp-relay=true,udp-relay=false\n",
                         DIRECT "[Proxy]\np=socks5,x,1,password=\n",
                         DIRECT "[Proxy]\np=socks5,x\n",
                         "[General] trailing\n"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        invalid(bad[i], SOLARIS_EINVAL);
    invalid(DIRECT "[TUN]\n", SOLARIS_ENOTSUP);
    invalid(DIRECT "[Unknown]\n", SOLARIS_ENOTSUP);
    invalid(DIRECT "#!include SECRET-CREDENTIAL\n", SOLARIS_ENOTSUP);
    invalid(DIRECT "SECRET-CREDENTIAL=value\n", SOLARIS_ENOTSUP);
    const char nul[] = DIRECT "\0";
    invalid_bytes(nul, sizeof(nul) - 1, SOLARIS_EINVAL);
    invalid(DIRECT "# invalid \xc0\xaf\n", SOLARIS_EINVAL);
    invalid(DIRECT "# invalid \xed\xa0\x80\n", SOLARIS_EINVAL);
    invalid(DIRECT "# invalid \xf4\x90\x80\x80\n", SOLARIS_EINVAL);
    invalid(DIRECT "# misplaced \xef\xbb\xbf\n", SOLARIS_EINVAL);
}
static void protocols(void) {
    solaris_config_t *c;
#if SOLARIS_HAS_SHADOWSOCKS
    c = valid(DIRECT "[Proxy]\np = ss, example.com, 443, encrypt-method=aes-128-gcm, password=secret, "
                     "udp-relay=true, udp-over-tcp=true, udp-over-tcp-version=2\n");
    CHECK(node_field(c, "udp-over-tcp")->value.boolean && !node_field(c, "udp-over-tcp-version"));
    solaris_config_release(c);
    invalid(DIRECT "[Proxy]\np = ss, x, 443, encrypt-method=wrong, password=SECRET-CREDENTIAL\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy]\np = ss, x, 443, encrypt-method=aes-128-gcm, password=secret, udp-over-tcp=true\n",
            SOLARIS_ENOTSUP);
#endif
#if SOLARIS_HAS_VLESS
    c = valid(DIRECT "[Proxy]\np = vless, x, 443, uuid=00000000-0000-0000-0000-000000000001, tls=true, "
                     "tls-server-name=sni.example, flow=xtls-rprx-vision, encryption=none, packet-encoding=xudp\n");
    CHECK(node_field(c, "tls")->value.boolean && !node_field(c, "encryption"));
    solaris_config_release(c);
    c = valid(DIRECT "[Proxy]\np = vless, x, 443, uuid=00000000-0000-0000-0000-000000000001, flow=xtls-rprx-vision, "
                     "encryption=mlkem768x25519plus.native.1rtt.hSDwCYkwp1R0i33ctD73Wg2_Og0mOBr066SpjqqbTmo\n");
    CHECK(node_field(c, "encryption") && !node_field(c, "tls")->value.boolean);
    solaris_config_release(c);
    invalid(DIRECT "[Proxy]\np = vless, x, 443, uuid=invalid\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Proxy]\np = vless, x, 443, uuid=00000000-0000-0000-0000-000000000001, flow=xtls-rprx-vision\n",
            SOLARIS_EINVAL);
    invalid(DIRECT
            "[Proxy]\np = vless, x, 443, uuid=00000000-0000-0000-0000-000000000001, packet-encoding=packetaddr\n",
            SOLARIS_ENOTSUP);
#endif
#if SOLARIS_HAS_ANYTLS
    c = valid(DIRECT "[Proxy]\np = anytls, x, 443, password=secret, tls-server-name=sni.example, "
                     "idle-session-timeout-ms=17000, idle-session-check-interval-ms=3000, min-idle-session=2\n");
    CHECK(node_field(c, "tls")->value.boolean && node_field(c, "idle-session-timeout-ms")->value.integer == 17000 &&
          node_field(c, "idle-session-check-interval-ms")->value.integer == 3000 &&
          node_field(c, "min-idle-session")->value.integer == 2);
    solaris_config_release(c);
    c = valid(DIRECT "[Proxy]\np = anytls, x, 443, password=secret\n");
    CHECK(node_field(c, "idle-session-timeout-ms")->value.integer == 30000 &&
          node_field(c, "idle-session-check-interval-ms")->value.integer == 30000);
    solaris_config_release(c);
    invalid(DIRECT "[Proxy]\np = anytls, x, 443, password=secret, idle-session-timeout-ms=0\n", SOLARIS_EINVAL);
#endif
    c = valid(DIRECT "[Proxy]\np=socks5,x,1080,username=null,password=08\n");
    CHECK(!strcmp(node_field(c, "username")->value.string.data, "null") &&
          !strcmp(node_field(c, "password")->value.string.data, "08"));
    solaris_config_release(c);
}
static void listeners(void) {
#if SOLARIS_HAS_PROXY_INBOUND
    solaris_config_t *c = valid(listener_sample);
    size_t count;
    const solaris_config_listener_t *items = solaris_config_listeners(c, &count);
    CHECK(count == 4 && items[0].auth_count == 2 && items[1].auth_count == 2 && items[2].auth_count == 1 &&
          !items[3].auth_count);
    CHECK(items[0].protocol == 1 && !items[0].udp && items[1].listen.family == SOLARIS_ADDRESS_IPV6 && items[1].udp);
    CHECK(!items[2].udp && !strcmp(items[2].auth[0].username, "client") &&
          !strcmp(items[0].auth[1].username, "user:two"));
    CHECK(!strcmp(items[0].auth[1].password, "p,a=ss\"\\#; //"));
    solaris_config_release(c);
    invalid(DIRECT "http-listen = 127.0.0.1:7890\nsocks-listen = 127.0.0.1:7890\n", SOLARIS_EINVAL);
    invalid(DIRECT "http-listen = localhost:7890\n", SOLARIS_EINVAL);
    invalid(DIRECT "http-listen = 127.0.0.1:0\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Listener]\nx = http, 127.0.0.1, 1, udp-relay=false\n", SOLARIS_ENOTSUP);
    invalid(DIRECT "[Listener]\nx = socks5, 127.0.0.1, 0\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Listener]\nx = socks5, 127.0.0.1, 1, authentication=missing\n", SOLARIS_EINVAL);
    invalid(DIRECT "authentication=missing\n", SOLARIS_EINVAL);
    invalid(DIRECT "[Authentication]\np = u=a,u=b\n", SOLARIS_EINVAL);
#else
    invalid(DIRECT "http-listen = 127.0.0.1:7890\n", SOLARIS_ENOTSUP);
#endif
}
typedef struct allocation {
    size_t calls, fail, live;
} allocation_t;
static void *allocate(void *context, size_t size) {
    allocation_t *a = context;
    if (++a->calls == a->fail)
        return NULL;
    void *p = malloc(size);
    if (p)
        a->live++;
    return p;
}
static void deallocate(void *context, void *pointer) {
    allocation_t *a = context;
    CHECK(a->live);
    a->live--;
    free(pointer);
}
static void failure_input(const char *input) {
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
    printf("Injected failures at %zu allocation sites, across lexer, AST and owned image\n", count);
}
static void failures(void) {
    failure_input(sample);
#if SOLARIS_HAS_PROXY_INBOUND
    failure_input(listener_sample);
#endif
}
static void worker(void *context) {
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
static void concurrent(void) {
    solaris_config_t *c = valid(sample);
    uv_thread_t threads[8];
    for (unsigned i = 0; i < 8; ++i)
        CHECK(!uv_thread_create(&threads[i], worker, c));
    for (unsigned i = 0; i < 8; ++i)
        CHECK(!uv_thread_join(&threads[i]));
    solaris_config_release(c);
}
int main(int argc, char **argv) {
    basics();
    lexical();
    protocols();
    listeners();
    failures();
    concurrent();
    if (argc > 1) {
        solaris_config_t *c;
        solaris_diagnostics_t *d;
        CHECK(solaris_config_compile_file(argv[1], NULL, &c, &d, NULL) == SOLARIS_OK);
        CHECK(solaris_config_base_directory(c));
        solaris_config_release(c);
        solaris_diagnostics_release(d);
    }
    puts("Solaris Conf v1 syntax, typed model, protocols, listeners, allocation rollback and concurrent ownership "
         "passed");
    return 0;
}
