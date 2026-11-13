/* Native conformance driver: owned config image and ordered route job.
 * No sockets are opened. DNS answers and leaf capabilities are controlled
 * inputs so matcher results have no network/environment drift. */
#include "codec/address/socks.h"
#include "contracts/config/image.h"
#include "runtime/executor/executor.h"
#include "solaris_builtin_modules.h"
#include "support/runtime/event.h"
#include <inttypes.h>
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
static const solaris_config_node_t *nodes;
static size_t node_count;
static const solaris_config_group_t *groups;
static size_t group_count;
static const char *route_original;
static solaris_address_t route_input;
static void string(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\')
            printf("\\%c", *p);
        else if (*p < 32)
            printf("\\u%04x", (unsigned)*p);
        else
            putchar(*p);
    }
    putchar('"');
}
static void key(const char *name) {
    string(name);
    putchar(':');
}
static const char *name_of(uint64_t id) {
    for (size_t i = 0; i < node_count; ++i)
        if (nodes[i].id == id)
            return nodes[i].name;
    for (size_t i = 0; i < group_count; ++i)
        if (groups[i].id == id)
            return groups[i].name;
    abort();
}
static const char *field_text(const solaris_config_view_t *view, const char *name) {
    const solaris_config_view_t *v = solaris_config_get(view, name);
    if (!v)
        return "";
    CHECK(v->kind == SOLARIS_CONFIG_STRING);
    return v->value.string.data;
}
static int64_t field_integer(const solaris_config_view_t *view, const char *name) {
    const solaris_config_view_t *v = solaris_config_get(view, name);
    if (!v)
        return 0;
    CHECK(v->kind == SOLARIS_CONFIG_INTEGER || v->kind == SOLARIS_CONFIG_BOOL);
    return v->kind == SOLARIS_CONFIG_BOOL ? v->value.boolean : v->value.integer;
}
static void text_field(const solaris_config_view_t *view, const char *name) {
    putchar(',');
    key(name);
    string(field_text(view, name));
}
static void bool_field(const solaris_config_view_t *view, const char *name) {
    putchar(',');
    key(name);
    fputs(field_integer(view, name) ? "true" : "false", stdout);
}
static void int_field(const solaris_config_view_t *view, const char *name) {
    putchar(',');
    key(name);
    printf("%" PRId64, field_integer(view, name));
}
static void address_text(const solaris_address_t *a, char *out, size_t size) {
    if (a->family == SOLARIS_ADDRESS_DOMAIN) {
        (void)snprintf(out, size, "%s", a->host);
        return;
    }
    CHECK((a->family == SOLARIS_ADDRESS_IPV4 ? uv_inet_ntop(AF_INET, a->ip, out, size)
                                             : uv_inet_ntop(AF_INET6, a->ip, out, size)) == 0);
}
static void dump_nodes(void) {
    fputs("\"nodes\":[", stdout);
    for (size_t i = 0; i < node_count; ++i) {
        const solaris_config_node_t *n = &nodes[i];
        const solaris_config_view_t *v = n->fields;
        if (i)
            putchar(',');
        fputs("{\"name\":", stdout);
        string(n->name);
        fputs(",\"type\":", stdout);
        string(!strcmp(n->type, "block") ? "reject" : !strcmp(n->type, "shadowsocks") ? "ss" : n->type);
        printf(",\"udp\":%s,\"fields\":{", n->udp_enabled ? "true" : "false");
        if (strcmp(n->type, "direct") && strcmp(n->type, "block")) {
            fputs("\"server\":", stdout);
            string(field_text(v, "server"));
            int_field(v, "port");
            if (!strcmp(n->type, "socks5")) {
                text_field(v, "username");
                text_field(v, "password");
            } else if (!strcmp(n->type, "shadowsocks")) {
                text_field(v, "cipher");
                text_field(v, "password");
                bool_field(v, "udp-over-tcp");
                if (field_integer(v, "udp-over-tcp"))
                    fputs(",\"udp-over-tcp-version\":2", stdout);
            } else if (!strcmp(n->type, "vless")) {
                char uuid[33] = {0};
                const char *s = field_text(v, "uuid");
                size_t k = 0;
                for (; *s; ++s)
                    if (*s != '-')
                        uuid[k++] = *s >= 'A' && *s <= 'F' ? (char)(*s + 32) : *s;
                fputs(",\"uuid\":", stdout);
                string(uuid);
                text_field(v, "flow");
                text_field(v, "encryption");
                text_field(v, "servername");
                bool_field(v, "tls");
                fputs(",\"packet-encoding\":\"xudp\"", stdout);
            } else if (!strcmp(n->type, "anytls")) {
                text_field(v, "password");
                text_field(v, "servername");
                bool_field(v, "tls");
                int_field(v, "idle-session-timeout-ms");
                int_field(v, "idle-session-check-interval-ms");
                int_field(v, "min-idle-session");
            }
        }
        fputs("}}", stdout);
    }
    putchar(']');
}
static void dump_groups(void) {
    fputs(",\"groups\":[", stdout);
    for (size_t i = 0; i < group_count; ++i) {
        if (i)
            putchar(',');
        fputs("{\"name\":", stdout);
        string(groups[i].name);
        fputs(",\"selected\":", stdout);
        string(name_of(groups[i].selected_id));
        fputs(",\"members\":[", stdout);
        for (size_t j = 0; j < groups[i].member_count; ++j) {
            if (j)
                putchar(',');
            string(name_of(groups[i].members[j]));
        }
        fputs("]}", stdout);
    }
    putchar(']');
}
static void dump_listeners(const solaris_config_t *config) {
    size_t count;
    const solaris_config_listener_t *listeners = solaris_config_listeners(config, &count);
    fputs(",\"listeners\":[", stdout);
    for (size_t i = 0; i < count; ++i) {
        const solaris_config_listener_t *l = &listeners[i];
        char host[256], endpoint[300];
        address_text(&l->listen, host, sizeof(host));
        (void)snprintf(endpoint, sizeof(endpoint), l->listen.family == SOLARIS_ADDRESS_IPV6 ? "[%s]:%u" : "%s:%u", host,
                       l->listen.port);
        if (i)
            putchar(',');
        fputs("{\"name\":", stdout);
        string(l->name);
        fputs(",\"type\":", stdout);
        string(l->protocol == 1 ? "http" : l->protocol == 2 ? "socks" : "mixed");
        fputs(",\"address\":", stdout);
        string(endpoint);
        printf(",\"udp\":%s,\"auth\":[", l->udp ? "true" : "false");
        for (size_t j = 0; j < l->auth_count; ++j) {
            if (j)
                putchar(',');
            fputs("{\"username\":", stdout);
            string(l->auth[j].username);
            fputs(",\"password\":", stdout);
            string(l->auth[j].password);
            putchar('}');
        }
        fputs("]}", stdout);
    }
    putchar(']');
}
static void dump_rules(const solaris_config_t *config) {
    static const char *const names[] = {"",          "Domain",  "DomainSuffix", "DomainKeyword", "IPCIDR", "IPCIDR",
                                        "SrcIPCIDR", "SrcPort", "DstPort",      "Network",       "Final"};
    size_t count;
    const solaris_route_rule_t *rules = solaris_config_rules(config, &count);
    fputs(",\"rules\":[", stdout);
    for (size_t i = 0; i < count; ++i) {
        const solaris_route_rule_t *r = &rules[i];
        char value[300] = {0};
        if (r->kind <= SOLARIS_ROUTE_DOMAIN_KEYWORD)
            (void)snprintf(value, sizeof(value), "%s", r->domain);
        else if (r->kind <= SOLARIS_ROUTE_SRC_IP_CIDR) {
            char host[256];
            address_text(&r->address, host, sizeof(host));
            (void)snprintf(value, sizeof(value), "%s/%u", host, r->prefix_length);
        } else if (r->kind == SOLARIS_ROUTE_SRC_PORT || r->kind == SOLARIS_ROUTE_DST_PORT) {
            if (r->port_first == r->port_last)
                (void)snprintf(value, sizeof(value), "%u", r->port_first);
            else
                (void)snprintf(value, sizeof(value), "%u-%u", r->port_first, r->port_last);
        } else if (r->kind == SOLARIS_ROUTE_NETWORK)
            (void)snprintf(value, sizeof(value), "%s", r->network == SOLARIS_NETWORK_TCP ? "tcp" : "udp");
        if (i)
            putchar(',');
        fputs("{\"type\":", stdout);
        string(names[r->kind]);
        fputs(",\"value\":", stdout);
        string(value);
        fputs(",\"target\":", stdout);
        string(name_of(r->target_id));
        /* Effective semantics: source CIDR never resolves the destination. */
        printf(",\"no-resolve\":%s}", r->no_resolve || r->kind == SOLARIS_ROUTE_SRC_IP_CIDR ? "true" : "false");
    }
    putchar(']');
}
static void dump_representation(const solaris_config_t *config) {
    /* Keep the pre-projection fields alongside the comparable semantic view. */
    fputs(",\"representation\":{\"rules\":[", stdout);
    size_t count;
    const solaris_route_rule_t *rules = solaris_config_rules(config, &count);
    for (size_t i = 0; i < count; ++i) {
        if (i)
            putchar(',');
        printf("{\"kind\":%u,\"no-resolve\":%s}", rules[i].kind, rules[i].no_resolve ? "true" : "false");
    }
    fputs("],\"vless\":[", stdout);
    size_t written = 0;
    for (size_t i = 0; i < node_count; ++i)
        if (!strcmp(nodes[i].type, "vless")) {
            if (written++)
                putchar(',');
            fputs("{\"name\":", stdout);
            string(nodes[i].name);
            text_field(nodes[i].fields, "uuid");
            text_field(nodes[i].fields, "flow");
            putchar('}');
        }
    putchar(']');
    if (route_original) {
        fputs(",\"route_metadata\":{\"input_host\":", stdout);
        string(route_original);
        fputs(",\"effective_host\":", stdout);
        string(route_input.host);
        putchar('}');
    }
    putchar('}');
}

typedef struct route_context {
    solaris_config_t *config;
    solaris_executor_t *owner;
    solaris_outbound_t leaf;
    solaris_route_options_t options;
    solaris_test_event_t done;
    solaris_address_t answer;
    solaris_resolve_fn callback;
    void *callback_user;
    unsigned calls;
    int has_answer;
} route_context_t;
static void release_leaf(void *context) { (void)context; }
static solaris_status_t acquire(void *context, solaris_executor_t *owner, uint64_t id, solaris_dial_plan_t *plan,
                                uint32_t *caps) {
    route_context_t *c = context;
    for (size_t i = 0; i < group_count; ++i)
        if (groups[i].id == id) {
            id = groups[i].selected_id;
            break;
        }
    for (size_t i = 0; i < node_count; ++i)
        if (nodes[i].id == id) {
            c->leaf.owner = owner;
            *caps = SOLARIS_OUTBOUND_STREAM | (nodes[i].udp_enabled ? SOLARIS_OUTBOUND_DATAGRAM : 0);
            *plan = (solaris_dial_plan_t){.outbound = &c->leaf, .context = c, .release = release_leaf, .node_id = id};
            return SOLARIS_OK;
        }
    return SOLARIS_EINVAL;
}
static void resolved(void *context, solaris_status_t status) {
    route_context_t *c = context;
    CHECK(status == SOLARIS_OK);
    c->callback(c->callback_user, c->has_answer ? SOLARIS_OK : SOLARIS_EIO, c->has_answer ? &c->answer : NULL,
                (size_t)c->has_answer);
}
static solaris_status_t resolve(void *context, solaris_executor_t *owner, const solaris_address_t *target,
                                uint64_t timeout, solaris_resolve_fn callback, void *user, void **request) {
    route_context_t *c = context;
    (void)target;
    (void)timeout;
    ++c->calls;
    c->callback = callback;
    c->callback_user = user;
    *request = c;
    return solaris_executor_post(owner, resolved, c);
}
static void cancel_resolve(void *context, void *request) {
    (void)context;
    (void)request;
}
static void routed(void *context, solaris_status_t status, solaris_route_result_t *result) {
    route_context_t *c = context;
    fputs(",\"route\":{", stdout);
    if (status != SOLARIS_OK)
        printf("\"status\":%d", status);
    else {
        fputs("\"node\":", stdout);
        string(name_of(result->plan.node_id));
        printf(",\"rule\":%" PRId64 ",\"udp\":%s",
               result->rule_index == UINT64_MAX ? INT64_C(-1) : (int64_t)result->rule_index,
               result->effective_capabilities & SOLARIS_OUTBOUND_DATAGRAM ? "true" : "false");
    }
    printf(",\"dns_calls\":%u}", c->calls);
    solaris_test_event_signal(&c->done);
}
static void start(void *context, solaris_status_t status) {
    route_context_t *c = context;
    solaris_route_job_t *job;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_route_start(&c->options, &job) == SOLARIS_OK);
}
static void dump_route(solaris_config_t *config, solaris_mode_t mode, char **args) {
    route_context_t c = {.config = config};
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(2 * 1024 * 1024, NULL, &budget) == SOLARIS_OK);
    solaris_executor_options_t opts = {.id = 0, .queue_capacity = 16, .resource_limit = 32, .budget = budget};
    CHECK(solaris_executor_create(&opts, &c.owner) == SOLARIS_OK);
    CHECK(solaris_test_event_init(&c.done, 0) == 0);
    c.options = (solaris_route_options_t){.owner = c.owner,
                                          .mode = mode,
                                          .direct_target = solaris_config_direct_target(config),
                                          .global_target = solaris_config_global_target(config),
                                          .timeout_ms = 5000,
                                          .context = &c,
                                          .acquire = acquire,
                                          .resolve = resolve,
                                          .cancel_resolve = cancel_resolve,
                                          .done = routed,
                                          .user = &c};
    c.options.rules = solaris_config_rules(config, &c.options.rule_count);
    c.options.metadata.network = !strcmp(args[0], "udp") ? SOLARIS_NETWORK_UDP : SOLARIS_NETWORK_TCP;
    solaris_address_t encoded, decoded;
    uint8_t wire[300];
    size_t written, consumed;
    CHECK(solaris_address_parse(args[1], (uint16_t)strtoul(args[2], NULL, 10), &encoded) == SOLARIS_OK);
    /* Preserve exact input spelling on the wire, then use the actual inbound
     * address decoder and the same domain normalization as proxy/socks5.c. */
    if (encoded.family == SOLARIS_ADDRESS_DOMAIN)
        (void)snprintf(encoded.host, sizeof(encoded.host), "%s", args[1]);
    CHECK(solaris_socks_address_encode(&encoded, wire, sizeof(wire), &written) == SOLARIS_OK);
    CHECK(solaris_socks_address_decode(wire, written, &decoded, &consumed) == SOLARIS_OK && consumed == written);
    c.options.metadata.destination = decoded;
    if (decoded.family == SOLARIS_ADDRESS_DOMAIN)
        CHECK(solaris_address_parse(decoded.host, decoded.port, &c.options.metadata.destination) == SOLARIS_OK);
    route_original = args[1];
    route_input = c.options.metadata.destination;
    CHECK(solaris_address_parse(args[3], (uint16_t)strtoul(args[4], NULL, 10), &c.options.metadata.source) ==
          SOLARIS_OK);
    c.has_answer = strcmp(args[5], "-") != 0;
    if (c.has_answer)
        CHECK(solaris_address_parse(args[5], c.options.metadata.destination.port, &c.answer) == SOLARIS_OK);
    CHECK(solaris_executor_activate(c.owner, 1) == SOLARIS_OK);
    CHECK(solaris_executor_post(c.owner, start, &c) == SOLARIS_OK);
    solaris_test_event_wait(&c.done);
    CHECK(solaris_executor_quiesce(c.owner) == SOLARIS_OK);
    CHECK(solaris_executor_destroy(c.owner) == SOLARIS_OK);
    solaris_test_event_destroy(&c.done);
    CHECK(solaris_budget_used(budget) == 0);
    solaris_budget_release(budget);
}
int main(int argc, char **argv) {
    CHECK(argc == 1 || argc == 7);
    char *input = malloc(1024 * 1024 + 1);
    CHECK(input);
    size_t length = fread(input, 1, 1024 * 1024 + 1, stdin);
    CHECK(!ferror(stdin) && length <= 1024 * 1024);
    solaris_config_t *config = NULL;
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_error_t error;
    solaris_status_t status = solaris_config_compile_bytes(input, length, NULL, &config, &diagnostics, &error);
    free(input);
    printf("{\"ok\":%s,\"status\":%d,\"capabilities\":{\"inbound\":%s,\"ss\":%s,\"vless\":%s,\"anytls\":%s}",
           status == SOLARIS_OK ? "true" : "false", status, SOLARIS_HAS_PROXY_INBOUND ? "true" : "false",
           SOLARIS_HAS_SHADOWSOCKS ? "true" : "false", SOLARIS_HAS_VLESS ? "true" : "false",
           SOLARIS_HAS_ANYTLS ? "true" : "false");
    if (status == SOLARIS_OK) {
        solaris_config_snapshot_t snapshot;
        CHECK(solaris_config_get_snapshot(config, &snapshot) == SOLARIS_OK);
        nodes = solaris_config_nodes(config, &node_count);
        groups = solaris_config_groups(config, &group_count);
        fputs(",\"mode\":", stdout);
        string(snapshot.mode == SOLARIS_MODE_DIRECT   ? "direct"
               : snapshot.mode == SOLARIS_MODE_GLOBAL ? "global"
                                                      : "rule");
        putchar(',');
        dump_nodes();
        dump_groups();
        dump_listeners(config);
        dump_rules(config);
        if (argc == 7)
            dump_route(config, snapshot.mode, argv + 1);
        dump_representation(config);
    } else {
        fputs(",\"diagnostics\":[", stdout);
        for (size_t i = 0; i < solaris_diagnostics_count(diagnostics); ++i) {
            solaris_config_diagnostic_t d;
            CHECK(solaris_diagnostics_get(diagnostics, i, &d) == SOLARIS_OK);
            if (i)
                putchar(',');
            fputs("{\"path\":", stdout);
            string(d.path);
            printf(",\"line\":%u,\"column\":%u,\"status\":%d}", d.line, d.column, d.status);
        }
        putchar(']');
    }
    puts("}");
    solaris_diagnostics_release(diagnostics);
    solaris_config_release(config);
    return 0;
}
