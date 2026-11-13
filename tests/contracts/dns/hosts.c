#include "contracts/dns/hosts.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct fixture { atomic_size_t calls, fail_at; solaris_budget_t *budget; unsigned groups; } fixture_t;
static void *allocate(void *context, size_t n)
{
    fixture_t *f = context; size_t call = atomic_fetch_add(&f->calls, 1u) + 1u;
    return call == atomic_load(&f->fail_at) ? NULL : malloc(n);
}
static void deallocate(void *context, void *p) { (void)context; free(p); }
static solaris_address_t address(uint32_t family, uint8_t last)
{
    solaris_address_t a; memset(&a, 0, sizeof(a)); a.family = family;
    if (family == 4) { a.ip[0] = 192; a.ip[1] = 0; a.ip[2] = 2; a.ip[3] = last; }
    else { a.ip[0] = 0xfd; a.ip[15] = last; }
    return a;
}
static solaris_hosts_t *build(fixture_t *f, const solaris_hosts_entry_t *config, size_t n,
    const solaris_hosts_entry_t *system, size_t m)
{
    solaris_hosts_t *h = NULL; solaris_hosts_diagnostic_t d;
    CHECK(solaris_hosts_build(f->budget, config, n, system, m, NULL, &h, &d) == SOLARIS_OK && h && !d.status);
    return h;
}
static solaris_hosts_result_t lookup(const solaris_hosts_t *h, const char *name, uint32_t family)
{
    solaris_hosts_result_t r; CHECK(solaris_hosts_lookup(h, name, family, &r) == SOLARIS_OK); return r;
}
static void defaults(fixture_t *f)
{
    solaris_address_t six = address(6, 2);
    solaris_hosts_entry_t system = {"localhost", SOLARIS_HOSTS_ADDRESSES, &six, 1, NULL};
    solaris_hosts_t *h = build(f, NULL, 0, &system, 1);
    solaris_hosts_result_t r = lookup(h, "LOCALHOST.", 0);
    CHECK(r.matched && r.source == SOLARIS_HOSTS_DEFAULT && r.address_count == 1);
    CHECK(r.addresses[0].family == 4 && r.addresses[0].ip[0] == 127 && r.addresses[0].ip[3] == 1);
    r = lookup(h, "localhost", 6); CHECK(r.matched && r.kind == SOLARIS_HOSTS_ADDRESSES && !r.address_count);
    r = lookup(h, "absent.example", 4); CHECK(!r.matched && !r.address_count);
    solaris_hosts_release(h);
    h = build(f, &system, 1, NULL, 0); r = lookup(h, "localhost", 6);
    CHECK(r.source == SOLARIS_HOSTS_CONFIG && r.address_count == 1 && r.addresses[0].family == 6);
    r = lookup(h, "localhost", 4); CHECK(r.matched && !r.address_count);
    CHECK(solaris_hosts_lookup(h, "localhost", 255, &r) == SOLARIS_EINVAL && !r.matched);
    CHECK(solaris_hosts_lookup(h, "*.example", 0, &r) == SOLARIS_EINVAL);
    solaris_hosts_release(h); f->groups++;
}
static void priorities(fixture_t *f)
{
    /* Goldens exercise the fixed reference's recursive branch ordering,
     * including a static suffix that outranks an exact-depth wildcard path. */
    const char *patterns[] = {".example.com", "*.example.com", "x.*.example.com", "x.foo.example.com",
        "+.base.example", ".apple.*", "*.tail", "node.*.tail", ".tail", ".foo.com", "x.*.com"};
    struct query { const char *name; uint8_t id; } queries[] = {
        {"example.com", 0}, {"foo.example.com", 2}, {"x.foo.example.com", 4}, {"x.bar.example.com", 3},
        {"y.foo.example.com", 1}, {"x.other.deep.example.com", 1}, {"base.example", 5},
        {"a.b.base.example", 5}, {"test.apple.com", 6}, {"apple.com", 0}, {"one.tail", 7},
        {"node.mid.tail", 8}, {"x.mid.tail", 9}, {"tail", 0}, {"x.foo.com", 10}, {"x.bar.com", 11}
    };
    solaris_address_t values[11]; solaris_hosts_entry_t entries[11], reversed[11];
    for (size_t i = 0; i < 11; i++) {
        values[i] = address(4, (uint8_t)(i + 1));
        entries[i] = (solaris_hosts_entry_t){patterns[i], SOLARIS_HOSTS_ADDRESSES, &values[i], 1, NULL};
        reversed[10u - i] = entries[i];
    }
    for (unsigned permutation = 0; permutation < 2; permutation++) {
        solaris_hosts_t *h = build(f, permutation ? reversed : entries, 11, NULL, 0);
        for (size_t i = 0; i < sizeof(queries) / sizeof(*queries); i++) {
            solaris_hosts_result_t r = lookup(h, queries[i].name, 4);
            CHECK(r.matched == (queries[i].id != 0));
            if (r.matched) CHECK(r.address_count == 1 && r.addresses[0].ip[3] == queries[i].id);
        }
        solaris_hosts_release(h);
    }
    solaris_address_t config_ip = address(4, 41), system_ip = address(6, 42);
    solaris_hosts_entry_t config = {"*.layer.example", SOLARIS_HOSTS_ADDRESSES, &config_ip, 1, NULL};
    solaris_hosts_entry_t system = {"one.layer.example", SOLARIS_HOSTS_ADDRESSES, &system_ip, 1, NULL};
    solaris_hosts_t *h = build(f, &config, 1, &system, 1);
    solaris_hosts_result_t r = lookup(h, "one.layer.example", 6);
    CHECK(r.source == SOLARIS_HOSTS_CONFIG && r.matched && !r.address_count);
    solaris_hosts_release(h); f->groups++;
}
static void aliases_and_copy(fixture_t *f)
{
    solaris_address_t *ips = malloc(3u * sizeof(*ips)); CHECK(ips);
    ips[0] = address(6, 6); ips[1] = address(4, 4); ips[2] = address(6, 0);
    memset(ips[2].ip, 0, 16); ips[2].ip[10] = ips[2].ip[11] = 255;
    ips[2].ip[12] = 192; ips[2].ip[14] = 2; ips[2].ip[15] = 8;
    char *name = malloc(32), *alias = malloc(32); CHECK(name && alias);
    strcpy(name, "HEAD.EXAMPLE."); strcpy(alias, "middle.example");
    solaris_address_t sysip = address(4, 99);
    solaris_hosts_entry_t config[] = {
        {name, SOLARIS_HOSTS_ALIAS, NULL, 0, alias},
        {"middle.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "TERMINAL.EXAMPLE."},
        {"terminal.example", SOLARIS_HOSTS_ADDRESSES, ips, 3, NULL},
        {"external.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "next.example"},
        {"next.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "outside.example"},
        {"sys-alias.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "system.example"},
        {"local-alias.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "localhost"}
    };
    solaris_hosts_entry_t system = {"system.example", SOLARIS_HOSTS_ADDRESSES, &sysip, 1, NULL};
    solaris_hosts_t *h = build(f, config, 7, &system, 1);
    solaris_hosts_entry_t reversed[7];
    for (size_t i = 0; i < 7; i++) reversed[6u - i] = config[i];
    solaris_hosts_t *other_order = build(f, reversed, 7, &system, 1);
    memset(ips, 0xa5, 3u * sizeof(*ips)); free(ips); memset(name, 0, 32); free(name); memset(alias, 0, 32); free(alias);
    memset(config, 0, sizeof(config)); memset(&sysip, 0, sizeof(sysip));
    solaris_hosts_result_t r = lookup(h, "head.example", 0);
    CHECK(r.matched && r.kind == SOLARIS_HOSTS_ADDRESSES && r.alias_hops == 2 && r.address_count == 3);
    CHECK(!strcmp(r.first_alias, "middle.example") && !strcmp(r.terminal_name, "terminal.example"));
    CHECK(r.addresses[0].family == 6 && r.addresses[1].family == 4 && r.addresses[2].family == 4 && r.addresses[2].ip[3] == 8);
    solaris_hosts_result_t same = lookup(other_order, "head.example", 0);
    CHECK(same.alias_hops == r.alias_hops && same.address_count == r.address_count &&
          !strcmp(same.terminal_name, r.terminal_name) && !memcmp(same.addresses, r.addresses, sizeof(r.addresses)));
    solaris_hosts_release(other_order);
    r = lookup(h, "head.example", 4); CHECK(r.address_count == 2 && r.addresses[0].ip[3] == 4 && r.addresses[1].ip[3] == 8);
    r = lookup(h, "external.example", 0);
    CHECK(r.matched && r.kind == SOLARIS_HOSTS_ALIAS && r.alias_hops == 2 && !r.address_count);
    CHECK(!strcmp(r.first_alias, "next.example") && !strcmp(r.terminal_name, "outside.example"));
    r = lookup(h, "sys-alias.example", 4); CHECK(r.kind == SOLARIS_HOSTS_ALIAS && !r.address_count && !strcmp(r.terminal_name, "system.example"));
    r = lookup(h, "local-alias.example", 4); CHECK(r.address_count == 1 && r.addresses[0].ip[0] == 127);
    r = lookup(h, "system.example", 4); CHECK(r.source == SOLARIS_HOSTS_SYSTEM && r.addresses[0].ip[3] == 99);
    solaris_hosts_release(h); CHECK(r.addresses[0].ip[3] == 99 && !strcmp(r.terminal_name, "system.example")); f->groups++;
}
static void failure(fixture_t *f, const solaris_hosts_entry_t *entries, size_t count,
    const solaris_hosts_options_t *o, solaris_status_t expected, uint32_t reason)
{
    solaris_hosts_t *h = (void *)1; solaris_hosts_diagnostic_t d;
    size_t used = solaris_budget_used(f->budget);
    CHECK(solaris_hosts_build(f->budget, entries, count, NULL, 0, o, &h, &d) == expected && !h);
    CHECK(d.status == expected && d.reason == reason && d.message[0]);
    CHECK(solaris_budget_used(f->budget) == used);
}
static void alias_errors(fixture_t *f)
{
    solaris_hosts_entry_t graph[] = {
        {"one.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "two.example"},
        {"two.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "three.example"},
        {"three.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "one.example"}
    }, reversed[3];
    failure(f, graph, 3, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_ALIAS_CYCLE);
    for (size_t i = 0; i < 3; i++) reversed[2u - i] = graph[i];
    failure(f, reversed, 3, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_ALIAS_CYCLE);
    solaris_hosts_entry_t self = {"+.loop.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "inside.loop.example"};
    failure(f, &self, 1, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_ALIAS_CYCLE);
    graph[2].alias = "external.example";
    solaris_hosts_options_t o; solaris_hosts_options_init(&o); o.alias_depth = 2;
    failure(f, graph, 3, &o, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_ALIAS_DEPTH);
    for (size_t i = 0; i < 3; i++) reversed[2u - i] = graph[i];
    failure(f, reversed, 3, &o, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_ALIAS_DEPTH);
    solaris_hosts_t *h = NULL;
    CHECK(solaris_hosts_build(f->budget, graph + 1, 2, NULL, 0, &o, &h, NULL) == SOLARIS_OK);
    solaris_hosts_result_t r = lookup(h, "two.example", 0); CHECK(r.alias_hops == 2 && r.kind == SOLARIS_HOSTS_ALIAS);
    solaris_hosts_release(h); f->groups++;
}
static void invalid_and_limits(fixture_t *f)
{
    solaris_address_t ips[2] = {address(4, 1), address(6, 2)};
    solaris_hosts_entry_t e = {"ok.example", SOLARIS_HOSTS_ADDRESSES, ips, 1, NULL};
    const char *names[] = {"", ".", "..example", "a..b", "+", "a.+.b", "partial*.example", "*.x..", "sp ace.example", "\xc3\xa9.example"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) { e.name = names[i]; failure(f, &e, 1, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_NAME); }
    e.name = "ok.example"; e.address_count = 0; failure(f, &e, 1, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_INPUT);
    e.address_count = 1; ips[0].port = 80; failure(f, &e, 1, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_ADDRESS);
    ips[0].port = 0; ips[0].scope_id = 2; failure(f, &e, 1, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_ADDRESS); ips[0].scope_id = 0;
    solaris_hosts_entry_t duplicates[] = {e, e}; duplicates[1].name = "OK.EXAMPLE.";
    failure(f, duplicates, 2, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_DUPLICATE);
    duplicates[0].name = "+.example"; duplicates[1].name = "example";
    failure(f, duplicates, 2, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_DUPLICATE);
    duplicates[0].name = ".example"; duplicates[1].name = "+.example";
    failure(f, duplicates, 2, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_DUPLICATE);
    duplicates[0].name = duplicates[1].name = "localhost";
    failure(f, duplicates, 2, NULL, SOLARIS_EINVAL, SOLARIS_HOSTS_DUPLICATE);
    solaris_hosts_options_t o; solaris_hosts_options_init(&o); o.entries = 1;
    failure(f, &e, 1, &o, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_LIMIT);
    solaris_hosts_options_init(&o); o.nodes = 3; failure(f, &e, 1, &o, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_LIMIT);
    solaris_hosts_options_init(&o); o.address_total = 1; failure(f, &e, 1, &o, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_LIMIT);
    solaris_hosts_options_init(&o); o.addresses_per_entry = 1; e.address_count = 2;
    failure(f, &e, 1, &o, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_LIMIT);
    o.addresses_per_entry = 17; failure(f, &e, 1, &o, SOLARIS_EINVAL, SOLARIS_HOSTS_LIMIT);
    e.name = "*.system.example"; e.address_count = 1;
    solaris_hosts_t *h = NULL; solaris_hosts_diagnostic_t d;
    CHECK(solaris_hosts_build(f->budget, NULL, 0, &e, 1, NULL, &h, &d) == SOLARIS_EINVAL && !h && d.source == SOLARIS_HOSTS_SYSTEM && d.entry_index == 0);
    memset(&o, 0, sizeof(o)); CHECK(solaris_hosts_build(f->budget, NULL, 0, NULL, 0, &o, &h, &d) == SOLARIS_OK); solaris_hosts_release(h); f->groups++;
    solaris_address_t many[17];
    for (size_t i = 0; i < 17; i++) many[i] = address(i & 1u ? 6u : 4u, (uint8_t)(i + 1u));
    e = (solaris_hosts_entry_t){"limit.example", SOLARIS_HOSTS_ADDRESSES, many, 16, NULL};
    h = build(f, &e, 1, NULL, 0); solaris_hosts_result_t r = lookup(h, "limit.example", 0);
    CHECK(r.address_count == 16 && r.addresses[15].ip[15] == 16); solaris_hosts_release(h);
    e.address_count = 17; failure(f, &e, 1, NULL, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_LIMIT);
}
static void allocation_failures(fixture_t *f)
{
    solaris_address_t ips[] = {address(4, 1), address(6, 2)};
    solaris_hosts_entry_t e[] = {{"first.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "tail.example"},
        {"tail.example", SOLARIS_HOSTS_ADDRESSES, ips, 2, NULL},
        {"+.many.example", SOLARIS_HOSTS_ADDRESSES, ips, 2, NULL}};
    size_t before = atomic_load(&f->calls); solaris_hosts_t *h = build(f, e, 3, NULL, 0);
    size_t count = atomic_load(&f->calls) - before; solaris_hosts_release(h);
    CHECK(count > 5 && solaris_budget_used(f->budget) == 0);
    for (size_t i = 1; i <= count; i++) {
        atomic_store(&f->fail_at, atomic_load(&f->calls) + i);
        failure(f, e, 3, NULL, SOLARIS_ENOMEM, SOLARIS_HOSTS_MEMORY);
        atomic_store(&f->fail_at, 0);
    }
    h = build(f, e, 3, NULL, 0); solaris_hosts_release(h); CHECK(solaris_budget_used(f->budget) == 0); f->groups++;
}
typedef struct reader { const solaris_hosts_t *hosts; unsigned id; } reader_t;
static void read_thread(void *context)
{
    reader_t *r = context;
    for (unsigned i = 0; i < 1000; i++) {
        solaris_hosts_retain(r->hosts);
        solaris_hosts_result_t result = lookup(r->hosts, "x.child.example", r->id & 1u ? 6u : 4u);
        CHECK(result.matched && result.alias_hops == 1 && result.address_count == 1);
        CHECK(result.addresses[0].family == (r->id & 1u ? 6u : 4u));
        solaris_hosts_release(r->hosts);
    }
    solaris_hosts_release(r->hosts);
}
static void concurrent_readers(fixture_t *f)
{
    solaris_address_t ips[] = {address(4, 1), address(6, 2)};
    solaris_hosts_entry_t e[] = {{"+.child.example", SOLARIS_HOSTS_ALIAS, NULL, 0, "target.example"},
        {"target.example", SOLARIS_HOSTS_ADDRESSES, ips, 2, NULL}};
    solaris_hosts_t *h = build(f, e, 2, NULL, 0); uv_thread_t threads[4]; reader_t readers[4];
    for (unsigned i = 0; i < 4; i++) { readers[i] = (reader_t){h, i}; solaris_hosts_retain(h); CHECK(!uv_thread_create(&threads[i], read_thread, &readers[i])); }
    solaris_hosts_release(h);
    for (unsigned i = 0; i < 4; i++) CHECK(!uv_thread_join(&threads[i]));
    CHECK(solaris_budget_used(f->budget) == 0); f->groups++;
}
int main(void)
{
    fixture_t f; memset(&f, 0, sizeof(f)); atomic_init(&f.calls, 0); atomic_init(&f.fail_at, 0);
    solaris_runtime_services_t services = {.context = &f, .allocate = allocate, .deallocate = deallocate};
    CHECK(solaris_budget_create(16u * 1024u * 1024u, &services, &f.budget) == SOLARIS_OK);
    defaults(&f); priorities(&f); aliases_and_copy(&f); alias_errors(&f); invalid_and_limits(&f);
    CHECK(solaris_budget_used(f.budget) == 0); allocation_failures(&f); concurrent_readers(&f);
    CHECK(solaris_budget_used(f.budget) == 0); solaris_budget_release(f.budget);
    printf("Hosts snapshot: %u contract groups passed\n", f.groups); return 0;
}
