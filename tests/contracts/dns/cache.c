#include "contracts/dns/cache.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct fixture {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_test_event_t finished;
    atomic_uint_fast64_t clock;
    atomic_size_t calls, fail_at;
    unsigned groups;
} fixture_t;
typedef struct packet { uint8_t bytes[65535]; size_t length; uint16_t counts[3]; } packet_t;
static void *allocate(void *context, size_t n)
{ fixture_t *f = context; return atomic_fetch_add(&f->calls, 1u) + 1u == atomic_load(&f->fail_at) ? NULL : malloc(n); }
static void deallocate(void *context, void *p) { (void)context; free(p); }
static uint64_t now_ns(void *context) { return atomic_load(&((fixture_t *)context)->clock); }
static void time_ms(fixture_t *f, uint64_t now) { atomic_store(&f->clock, now * UINT64_C(1000000)); }
static void fail_nth(fixture_t *f, size_t n) { atomic_store(&f->fail_at, n ? atomic_load(&f->calls) + n : 0u); }
static void u16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }
static void u32(uint8_t *p, uint32_t n) { for (size_t i = 0; i < 4; i++) p[i] = (uint8_t)(n >> (24u - i * 8u)); }
/* Test encoder is independent of the production builders and uses no pointer
 * compression. Expected wire bytes are compared directly in fresh/stale tests. */
static void name(packet_t *p, const char *text)
{
    while (*text) {
        const char *dot = strchr(text, '.'); size_t n = dot ? (size_t)(dot - text) : strlen(text);
        CHECK(n && n <= 63); p->bytes[p->length++] = (uint8_t)n;
        memcpy(p->bytes + p->length, text, n); p->length += n;
        if (!dot) break;
        text = dot + 1;
    }
    p->bytes[p->length++] = 0;
}
static void begin(packet_t *p, const char *qname, uint16_t type, uint16_t id, uint16_t flags)
{
    memset(p, 0, sizeof(*p)); p->length = 12;
    u16(p->bytes, id); u16(p->bytes + 2, flags); u16(p->bytes + 4, 1);
    name(p, qname); u16(p->bytes + p->length, type); u16(p->bytes + p->length + 2, 1); p->length += 4;
}
static size_t rr(packet_t *p, const char *owner, uint16_t type, unsigned section, uint32_t ttl)
{
    name(p, owner); u16(p->bytes + p->length, type); u16(p->bytes + p->length + 2, 1);
    u32(p->bytes + p->length + 4, ttl); p->length += 10; p->counts[section]++;
    return p->length;
}
static void end_rr(packet_t *p, size_t start) { u16(p->bytes + start - 2, (uint16_t)(p->length - start)); }
static void a_record(packet_t *p, const char *owner, uint32_t ttl, uint8_t last)
{
    size_t start = rr(p, owner, 1, 0, ttl); const uint8_t a[] = {127, 0, 0, last};
    memcpy(p->bytes + p->length, a, 4); p->length += 4; end_rr(p, start);
}
static void cname(packet_t *p, const char *owner, const char *target, uint32_t ttl)
{ size_t start = rr(p, owner, 5, 0, ttl); name(p, target); end_rr(p, start); }
static void soa(packet_t *p, const char *zone, uint32_t ttl, uint32_t minimum)
{
    size_t start = rr(p, zone, 6, 1, ttl); name(p, "ns.example.com"); name(p, "host.example.com");
    for (uint32_t i = 1; i <= 4; i++) { u32(p->bytes + p->length, i); p->length += 4; }
    u32(p->bytes + p->length, minimum); p->length += 4; end_rr(p, start);
}
static void opt(packet_t *p, uint16_t udp, uint16_t flags, int option)
{
    p->bytes[p->length++] = 0; u16(p->bytes + p->length, 41); u16(p->bytes + p->length + 2, udp);
    u32(p->bytes + p->length + 4, flags); u16(p->bytes + p->length + 8, option ? 5 : 0); p->length += 10;
    if (option) { u16(p->bytes + p->length, 65001); u16(p->bytes + p->length + 2, 1); p->bytes[p->length + 4] = 7; p->length += 5; }
    p->counts[2]++;
}
static void finish(packet_t *p) { for (size_t i = 0; i < 3; i++) u16(p->bytes + 6 + i * 2, p->counts[i]); }
static solaris_dns_wire_t *parse(fixture_t *f, packet_t *p)
{
    finish(p); solaris_dns_wire_t *wire = NULL;
    CHECK(solaris_dns_wire_parse(f->budget, p->bytes, p->length, NULL, &wire, NULL) == SOLARIS_OK); return wire;
}
static solaris_dns_wire_t *parse_buffer(fixture_t *f, const solaris_buffer_t *buffer)
{
    solaris_dns_wire_t *wire = NULL;
    CHECK(solaris_dns_wire_parse(f->budget, solaris_buffer_data(buffer), solaris_buffer_length(buffer), NULL, &wire, NULL) == SOLARIS_OK); return wire;
}
static solaris_dns_wire_t *query(fixture_t *f, const char *qname, uint16_t id)
{ packet_t p; begin(&p, qname, 1, id, SOLARIS_DNS_RD); return parse(f, &p); }
static solaris_dns_wire_t *answer(fixture_t *f, uint8_t last, uint32_t ttl)
{ packet_t p; begin(&p, "www.example.com", 1, 0x1234, 0x8180); a_record(&p, "www.example.com", ttl, last); return parse(f, &p); }
static solaris_dns_cache_key_t key(const solaris_dns_wire_t *q, uint64_t upstream)
{
    solaris_dns_lookup_view_t view = {.role = SOLARIS_DNS_CLIENT_QUERY, .config_revision = 1,
        .resolver_revision = 2, .network_revision = 3, .selection_revision = 4};
    solaris_dns_cache_key_t k; CHECK(solaris_dns_cache_key_make(&view, 5, upstream, q, &k) == SOLARIS_OK); return k;
}
static solaris_dns_cache_t *make(fixture_t *f, size_t entries, size_t bytes, uint64_t stale)
{
    solaris_dns_cache_options_t o; solaris_dns_cache_options_init(&o); o.owner = f->owner; o.budget = f->budget;
    o.entry_limit = entries; o.byte_limit = bytes; o.stale_window_ms = stale;
    solaris_dns_cache_t *c = NULL; CHECK(solaris_dns_cache_create(&o, &c) == SOLARIS_OK); return c;
}
static solaris_dns_cache_put_result_t put(solaris_dns_cache_t *c, const solaris_dns_cache_key_t *k,
    const solaris_dns_wire_t *q, const solaris_dns_wire_t *r)
{ solaris_dns_cache_put_result_t result; CHECK(solaris_dns_cache_put(c, k, q, r, &result) == SOLARIS_OK); return result; }
static solaris_dns_cache_hit_t get(solaris_dns_cache_t *c, const solaris_dns_cache_key_t *k,
    const solaris_dns_wire_t *q, int stale)
{ solaris_dns_cache_hit_t hit; CHECK(solaris_dns_cache_get(c, k, q, stale, &hit) == SOLARIS_OK); return hit; }
static void fresh_and_stale(fixture_t *f)
{
    time_ms(f, 1000000); solaris_dns_cache_t *c = make(f, 8, 0, 2000);
    solaris_dns_wire_t *q = query(f, "www.example.com", 0x1234); solaris_dns_cache_key_t k = key(q, 6);
    packet_t p; begin(&p, "www.example.com", 1, 0x1234, 0x8180);
    cname(&p, "www.example.com", "alias.example.com", 300); a_record(&p, "alias.example.com", 60, 9);
    solaris_dns_wire_t *r = parse(f, &p); solaris_dns_cache_put_result_t inserted = put(c, &k, q, r);
    CHECK(inserted.stored && inserted.ttl_seconds == 60 && inserted.kind == SOLARIS_DNS_CACHE_POSITIVE);
    solaris_dns_wire_release(r); solaris_dns_wire_release(q);
    q = query(f, "WWW.EXAMPLE.COM", 0xbeef); solaris_dns_cache_key_t same = key(q, 6);
    CHECK(solaris_dns_cache_key_equal(&k, &same));
    time_ms(f, 1005500); solaris_dns_cache_hit_t hit = get(c, &same, q, 0);
    CHECK(hit.found && !hit.stale && !hit.needs_refresh);
    begin(&p, "WWW.EXAMPLE.COM", 1, 0xbeef, 0x8180);
    cname(&p, "www.example.com", "alias.example.com", 295); a_record(&p, "alias.example.com", 55, 9); finish(&p);
    CHECK(solaris_buffer_length(hit.wire) == p.length && !memcmp(solaris_buffer_data(hit.wire), p.bytes, p.length));
    solaris_buffer_release(hit.wire);
    time_ms(f, 1060000); hit = get(c, &same, q, 0); CHECK(!hit.found && !hit.wire);
    hit = get(c, &same, q, 1); CHECK(hit.found && hit.stale && hit.needs_refresh);
    begin(&p, "WWW.EXAMPLE.COM", 1, 0xbeef, 0x8180);
    cname(&p, "www.example.com", "alias.example.com", 1); a_record(&p, "alias.example.com", 1, 9); finish(&p);
    CHECK(solaris_buffer_length(hit.wire) == p.length && !memcmp(solaris_buffer_data(hit.wire), p.bytes, p.length));
    solaris_buffer_t *retained = hit.wire;
    time_ms(f, 1062000); hit = get(c, &same, q, 1); CHECK(!hit.found && !hit.wire);
    CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK);
    CHECK(solaris_buffer_length(retained) == p.length && !memcmp(solaris_buffer_data(retained), p.bytes, p.length));
    solaris_buffer_release(retained); solaris_dns_wire_release(q); f->groups++;
}
static void negative(fixture_t *f)
{
    time_ms(f, 2000000); solaris_dns_cache_t *c = make(f, 8, 0, 2000);
    solaris_dns_wire_t *q = query(f, "www.example.com", 0x1234); solaris_dns_cache_key_t k = key(q, 6);
    for (unsigned mode = 0; mode < 3; mode++) {
        time_ms(f, 2000000); packet_t p; begin(&p, "www.example.com", 1, 0x1234, mode == 0 ? 0x8183 : 0x8180);
        if (mode == 2) cname(&p, "www.example.com", "missing.example.com", 5);
        soa(&p, "example.com", mode == 1 ? 20 : 120, mode == 1 ? 100 : 30);
        solaris_dns_wire_t *r = parse(f, &p); solaris_dns_cache_put_result_t result = put(c, &k, q, r);
        CHECK(result.stored && result.kind == (mode == 0 ? SOLARIS_DNS_CACHE_NXDOMAIN : SOLARIS_DNS_CACHE_NODATA));
        CHECK(result.ttl_seconds == (mode == 0 ? 30u : mode == 1 ? 20u : 5u)); solaris_dns_wire_release(r);
        time_ms(f, 2004000); solaris_dns_cache_hit_t hit = get(c, &k, q, 0); CHECK(hit.found);
        r = parse_buffer(f, hit.wire);
        const solaris_dns_record_t *authority = solaris_dns_wire_record(r, mode == 2 ? 1 : 0);
        CHECK(authority->ttl == (mode == 1 ? 16u : 26u));
        if (mode == 2) CHECK(solaris_dns_wire_record(r, 0)->ttl == 1);
        solaris_dns_wire_release(r); solaris_buffer_release(hit.wire);
        CHECK(solaris_dns_cache_flush(c, 0, 0, 0, NULL) == SOLARIS_OK);
    }
    for (unsigned mode = 0; mode < 6; mode++) {
        packet_t p; begin(&p, "www.example.com", 1, 0x1234, 0x8183);
        if (mode != 0) soa(&p, mode == 1 ? "elsewhere.test" : "example.com", 30, mode == 2 ? 0 : 20);
        if (mode == 3) soa(&p, "example.com", 30, 20);
        /* Keep sections in correct wire order for the contradictory answer. */
        if (mode == 4) { begin(&p, "www.example.com", 1, 0x1234, 0x8183); a_record(&p, "www.example.com", 10, 1); soa(&p, "example.com", 30, 20); }
        if (mode == 5) { begin(&p, "www.example.com", 1, 0x1234, 0x8180); cname(&p, "www.example.com", "missing.other.test", 30); soa(&p, "example.com", 30, 20); }
        solaris_dns_wire_t *r = parse(f, &p); solaris_dns_cache_put_result_t result = put(c, &k, q, r);
        CHECK(!result.stored && result.reason == (mode == 2 ? SOLARIS_DNS_CACHE_SKIP_ZERO_TTL : SOLARIS_DNS_CACHE_SKIP_NO_ANSWER)); solaris_dns_wire_release(r);
    }
    solaris_dns_wire_release(q); CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK); f->groups++;
}
static void skipped_and_edns(fixture_t *f)
{
    time_ms(f, 3000000); solaris_dns_cache_t *c = make(f, 8, 0, 2000);
    solaris_dns_wire_t *q = query(f, "www.example.com", 0x1234); solaris_dns_cache_key_t k = key(q, 6);
    const uint32_t reasons[] = {SOLARIS_DNS_CACHE_SKIP_TRUNCATED, SOLARIS_DNS_CACHE_SKIP_RCODE,
        SOLARIS_DNS_CACHE_SKIP_ZERO_TTL, SOLARIS_DNS_CACHE_SKIP_AUTHENTICATED, SOLARIS_DNS_CACHE_SKIP_RDATA,
        SOLARIS_DNS_CACHE_SKIP_EDNS, SOLARIS_DNS_CACHE_SKIP_CHAIN, SOLARIS_DNS_CACHE_SKIP_CHAIN};
    for (unsigned mode = 0; mode < sizeof(reasons) / sizeof(*reasons); mode++) {
        packet_t p; begin(&p, "www.example.com", 1, 0x1234, (uint16_t)(0x8180 | (mode == 0 ? 0x0200 : mode == 1 ? 2 : mode == 3 ? 0x0020 : 0)));
        if (mode < 6) a_record(&p, "www.example.com", mode == 2 ? 0 : 60, 9);
        if (mode == 4) { size_t start = rr(&p, "www.example.com", 65000, 2, 60); p.bytes[p.length++] = 0xc0; p.bytes[p.length++] = 0xff; end_rr(&p, start); }
        if (mode == 5) opt(&p, 1232, 0, 1);
        if (mode == 6) cname(&p, "www.example.com", "www.example.com", 60);
        if (mode == 7) { cname(&p, "www.example.com", "a.example.com", 60); cname(&p, "www.example.com", "b.example.com", 60); }
        solaris_dns_wire_t *r = parse(f, &p); solaris_dns_cache_put_result_t result = put(c, &k, q, r);
        CHECK(!result.stored && result.reason == reasons[mode]);
        CHECK(solaris_buffer_length(solaris_dns_wire_buffer(r)) == p.length && !memcmp(solaris_buffer_data(solaris_dns_wire_buffer(r)), p.bytes, p.length));
        solaris_dns_wire_release(r);
    }
    solaris_dns_wire_release(q);
    packet_t p; begin(&p, "www.example.com", 1, 0x1234, SOLARIS_DNS_RD); opt(&p, 512, SOLARIS_DNS_DO, 0);
    q = parse(f, &p); k = key(q, 6);
    begin(&p, "www.example.com", 1, 0x1234, 0x8180); a_record(&p, "www.example.com", 60, 9); opt(&p, 4096, SOLARIS_DNS_DO, 0);
    solaris_dns_wire_t *r = parse(f, &p); CHECK(put(c, &k, q, r).stored); solaris_dns_wire_release(r);
    solaris_dns_cache_hit_t hit = get(c, &k, q, 0); CHECK(hit.found); r = parse_buffer(f, hit.wire);
    CHECK(solaris_dns_wire_edns(r)->udp_size == 1232 && solaris_dns_wire_edns(r)->flags == SOLARIS_DNS_DO && !solaris_dns_wire_edns(r)->option_count);
    solaris_dns_wire_release(r); solaris_buffer_release(hit.wire); solaris_dns_wire_release(q);
    begin(&p, "www.example.com", 1, 0x1234, SOLARIS_DNS_RD); opt(&p, 512, SOLARIS_DNS_DO, 1); q = parse(f, &p);
    CHECK(solaris_dns_cache_key_make(&k.view, 5, 6, q, &k) == SOLARIS_ENOTSUP);
    solaris_dns_wire_release(q); CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK); f->groups++;
}
static void key_isolation(fixture_t *f)
{
    time_ms(f, 4000000); solaris_dns_cache_t *c = make(f, 32, 0, 0);
    solaris_dns_wire_t *q = query(f, "www.example.com", 0x1234), *r = answer(f, 9, 60);
    solaris_dns_cache_key_t base = key(q, 6); CHECK(put(c, &base, q, r).stored);
    for (unsigned i = 0; i < 7; i++) {
        solaris_dns_cache_key_t k = base;
        switch (i) { case 0: k.view.role = SOLARIS_DNS_BOOTSTRAP; break; case 1: k.view.config_revision++; break;
        case 2: k.view.resolver_revision++; break; case 3: k.view.network_revision++; break;
        case 4: k.view.selection_revision++; break; case 5: k.policy_id++; break; default: k.upstream_id++; break; }
        CHECK(!solaris_dns_cache_key_equal(&base, &k)); CHECK(!get(c, &k, q, 0).found);
    }
    for (unsigned i = 0; i < 8; i++) {
        packet_t p; begin(&p, "www.example.com", i == 0 ? 28 : 1, 0x1234,
            (uint16_t)(i == 1 ? 0 : SOLARIS_DNS_RD | (i == 2 ? SOLARIS_DNS_CD : i == 3 ? SOLARIS_DNS_AD : 0)));
        if (i >= 4 && i <= 6) opt(&p, i == 6 ? 4096 : 1232, i == 5 ? SOLARIS_DNS_DO : 0, 0);
        if (i == 7) u16(p.bytes + p.length - 2, 3);
        solaris_dns_wire_t *other = parse(f, &p); solaris_dns_cache_key_t k = key(other, 6);
        CHECK(!solaris_dns_cache_key_equal(&base, &k)); CHECK(!get(c, &k, other, 0).found); solaris_dns_wire_release(other);
    }
    packet_t edns_packet; begin(&edns_packet, "www.example.com", 1, 0x1234, SOLARIS_DNS_RD); opt(&edns_packet, 1232, 0, 0);
    solaris_dns_wire_t *edns_query = parse(f, &edns_packet); solaris_dns_cache_key_t edns_key = key(edns_query, 6);
    CHECK(put(c, &edns_key, edns_query, r).stored);
    for (unsigned i = 0; i < 2; i++) {
        begin(&edns_packet, "www.example.com", 1, 0x1234, SOLARIS_DNS_RD); opt(&edns_packet, i ? 4096 : 1232, i ? 0 : SOLARIS_DNS_DO, 0);
        solaris_dns_wire_t *other = parse(f, &edns_packet); solaris_dns_cache_key_t k = key(other, 6);
        CHECK(!solaris_dns_cache_key_equal(&edns_key, &k) && !get(c, &k, other, 0).found); solaris_dns_wire_release(other);
    }
    solaris_dns_wire_release(edns_query);
    solaris_dns_cache_hit_t hit = get(c, &base, q, 0); CHECK(hit.found); solaris_buffer_release(hit.wire);
    solaris_dns_wire_release(q); solaris_dns_wire_release(r); CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK); f->groups++;
}
static void lru_and_flush(fixture_t *f)
{
    time_ms(f, 5000000); solaris_dns_wire_t *q = query(f, "www.example.com", 0x1234), *r = answer(f, 9, 60);
    solaris_dns_cache_t *c = make(f, 2, 0, 0); solaris_dns_cache_key_t keys[] = {key(q, 1), key(q, 2), key(q, 3)};
    CHECK(put(c, &keys[0], q, r).stored); solaris_dns_cache_stats_t stats;
    CHECK(solaris_dns_cache_snapshot(c, &stats) == SOLARIS_OK); size_t charge = stats.charged_bytes;
    CHECK(put(c, &keys[1], q, r).stored);
    solaris_dns_cache_hit_t hit = get(c, &keys[0], q, 0); CHECK(hit.found); solaris_buffer_t *held = hit.wire;
    CHECK(put(c, &keys[2], q, r).stored); CHECK(!get(c, &keys[1], q, 0).found);
    CHECK(solaris_dns_cache_snapshot(c, &stats) == SOLARIS_OK && stats.entries == 2 && stats.evictions == 1);
    CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK);
    solaris_dns_wire_t *decoded = parse_buffer(f, held); CHECK(solaris_dns_wire_record(decoded, 0)->value.address[3] == 9);
    solaris_dns_wire_release(decoded); solaris_buffer_release(held);
    c = make(f, 8, charge * 2u - 1u, 0); CHECK(put(c, &keys[0], q, r).stored && put(c, &keys[1], q, r).stored);
    CHECK(solaris_dns_cache_snapshot(c, &stats) == SOLARIS_OK && stats.entries == 1 && stats.charged_bytes == charge);
    CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK);
    c = make(f, 8, charge - 1u, 0); solaris_dns_cache_put_result_t skip = put(c, &keys[0], q, r);
    CHECK(!skip.stored && skip.reason == SOLARIS_DNS_CACHE_SKIP_LIMIT); CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK);
    c = make(f, 8, 0, 0); keys[1].view.network_revision++; keys[2].view.resolver_revision++;
    for (size_t i = 0; i < 3; i++) CHECK(put(c, &keys[i], q, r).stored);
    hit = get(c, &keys[2], q, 0); held = hit.wire;
    size_t removed; CHECK(solaris_dns_cache_flush(c, SOLARIS_DNS_CACHE_FLUSH_NETWORK, keys[0].view.network_revision, 0, &removed) == SOLARIS_OK && removed == 2);
    hit = get(c, &keys[1], q, 0); CHECK(hit.found); solaris_buffer_release(hit.wire);
    CHECK(solaris_dns_cache_flush(c, SOLARIS_DNS_CACHE_FLUSH_RESOLVER, 0, keys[1].view.resolver_revision, &removed) == SOLARIS_OK && removed == 1);
    CHECK(solaris_dns_cache_snapshot(c, &stats) == SOLARIS_OK && !stats.entries && !stats.charged_bytes);
    CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK); decoded = parse_buffer(f, held);
    CHECK(solaris_dns_wire_record(decoded, 0)->ttl == 60); solaris_dns_wire_release(decoded); solaris_buffer_release(held);
    solaris_dns_wire_release(q); solaris_dns_wire_release(r); f->groups++;
}
static void allocation_failures(fixture_t *f)
{
    time_ms(f, 6000000); solaris_dns_wire_t *q = query(f, "www.example.com", 0x1234), *r = answer(f, 9, 60), *replacement = answer(f, 10, 60);
    solaris_dns_cache_options_t o; solaris_dns_cache_options_init(&o); o.owner = f->owner; o.budget = f->budget;
    solaris_dns_cache_t *c = (void *)1; size_t baseline = solaris_budget_used(f->budget);
    fail_nth(f, 1); CHECK(solaris_dns_cache_create(&o, &c) == SOLARIS_ENOMEM && !c); fail_nth(f, 0); CHECK(solaris_budget_used(f->budget) == baseline);
    c = make(f, 8, 0, 0); solaris_dns_cache_key_t k = key(q, 6); CHECK(put(c, &k, q, r).stored);
    baseline = solaris_budget_used(f->budget); solaris_dns_cache_put_result_t result;
    fail_nth(f, 1); CHECK(solaris_dns_cache_put(c, &k, q, replacement, &result) == SOLARIS_ENOMEM && !result.stored); fail_nth(f, 0);
    CHECK(solaris_budget_used(f->budget) == baseline);
    for (size_t i = 1; i <= 2; i++) {
        solaris_dns_cache_hit_t hit; fail_nth(f, i);
        CHECK(solaris_dns_cache_get(c, &k, q, 0, &hit) == SOLARIS_ENOMEM && !hit.found && !hit.wire); fail_nth(f, 0);
        CHECK(solaris_budget_used(f->budget) == baseline);
    }
    solaris_dns_cache_hit_t hit = get(c, &k, q, 0); solaris_dns_wire_t *decoded = parse_buffer(f, hit.wire);
    CHECK(solaris_dns_wire_record(decoded, 0)->value.address[3] == 9); solaris_dns_wire_release(decoded); solaris_buffer_release(hit.wire);
    CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK); solaris_dns_wire_release(q); solaris_dns_wire_release(r); solaris_dns_wire_release(replacement); f->groups++;
}
static void limits_and_refresh(fixture_t *f)
{
    time_ms(f, 7000000); solaris_dns_wire_t *q = query(f, "www.example.com", 0x1234);
    solaris_dns_cache_key_t k = key(q, 6); packet_t p;
    begin(&p, "www.example.com", 1, 0x1234, 0x8180);
    cname(&p, "www.example.com", "one.example.com", 60);
    cname(&p, "one.example.com", "two.example.com", 60); a_record(&p, "two.example.com", 60, 9);
    solaris_dns_wire_t *chain = parse(f, &p);
    solaris_dns_cache_options_t o; solaris_dns_cache_options_init(&o); o.owner = f->owner; o.budget = f->budget; o.cname_depth = 1;
    solaris_dns_cache_t *c; CHECK(solaris_dns_cache_create(&o, &c) == SOLARIS_OK);
    CHECK(put(c, &k, q, chain).reason == SOLARIS_DNS_CACHE_SKIP_CHAIN); CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK);
    o.cname_depth = 2; o.record_limit = 2; CHECK(solaris_dns_cache_create(&o, &c) == SOLARIS_OK);
    CHECK(put(c, &k, q, chain).reason == SOLARIS_DNS_CACHE_SKIP_LIMIT); CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK);
    o.record_limit = 3; CHECK(solaris_dns_cache_create(&o, &c) == SOLARIS_OK); CHECK(put(c, &k, q, chain).stored);
    solaris_dns_wire_release(chain);
    solaris_dns_wire_t *zero = answer(f, 10, 0);
    CHECK(put(c, &k, q, zero).reason == SOLARIS_DNS_CACHE_SKIP_ZERO_TTL); CHECK(!get(c, &k, q, 1).found);
    solaris_dns_wire_release(zero);
    solaris_dns_wire_t *good = answer(f, 9, 60); CHECK(put(c, &k, q, good).stored);
    begin(&p, "www.example.com", 1, 0x1234, 0x8182); solaris_dns_wire_t *failure = parse(f, &p);
    CHECK(put(c, &k, q, failure).reason == SOLARIS_DNS_CACHE_SKIP_RCODE); solaris_dns_wire_release(failure);
    solaris_dns_cache_hit_t hit = get(c, &k, q, 0); CHECK(hit.found); solaris_buffer_release(hit.wire);
    begin(&p, "www.example.com", 1, 0x1234, 0x8380); failure = parse(f, &p);
    CHECK(put(c, &k, q, failure).reason == SOLARIS_DNS_CACHE_SKIP_TRUNCATED); solaris_dns_wire_release(failure);
    hit = get(c, &k, q, 0); CHECK(hit.found); solaris_buffer_release(hit.wire);
    solaris_dns_cache_key_t bad_key = k; bad_key.question.type = 28;
    solaris_dns_cache_put_result_t result; CHECK(solaris_dns_cache_put(c, &bad_key, q, good, &result) == SOLARIS_EINVAL);
    solaris_dns_wire_t *wrong_query = query(f, "www.example.com", 0x9999);
    CHECK(solaris_dns_cache_put(c, &k, wrong_query, good, &result) == SOLARIS_EINVAL);
    solaris_dns_wire_release(wrong_query); solaris_dns_wire_release(good); solaris_dns_wire_release(q);
    CHECK(solaris_dns_cache_destroy(c) == SOLARIS_OK); f->groups++;
}
static void run(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == SOLARIS_OK); size_t baseline = solaris_budget_used(f->budget);
    fresh_and_stale(f); negative(f); skipped_and_edns(f); key_isolation(f); lru_and_flush(f); allocation_failures(f); limits_and_refresh(f);
    CHECK(solaris_budget_used(f->budget) == baseline); solaris_test_event_signal(&f->finished);
}
int main(void)
{
    fixture_t f; memset(&f, 0, sizeof(f)); atomic_init(&f.clock, 0u); atomic_init(&f.calls, 0u); atomic_init(&f.fail_at, 0u);
    CHECK(!solaris_test_event_init(&f.finished, 0));
    solaris_runtime_services_t services = {.context = &f, .allocate = allocate, .deallocate = deallocate, .now_ns = now_ns};
    CHECK(solaris_budget_create(32u * 1024u * 1024u, &services, &f.budget) == SOLARIS_OK);
    solaris_executor_options_t eo = {.id = 0, .queue_capacity = 16u, .resource_limit = 32u, .budget = f.budget, .services = &services};
    CHECK(solaris_executor_create(&eo, &f.owner) == SOLARIS_OK && solaris_executor_activate(f.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(f.owner, run, &f) == SOLARIS_OK); solaris_test_event_wait(&f.finished);
    CHECK(solaris_executor_quiesce(f.owner) == SOLARIS_OK && solaris_executor_destroy(f.owner) == SOLARIS_OK);
    CHECK(!solaris_budget_used(f.budget)); solaris_budget_release(f.budget); solaris_test_event_destroy(&f.finished);
    printf("DNS cache: %u contract groups passed\n", f.groups); return 0;
}
