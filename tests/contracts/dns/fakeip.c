#include "contracts/dns/fakeip.h"
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
    solaris_test_event_t free_entered, free_continue;
    atomic_uint_fast64_t clock;
    atomic_size_t allocations, fail_at;
    atomic_uintptr_t last_allocation, paused_free;
    solaris_fakeip_store_t *persistent;
    unsigned cases;
} fixture_t;
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    size_t n = atomic_fetch_add(&f->allocations, 1u) + 1u;
    void *p = n == atomic_load(&f->fail_at) ? NULL : malloc(size);
    atomic_store(&f->last_allocation, (uintptr_t)p); return p;
}
static void deallocate(void *context, void *p)
{
    fixture_t *f = context;
    if ((uintptr_t)p == atomic_load(&f->paused_free)) {
        solaris_test_event_signal(&f->free_entered); solaris_test_event_wait(&f->free_continue);
    }
    free(p);
}
static uint64_t clock_ns(void *context) { return atomic_load(&((fixture_t *)context)->clock); }
static void time_ms(fixture_t *f, uint64_t now) { atomic_store(&f->clock, now * UINT64_C(1000000)); }
static void fail_nth(fixture_t *f, size_t n) { atomic_store(&f->fail_at, n ? atomic_load(&f->allocations) + n : 0u); }
static solaris_fakeip_options_t options(fixture_t *f)
{
    solaris_fakeip_options_t o; memset(&o, 0, sizeof(o));
    o.owner = f->owner; o.budget = f->budget; o.pool_epoch = 42u;
    o.entry_limit = 8u; o.quarantine_ms = 10u;
    o.ipv4.first.family = SOLARIS_ADDRESS_IPV4;
    o.ipv4.first.ip[0] = 198; o.ipv4.first.ip[1] = 18; o.ipv4.first.ip[3] = 1; o.ipv4.count = 2;
    o.ipv6.first.family = SOLARIS_ADDRESS_IPV6;
    o.ipv6.first.ip[0] = 0xfd; o.ipv6.first.ip[15] = 1; o.ipv6.count = 2;
    return o;
}
static solaris_fakeip_store_t *make(fixture_t *f, solaris_fakeip_options_t *o, int start)
{
    (void)f; solaris_fakeip_store_t *s = NULL;
    CHECK(solaris_fakeip_create(o, &s) == SOLARIS_OK && s);
    if (start) CHECK(solaris_fakeip_start(s, 1, 1) == SOLARIS_OK);
    return s;
}
static void drop(solaris_fakeip_store_t *s)
{ CHECK(solaris_fakeip_stop(s) == SOLARIS_OK); CHECK(solaris_fakeip_destroy(s) == SOLARIS_OK); }
static solaris_fakeip_lease_t *get(solaris_fakeip_store_t *s, const char *name, uint32_t family)
{
    solaris_fakeip_lease_t *lease = NULL;
    CHECK(solaris_fakeip_acquire(s, name, family, &lease) == SOLARIS_OK && lease); return lease;
}
static void mapping(fixture_t *f)
{
    time_ms(f, 1000u); solaris_fakeip_options_t o = options(f);
    solaris_fakeip_store_t *s = make(f, &o, 1);
    solaris_fakeip_lease_t *a = get(s, "WWW.Example.COM.", 4), *b = get(s, "other.example", 4);
    solaris_fakeip_lease_t *a6 = get(s, "www.example.com", 6), *same = get(s, "www.example.com", 4);
    const uint8_t ip4[] = {198, 18, 0, 1};
    CHECK(!strcmp(solaris_fakeip_lease_name(a), "www.example.com"));
    CHECK(!memcmp(solaris_fakeip_lease_address(a)->ip, ip4, sizeof(ip4)));
    CHECK(solaris_fakeip_lease_address(b)->ip[3] == 2);
    CHECK(solaris_fakeip_lease_address(a6)->ip[0] == 0xfd && solaris_fakeip_lease_address(a6)->ip[15] == 1);
    CHECK(solaris_fakeip_lease_address(a)->ip[3] == solaris_fakeip_lease_address(same)->ip[3]);
    CHECK(solaris_fakeip_lease_epoch(a) == 42u);
    solaris_address_t target = *solaris_fakeip_lease_address(a); target.port = 443;
    solaris_fakeip_lease_t *reverse = NULL;
    CHECK(solaris_fakeip_reverse(s, &target, &reverse) == SOLARIS_OK);
    CHECK(!strcmp(solaris_fakeip_lease_name(reverse), "www.example.com"));
    solaris_fakeip_lease_t *missing = (void *)1;
    CHECK(solaris_fakeip_acquire(s, "full.example", 4, &missing) == SOLARIS_EAGAIN && !missing);
    target.ip[3] = 99; CHECK(solaris_fakeip_reverse(s, &target, &missing) == SOLARIS_EACCESS && !missing);
    const char *bad[] = {"", ".", "a..b", "bad name", "a..", "a/b", "xn.\xc3\xa9"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) CHECK(solaris_fakeip_acquire(s, bad[i], 4, &missing) == SOLARIS_EINVAL);
    char long_label[65]; memset(long_label, 'a', 64); long_label[64] = 0;
    CHECK(solaris_fakeip_acquire(s, long_label, 4, &missing) == SOLARIS_EINVAL);
    solaris_fakeip_lease_retain(a); solaris_fakeip_lease_release(a);
    CHECK(solaris_fakeip_destroy(s) == SOLARIS_EBUSY);
    solaris_fakeip_lease_release(a); solaris_fakeip_lease_release(b); solaris_fakeip_lease_release(a6);
    solaris_fakeip_lease_release(same); solaris_fakeip_lease_release(reverse); drop(s); f->cases++;
}
static void expiration(fixture_t *f)
{
    time_ms(f, 1000u); solaris_fakeip_options_t o = options(f); o.ipv4.count = 1;
    solaris_fakeip_store_t *s = make(f, &o, 1); solaris_fakeip_lease_t *a = get(s, "a.example", 4), *out;
    CHECK(solaris_fakeip_mark_visible(s, a, 100u) == SOLARIS_OK);
    solaris_fakeip_lease_release(a); size_t reclaimed;
    CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && reclaimed == 0);
    time_ms(f, 1100u); CHECK(solaris_fakeip_acquire(s, "b.example", 4, &out) == SOLARIS_EAGAIN);
    time_ms(f, 1109u); CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && !reclaimed);
    time_ms(f, 1110u); CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && reclaimed == 1);
    a = get(s, "b.example", 4); CHECK(solaris_fakeip_lease_address(a)->ip[3] == 1);
    CHECK(solaris_fakeip_mark_visible(s, a, 1u) == SOLARIS_OK);
    time_ms(f, 5000u); CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && !reclaimed);
    solaris_fakeip_lease_release(a);
    CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && !reclaimed);
    time_ms(f, 5009u); CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && !reclaimed);
    time_ms(f, 5010u); CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && reclaimed == 1);
    a = get(s, "cache.example", 4); CHECK(solaris_fakeip_mark_visible(s, a, 20) == SOLARIS_OK);
    time_ms(f, 5020u); CHECK(solaris_fakeip_mark_visible(s, a, 100) == SOLARIS_OK); solaris_fakeip_lease_release(a);
    CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && !reclaimed);
    time_ms(f, 5129u); CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && !reclaimed);
    time_ms(f, 5130u); CHECK(solaris_fakeip_collect(s, &reclaimed) == SOLARIS_OK && reclaimed == 1);
    drop(s); f->cases++;
}
static void restart(fixture_t *f)
{
    time_ms(f, 100u); solaris_fakeip_options_t o = options(f); solaris_fakeip_store_t *s = make(f, &o, 0);
    CHECK(solaris_fakeip_start(s, 0, 1) == SOLARIS_EACCESS);
    CHECK(solaris_fakeip_start(s, 1, 0) == SOLARIS_EACCESS);
    CHECK(solaris_fakeip_start(s, 1, 1) == SOLARIS_OK);
    solaris_fakeip_lease_t *a = get(s, "held.example", 4), *b;
    CHECK(solaris_fakeip_mark_visible(s, a, 10000u) == SOLARIS_OK);
    solaris_address_t saved = *solaris_fakeip_lease_address(a);
    CHECK(solaris_fakeip_stop(s) == SOLARIS_OK);
    CHECK(solaris_fakeip_acquire(s, "other.example", 4, &b) == SOLARIS_ECLOSED);
    CHECK(solaris_fakeip_destroy(s) == SOLARIS_EBUSY);
    solaris_buffer_t *snapshot = NULL;
    CHECK(solaris_fakeip_seal(s, 1, &snapshot) == SOLARIS_EBUSY && !snapshot);
    solaris_fakeip_lease_release(a);
    CHECK(solaris_fakeip_start(s, 1, 1) == SOLARIS_EACCESS);
    CHECK(solaris_fakeip_start(s, 0, 1) == SOLARIS_OK);
    CHECK(solaris_fakeip_reverse(s, &saved, &b) == SOLARIS_OK);
    CHECK(!strcmp(solaris_fakeip_lease_name(b), "held.example")); solaris_fakeip_lease_release(b);
    a = get(s, "new.example", 4); CHECK(solaris_fakeip_lease_address(a)->ip[3] == 2);
    solaris_fakeip_lease_release(a); drop(s); f->cases++;
}
static void put32(uint8_t *p, uint32_t n) { for (size_t i = 0; i < 4; i++) p[i] = (uint8_t)(n >> (24u - i * 8u)); }
static void put64(uint8_t *p, uint64_t n) { for (size_t i = 0; i < 8; i++) p[i] = (uint8_t)(n >> (56u - i * 8u)); }
static void recheck(uint8_t *p, size_t n)
{
    memset(p + 120, 0, 8); uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < n; i++) { hash ^= p[i]; hash *= UINT64_C(1099511628211); }
    put64(p + 120, hash);
}
static solaris_buffer_t *checkpoint(fixture_t *f, solaris_fakeip_options_t *o)
{
    time_ms(f, 1000u); solaris_fakeip_store_t *s = make(f, o, 1);
    solaris_fakeip_lease_t *a = get(s, "a.example", 4), *b = get(s, "a.example", 6);
    CHECK(solaris_fakeip_mark_visible(s, a, 1000) == SOLARIS_OK);
    CHECK(solaris_fakeip_mark_visible(s, b, 2000) == SOLARIS_OK);
    solaris_fakeip_lease_release(a); solaris_fakeip_lease_release(b); CHECK(solaris_fakeip_stop(s) == SOLARIS_OK);
    solaris_buffer_t *buffer = NULL; CHECK(solaris_fakeip_seal(s, 7u, &buffer) == SOLARIS_OK);
    CHECK(solaris_fakeip_destroy(s) == SOLARIS_OK); return buffer;
}
static void snapshots(fixture_t *f)
{
    solaris_fakeip_options_t o = options(f); solaris_buffer_t *buffer = checkpoint(f, &o);
    const uint8_t *bytes = solaris_buffer_data(buffer); size_t n = solaris_buffer_length(buffer);
    CHECK(n == 704u && !memcmp(bytes, "SLRFIP01\0\0\0\1\0\0\0\200", 16));
    CHECK(bytes[31] == 42 && bytes[39] == 7 && bytes[55] == 2);
    CHECK(bytes[56] == 198 && bytes[57] == 18 && bytes[59] == 1 && bytes[76] == 0xfd);
    CHECK(bytes[131] == 6 && !strcmp((const char *)bytes + 160, "a.example"));
    CHECK(bytes[419] == 4 && !strcmp((const char *)bytes + 448, "a.example"));
    time_ms(f, 10u); /* New monotonic epoch; no wall-clock-derived expiry. */
    solaris_fakeip_store_t *s = make(f, &o, 0);
    solaris_fakeip_manifest_t manifest = {42u, 7u, 7u, 1};
    solaris_fakeip_manifest_t bad = manifest; bad.clean = 0;
    CHECK(solaris_fakeip_import(s, bytes, n, &bad) == SOLARIS_EACCESS);
    bad = manifest; bad.latest_seal_id = 8u; CHECK(solaris_fakeip_import(s, bytes, n, &bad) == SOLARIS_EACCESS);
    bad = manifest; bad.pool_epoch++; CHECK(solaris_fakeip_import(s, bytes, n, &bad) == SOLARIS_EACCESS);
    uint8_t mutated[705];
    for (unsigned case_id = 0; case_id < 12u; case_id++) {
        memcpy(mutated, bytes, n);
        switch (case_id) {
        case 0: mutated[8] = 1; break; /* unsupported version */
        case 1: memcpy(mutated + 416, mutated + 128, 288); break; /* duplicate slot/name */
        case 2: mutated[160] = 'A'; break; /* noncanonical name */
        case 3: put64(mutated + 136, UINT64_MAX); break;
        case 4: put32(mutated + 132, 2); break; /* out of pool */
        case 5: mutated[104] = 1; break;
        case 6: put32(mutated + 152, 254); break;
        case 7: mutated[170] = 1; break; /* garbage after NUL */
        case 8: put32(mutated + 96, 2); break; /* invalid cursor */
        case 9: put32(mutated + 52, 65536); break;
        case 10: put32(mutated + 128, 4); put32(mutated + 132, 1); break; /* same name, different slot */
        default: put32(mutated + 128, 4); mutated[160] = 'b'; break; /* same slot, different name */
        }
        recheck(mutated, n);
        CHECK(solaris_fakeip_import(s, mutated, n, &manifest) == SOLARIS_EINVAL);
    }
    memcpy(mutated, bytes, n); mutated[160] ^= 1; /* checksum mismatch */
    CHECK(solaris_fakeip_import(s, mutated, n, &manifest) == SOLARIS_EINVAL);
    CHECK(solaris_fakeip_import(s, bytes, n - 1u, &manifest) == SOLARIS_EINVAL);
    CHECK(solaris_fakeip_import(s, mutated, n + 1u, &manifest) == SOLARIS_EINVAL);
    CHECK(solaris_fakeip_import(s, bytes, n, &manifest) == SOLARIS_OK);
    CHECK(solaris_fakeip_import(s, bytes, n, &manifest) == SOLARIS_EBUSY);
    solaris_buffer_t *next = NULL; CHECK(solaris_fakeip_seal(s, 7, &next) == SOLARIS_EACCESS && !next);
    CHECK(solaris_fakeip_start(s, 0, 1) == SOLARIS_OK);
    solaris_fakeip_lease_t *a = get(s, "a.example", 4); CHECK(solaris_fakeip_lease_address(a)->ip[3] == 1);
    solaris_fakeip_lease_release(a); size_t removed;
    CHECK(solaris_fakeip_collect(s, &removed) == SOLARIS_OK && !removed);
    time_ms(f, 1019); CHECK(solaris_fakeip_collect(s, &removed) == SOLARIS_OK && !removed);
    time_ms(f, 1020); CHECK(solaris_fakeip_collect(s, &removed) == SOLARIS_OK && removed == 1);
    time_ms(f, 2020); CHECK(solaris_fakeip_collect(s, &removed) == SOLARIS_OK && removed == 1);
    CHECK(solaris_fakeip_stop(s) == SOLARIS_OK);
    CHECK(solaris_fakeip_import(s, bytes, n, &manifest) == SOLARIS_EBUSY); /* empty but used */
    CHECK(solaris_fakeip_seal(s, 8, &next) == SOLARIS_OK); solaris_buffer_release(next);
    drop(s); solaris_buffer_release(buffer); f->cases++;
}
static void allocation_failures(fixture_t *f)
{
    time_ms(f, 1000u); solaris_fakeip_options_t o = options(f); size_t baseline = solaris_budget_used(f->budget);
    solaris_fakeip_store_t *s = (void *)1; fail_nth(f, 1);
    CHECK(solaris_fakeip_create(&o, &s) == SOLARIS_ENOMEM && !s); fail_nth(f, 0);
    CHECK(solaris_budget_used(f->budget) == baseline);
    s = make(f, &o, 1); size_t empty = solaris_budget_used(f->budget); solaris_fakeip_lease_t *a;
    for (size_t i = 1; i <= 2; i++) {
        fail_nth(f, i); CHECK(solaris_fakeip_acquire(s, "fail.example", 4, &a) == SOLARIS_ENOMEM && !a); fail_nth(f, 0);
        CHECK(solaris_budget_used(f->budget) == empty);
    }
    a = get(s, "fail.example", 4); CHECK(solaris_fakeip_lease_address(a)->ip[3] == 1);
    fail_nth(f, 1); solaris_fakeip_lease_t *other;
    CHECK(solaris_fakeip_acquire(s, "FAIL.example.", 4, &other) == SOLARIS_ENOMEM && !other); fail_nth(f, 0);
    solaris_fakeip_lease_release(a); CHECK(solaris_fakeip_stop(s) == SOLARIS_OK);
    solaris_buffer_t *buffer = NULL; fail_nth(f, 1);
    CHECK(solaris_fakeip_seal(s, 1, &buffer) == SOLARIS_ENOMEM && !buffer); fail_nth(f, 0);
    CHECK(solaris_fakeip_seal(s, 1, &buffer) == SOLARIS_OK); solaris_buffer_release(buffer); drop(s);
    CHECK(solaris_budget_used(f->budget) == baseline);
    buffer = checkpoint(f, &o); s = make(f, &o, 0); empty = solaris_budget_used(f->budget);
    solaris_fakeip_manifest_t manifest = {42, 7, 7, 1};
    for (size_t i = 1; i <= 3; i++) {
        fail_nth(f, i);
        CHECK(solaris_fakeip_import(s, solaris_buffer_data(buffer), solaris_buffer_length(buffer), &manifest) == SOLARIS_ENOMEM);
        fail_nth(f, 0); CHECK(solaris_budget_used(f->budget) == empty);
    }
    CHECK(solaris_fakeip_import(s, solaris_buffer_data(buffer), solaris_buffer_length(buffer), &manifest) == SOLARIS_OK);
    drop(s); solaris_buffer_release(buffer); CHECK(solaris_budget_used(f->budget) == baseline); f->cases++;
}
typedef struct release_case {
    solaris_fakeip_store_t *store;
    solaris_fakeip_lease_t *lease;
    solaris_test_event_t ready, go, done;
} release_case_t;
static void foreign_release(void *context)
{
    release_case_t *c = context;
    CHECK(!strcmp(solaris_fakeip_lease_name(c->lease), "thread.example"));
    CHECK(solaris_fakeip_stop(c->store) == SOLARIS_ETHREAD);
    solaris_fakeip_lease_retain(c->lease); solaris_fakeip_lease_release(c->lease);
    solaris_test_event_signal(&c->ready); solaris_test_event_wait(&c->go);
    solaris_fakeip_lease_release(c->lease); solaris_test_event_signal(&c->done);
}
static void cross_owner(fixture_t *f)
{
    time_ms(f, 1u); solaris_fakeip_options_t o = options(f); o.quarantine_ms = 0;
    release_case_t c; memset(&c, 0, sizeof(c));
    CHECK(!solaris_test_event_init(&c.ready, 0) && !solaris_test_event_init(&c.go, 0) && !solaris_test_event_init(&c.done, 0));
    c.store = make(f, &o, 1); c.lease = get(c.store, "thread.example", 4);
    /* Pause final lease deallocation AFTER its last entry access/pin decrement.
     * The owner frees the entry/store while foreign release is still running. */
    atomic_store(&f->paused_free, atomic_load(&f->last_allocation));
    uv_thread_t thread; CHECK(!uv_thread_create(&thread, foreign_release, &c)); solaris_test_event_wait(&c.ready);
    CHECK(solaris_fakeip_stop(c.store) == SOLARIS_OK && solaris_fakeip_destroy(c.store) == SOLARIS_EBUSY);
    solaris_test_event_signal(&c.go); solaris_test_event_wait(&f->free_entered);
    CHECK(solaris_fakeip_destroy(c.store) == SOLARIS_OK);
    atomic_store(&f->paused_free, 0u); solaris_test_event_signal(&f->free_continue);
    solaris_test_event_wait(&c.done); CHECK(!uv_thread_join(&thread));
    solaris_test_event_destroy(&c.ready); solaris_test_event_destroy(&c.go); solaris_test_event_destroy(&c.done); f->cases++;
}
static void range_bounds(fixture_t *f)
{
    solaris_fakeip_options_t o = options(f); solaris_fakeip_store_t *s;
    memset(o.ipv4.first.ip, 255, 4); o.ipv4.count = 2;
    CHECK(solaris_fakeip_create(&o, &s) == SOLARIS_EINVAL);
    o = options(f); memset(o.ipv6.first.ip, 255, 16); o.ipv6.count = 2;
    CHECK(solaris_fakeip_create(&o, &s) == SOLARIS_EINVAL);
    o = options(f); o.entry_limit = 1; s = make(f, &o, 1);
    solaris_fakeip_lease_t *a = get(s, "one.example", 4), *b;
    CHECK(solaris_fakeip_acquire(s, "one.example", 6, &b) == SOLARIS_EAGAIN && !b);
    solaris_fakeip_lease_release(a); drop(s);
    o = options(f); memset(&o.ipv4, 0, sizeof(o.ipv4)); s = make(f, &o, 1);
    CHECK(solaris_fakeip_acquire(s, "one.example", 4, &b) == SOLARIS_ENOTSUP && !b);
    a = get(s, "one.example", 6); solaris_fakeip_lease_release(a); drop(s);
    o = options(f); o.ipv4.first.ip[3] = 255; o.ipv6.first.ip[15] = 255; s = make(f, &o, 1);
    a = get(s, "one.example", 4); b = get(s, "two.example", 4);
    CHECK(solaris_fakeip_lease_address(a)->ip[3] == 255);
    CHECK(solaris_fakeip_lease_address(b)->ip[2] == 1 && solaris_fakeip_lease_address(b)->ip[3] == 0);
    solaris_fakeip_lease_release(a); solaris_fakeip_lease_release(b);
    a = get(s, "one.example", 6); b = get(s, "two.example", 6);
    CHECK(solaris_fakeip_lease_address(a)->ip[15] == 255);
    CHECK(solaris_fakeip_lease_address(b)->ip[14] == 1 && solaris_fakeip_lease_address(b)->ip[15] == 0);
    solaris_fakeip_lease_release(a); solaris_fakeip_lease_release(b); drop(s); f->cases++;
}
static void run(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == SOLARIS_OK);
    size_t baseline = solaris_budget_used(f->budget);
    mapping(f); expiration(f); restart(f); snapshots(f); allocation_failures(f); cross_owner(f); range_bounds(f);
    CHECK(solaris_budget_used(f->budget) == baseline);
    solaris_fakeip_options_t o = options(f); f->persistent = make(f, &o, 1);
    solaris_fakeip_lease_t *lease = get(f->persistent, "restart.example", 4);
    CHECK(solaris_fakeip_mark_visible(f->persistent, lease, 10000u) == SOLARIS_OK);
    solaris_fakeip_lease_release(lease); CHECK(solaris_fakeip_stop(f->persistent) == SOLARIS_OK);
    solaris_test_event_signal(&f->finished);
}
static void resumed(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == SOLARIS_OK && solaris_executor_generation(f->owner) == 2u);
    CHECK(solaris_fakeip_start(f->persistent, 0, 1) == SOLARIS_OK);
    solaris_fakeip_lease_t *lease = get(f->persistent, "RESTART.EXAMPLE.", 4);
    CHECK(solaris_fakeip_lease_address(lease)->ip[3] == 1u);
    solaris_fakeip_lease_release(lease);
    lease = get(f->persistent, "next.example", 4); CHECK(solaris_fakeip_lease_address(lease)->ip[3] == 2u);
    solaris_fakeip_lease_release(lease); drop(f->persistent); f->persistent = NULL; f->cases++;
    solaris_test_event_signal(&f->finished);
}
int main(void)
{
    fixture_t f; memset(&f, 0, sizeof(f));
    atomic_init(&f.clock, UINT64_C(1000000000)); atomic_init(&f.allocations, 0u); atomic_init(&f.fail_at, 0u);
    atomic_init(&f.last_allocation, 0u); atomic_init(&f.paused_free, 0u);
    CHECK(!solaris_test_event_init(&f.finished, 0) && !solaris_test_event_init(&f.free_entered, 0) &&
          !solaris_test_event_init(&f.free_continue, 0));
    solaris_runtime_services_t services = {.context = &f, .allocate = allocate, .deallocate = deallocate, .now_ns = clock_ns};
    CHECK(solaris_budget_create(16u * 1024u * 1024u, &services, &f.budget) == SOLARIS_OK);
    solaris_executor_options_t eo = {.id = 0, .queue_capacity = 16u, .resource_limit = 32u, .budget = f.budget, .services = &services};
    CHECK(solaris_executor_create(&eo, &f.owner) == SOLARIS_OK);
    CHECK(solaris_executor_activate(f.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(f.owner, run, &f) == SOLARIS_OK); solaris_test_event_wait(&f.finished);
    CHECK(solaris_executor_quiesce(f.owner) == SOLARIS_OK);
    CHECK(solaris_executor_activate(f.owner, 2u) == SOLARIS_OK);
    CHECK(solaris_executor_post(f.owner, resumed, &f) == SOLARIS_OK); solaris_test_event_wait(&f.finished);
    CHECK(solaris_executor_quiesce(f.owner) == SOLARIS_OK);
    CHECK(solaris_executor_destroy(f.owner) == SOLARIS_OK);
    CHECK(solaris_budget_used(f.budget) == 0u); solaris_budget_release(f.budget); solaris_test_event_destroy(&f.finished);
    solaris_test_event_destroy(&f.free_entered); solaris_test_event_destroy(&f.free_continue);
    printf("Fake-IP pool: %u contract groups passed\n", f.cases); return 0;
}
