#include "contracts/dns/fakeip.h"
#include <assert.h>
#include <stdatomic.h>
#include <string.h>

#define ENTRY_LIMIT 65536u
#define DURATION_LIMIT (UINT64_C(4294967295) * UINT64_C(1000))
#define HEADER_SIZE 128u
#define RECORD_SIZE 288u

typedef struct fakeip_entry fakeip_entry_t;
struct fakeip_entry {
    fakeip_entry_t *next, *name_next, *address_next;
    solaris_fakeip_store_t *store;
    atomic_size_t pins;
    solaris_address_t address;
    char name[254];
    uint32_t slot;
    uint64_t visible_until, reuse_after;
    int observe_release;
};
struct solaris_fakeip_store {
    solaris_fakeip_options_t options;
    fakeip_entry_t *entries;
    size_t buckets;
    uint32_t count, cursor4, cursor6;
    uint64_t last_seal;
    int initialized, running;
    fakeip_entry_t *table[]; /* names, then numeric addresses */
};
struct solaris_fakeip_lease {
    atomic_size_t references;
    fakeip_entry_t *entry;
};

static solaris_status_t owner(const solaris_fakeip_store_t *s)
{
    if (!s) return SOLARIS_EINVAL;
    return solaris_executor_is_owner(s->options.owner) ? SOLARIS_OK : SOLARIS_ETHREAD;
}
static uint64_t now_ms(const solaris_fakeip_store_t *s)
{ return solaris_executor_now_ns(s->options.owner) / UINT64_C(1000000); }
static uint64_t later(uint64_t a, uint64_t b) { return a > b ? a : b; }
static uint64_t saturating_add(uint64_t a, uint64_t b)
{ return a > UINT64_MAX - b ? UINT64_MAX : a + b; }
static uint64_t remaining(uint64_t due, uint64_t now) { return due > now ? due - now : 0; }

static solaris_status_t normalize(const char *name, char out[254])
{
    if (!name) return SOLARIS_EINVAL;
    size_t n = 0;
    while (n < 255u && name[n]) n++;
    if (!n || n == 255u) return SOLARIS_EINVAL;
    if (name[n - 1u] == '.') n--;
    if (!n || n > 253u) return SOLARIS_EINVAL;
    size_t label = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c == '.') { if (!label || label > 63u) return SOLARIS_EINVAL; label = 0; }
        else {
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-' || c == '_')) return SOLARIS_EINVAL;
            if (++label > 63u) return SOLARIS_EINVAL;
        }
        out[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    if (!label) return SOLARIS_EINVAL;
    out[n] = 0;
    return SOLARIS_OK;
}
static uint64_t hash_bytes(uint64_t h, const void *bytes, size_t n)
{
    const uint8_t *p = bytes;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= UINT64_C(1099511628211); }
    return h;
}
static size_t name_bucket(const solaris_fakeip_store_t *s, const char *name, uint32_t family)
{ return (size_t)hash_bytes(family, name, strlen(name)) & (s->buckets - 1u); }
static size_t address_bucket(const solaris_fakeip_store_t *s, const solaris_address_t *a)
{ return (size_t)hash_bytes(a->family, a->ip, a->family == SOLARIS_ADDRESS_IPV4 ? 4u : 16u) & (s->buckets - 1u); }
static fakeip_entry_t *find_name(const solaris_fakeip_store_t *s, const char *name, uint32_t family)
{
    for (fakeip_entry_t *e = s->table[name_bucket(s, name, family)]; e; e = e->name_next)
        if (e->address.family == family && !strcmp(e->name, name)) return e;
    return NULL;
}
static fakeip_entry_t *find_address(const solaris_fakeip_store_t *s, const solaris_address_t *a)
{
    for (fakeip_entry_t *e = s->table[s->buckets + address_bucket(s, a)]; e; e = e->address_next)
        if (e->address.family == a->family && !memcmp(e->address.ip, a->ip, a->family == 4u ? 4u : 16u)) return e;
    return NULL;
}
static int address_at(const solaris_fakeip_range_t *range, uint32_t slot, solaris_address_t *out)
{
    *out = range->first;
    uint64_t carry = slot;
    for (size_t i = out->family == SOLARIS_ADDRESS_IPV4 ? 4u : 16u; i > 0u; i--) {
        carry += out->ip[i - 1u]; out->ip[i - 1u] = (uint8_t)carry; carry >>= 8u;
    }
    return carry == 0;
}
static int valid_range(const solaris_fakeip_range_t *r, uint32_t family)
{
    if (!r->count) return r->first.family == 0u;
    if (r->first.family != family || r->first.port || r->first.scope_id || r->first.host[0]) return 0;
    if (family == SOLARIS_ADDRESS_IPV4)
        for (size_t i = 4u; i < 16u; i++) if (r->first.ip[i]) return 0;
    solaris_address_t last;
    return address_at(r, r->count - 1u, &last);
}
static void link_entry(solaris_fakeip_store_t *s, fakeip_entry_t *e)
{
    size_t n = name_bucket(s, e->name, e->address.family), a = s->buckets + address_bucket(s, &e->address);
    e->name_next = s->table[n]; s->table[n] = e;
    e->address_next = s->table[a]; s->table[a] = e;
    e->next = s->entries; s->entries = e; s->count++;
}
static void unlink_index(solaris_fakeip_store_t *s, fakeip_entry_t *e)
{
    fakeip_entry_t **p = &s->table[name_bucket(s, e->name, e->address.family)];
    while (*p != e) p = &(*p)->name_next;
    *p = e->name_next;
    p = &s->table[s->buckets + address_bucket(s, &e->address)];
    while (*p != e) p = &(*p)->address_next;
    *p = e->address_next;
    s->count--;
}
static void observe(fakeip_entry_t *e, uint64_t now)
{
    if (e->observe_release && atomic_load_explicit(&e->pins, memory_order_acquire) == 0u) {
        e->reuse_after = saturating_add(later(now, e->visible_until), e->store->options.quarantine_ms);
        e->observe_release = 0;
    }
}
static void observe_all(solaris_fakeip_store_t *s, uint64_t now)
{ for (fakeip_entry_t *e = s->entries; e; e = e->next) observe(e, now); }
static int has_pins(solaris_fakeip_store_t *s)
{
    for (fakeip_entry_t *e = s->entries; e; e = e->next)
        if (atomic_load_explicit(&e->pins, memory_order_acquire)) return 1;
    return 0;
}

solaris_status_t solaris_fakeip_create(const solaris_fakeip_options_t *o, solaris_fakeip_store_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!o || !o->owner || !o->budget || !o->entry_limit || o->entry_limit > ENTRY_LIMIT ||
        !o->pool_epoch || o->quarantine_ms > DURATION_LIMIT || (!o->ipv4.count && !o->ipv6.count) ||
        !valid_range(&o->ipv4, SOLARIS_ADDRESS_IPV4) || !valid_range(&o->ipv6, SOLARIS_ADDRESS_IPV6)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(o->owner)) return SOLARIS_ETHREAD;
    size_t buckets = 2u;
    while (buckets < (size_t)o->entry_limit * 2u) buckets *= 2u;
    size_t size = sizeof(solaris_fakeip_store_t) + buckets * 2u * sizeof(fakeip_entry_t *);
    solaris_fakeip_store_t *s = solaris_memory_allocate(o->budget, size);
    if (!s) return SOLARIS_ENOMEM;
    memset(s, 0, size); s->options = *o; s->buckets = buckets; *out = s;
    return SOLARIS_OK;
}
solaris_status_t solaris_fakeip_start(solaris_fakeip_store_t *s, int fresh, int dirty)
{
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    if (s->running) return SOLARIS_EBUSY;
    if (dirty != 1 || (fresh != 0 && fresh != 1) || (!s->initialized && !fresh) || (s->initialized && fresh)) return SOLARIS_EACCESS;
    s->initialized = s->running = 1;
    return SOLARIS_OK;
}
solaris_status_t solaris_fakeip_stop(solaris_fakeip_store_t *s)
{
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    s->running = 0; observe_all(s, now_ms(s)); return SOLARIS_OK;
}
solaris_status_t solaris_fakeip_destroy(solaris_fakeip_store_t *s)
{
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    if (s->running || has_pins(s)) return SOLARIS_EBUSY;
    fakeip_entry_t *e = s->entries;
    while (e) { fakeip_entry_t *next = e->next; solaris_memory_free(e); e = next; }
    solaris_memory_free(s); return SOLARIS_OK;
}
solaris_status_t solaris_fakeip_collect(solaris_fakeip_store_t *s, size_t *reclaimed)
{
    if (reclaimed) *reclaimed = 0;
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    uint64_t now = now_ms(s); size_t count = 0;
    fakeip_entry_t **p = &s->entries;
    while (*p) {
        fakeip_entry_t *e = *p; observe(e, now);
        if (!atomic_load_explicit(&e->pins, memory_order_acquire) && !e->observe_release &&
            now >= e->visible_until && now >= e->reuse_after) {
            *p = e->next; unlink_index(s, e); solaris_memory_free(e); count++;
        } else p = &e->next;
    }
    if (reclaimed) *reclaimed = count;
    return SOLARIS_OK;
}
static solaris_status_t make_lease(solaris_fakeip_store_t *s, fakeip_entry_t *e, solaris_fakeip_lease_t **out)
{
    solaris_fakeip_lease_t *lease = solaris_memory_allocate(s->options.budget, sizeof(*lease));
    if (!lease) return SOLARIS_ENOMEM;
    if (atomic_load_explicit(&e->pins, memory_order_relaxed) == SIZE_MAX) { solaris_memory_free(lease); return SOLARIS_EOVERFLOW; }
    atomic_init(&lease->references, 1u); lease->entry = e;
    (void)atomic_fetch_add_explicit(&e->pins, 1u, memory_order_relaxed);
    e->observe_release = 1; *out = lease; return SOLARIS_OK;
}
static solaris_status_t vacant(solaris_fakeip_store_t *s, uint32_t family, uint32_t *slot, solaris_address_t *a)
{
    const solaris_fakeip_range_t *range = family == SOLARIS_ADDRESS_IPV4 ? &s->options.ipv4 : &s->options.ipv6;
    if (!range->count) return SOLARIS_ENOTSUP;
    uint32_t next = family == SOLARIS_ADDRESS_IPV4 ? s->cursor4 : s->cursor6;
    uint64_t attempts = (uint64_t)s->count + 1u;
    if (attempts > range->count) attempts = range->count;
    for (uint64_t i = 0; i < attempts; i++) {
        (void)address_at(range, next, a);
        if (!find_address(s, a)) { *slot = next; return SOLARIS_OK; }
        next = next == range->count - 1u ? 0u : next + 1u;
    }
    return SOLARIS_EAGAIN;
}
solaris_status_t solaris_fakeip_acquire(solaris_fakeip_store_t *s, const char *name, uint32_t family, solaris_fakeip_lease_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    if (!s->running) return SOLARIS_ECLOSED;
    if (family != SOLARIS_ADDRESS_IPV4 && family != SOLARIS_ADDRESS_IPV6) return SOLARIS_EINVAL;
    char canonical[254]; rc = normalize(name, canonical); if (rc != SOLARIS_OK) return rc;
    observe_all(s, now_ms(s));
    fakeip_entry_t *e = find_name(s, canonical, family);
    if (e) return make_lease(s, e, out);
    solaris_address_t address; uint32_t slot;
    rc = vacant(s, family, &slot, &address);
    if (s->count == s->options.entry_limit || rc == SOLARIS_EAGAIN) {
        (void)solaris_fakeip_collect(s, NULL); rc = vacant(s, family, &slot, &address);
    }
    if (rc != SOLARIS_OK) return rc;
    if (s->count == s->options.entry_limit) return SOLARIS_EAGAIN;
    e = solaris_memory_allocate(s->options.budget, sizeof(*e));
    if (!e) return SOLARIS_ENOMEM;
    memset(e, 0, sizeof(*e)); e->store = s; e->address = address; e->slot = slot;
    memcpy(e->name, canonical, strlen(canonical) + 1u); atomic_init(&e->pins, 0u);
    rc = make_lease(s, e, out);
    if (rc != SOLARIS_OK) { solaris_memory_free(e); return rc; }
    link_entry(s, e);
    const solaris_fakeip_range_t *range = family == 4u ? &s->options.ipv4 : &s->options.ipv6;
    uint32_t next = slot == range->count - 1u ? 0u : slot + 1u;
    if (family == 4u) s->cursor4 = next; else s->cursor6 = next;
    return SOLARIS_OK;
}
solaris_status_t solaris_fakeip_reverse(solaris_fakeip_store_t *s, const solaris_address_t *a, solaris_fakeip_lease_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    if (!s->running) return SOLARIS_ECLOSED;
    if (!a || (a->family != 4u && a->family != 6u) || a->scope_id) return SOLARIS_EINVAL;
    observe_all(s, now_ms(s));
    fakeip_entry_t *e = find_address(s, a);
    return e ? make_lease(s, e, out) : SOLARIS_EACCESS;
}
solaris_status_t solaris_fakeip_mark_visible(solaris_fakeip_store_t *s, const solaris_fakeip_lease_t *lease, uint64_t ttl)
{
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    if (!s->running) return SOLARIS_ECLOSED;
    if (!lease || lease->entry->store != s || ttl > DURATION_LIMIT) return SOLARIS_EINVAL;
    uint64_t now = now_ms(s);
    if (now > UINT64_MAX - ttl || now + ttl > UINT64_MAX - s->options.quarantine_ms) return SOLARIS_EOVERFLOW;
    fakeip_entry_t *e = lease->entry; e->visible_until = later(e->visible_until, now + ttl);
    return SOLARIS_OK;
}
void solaris_fakeip_lease_retain(const solaris_fakeip_lease_t *lease)
{
    if (lease) (void)atomic_fetch_add_explicit(&((solaris_fakeip_lease_t *)lease)->references, 1u, memory_order_relaxed);
}
void solaris_fakeip_lease_release(const solaris_fakeip_lease_t *lease)
{
    if (lease && atomic_fetch_sub_explicit(&((solaris_fakeip_lease_t *)lease)->references, 1u, memory_order_acq_rel) == 1u) {
        /* This is the LAST access to entry. Owner may free it immediately. */
        (void)atomic_fetch_sub_explicit(&lease->entry->pins, 1u, memory_order_release);
        solaris_memory_free((void *)lease);
    }
}
const char *solaris_fakeip_lease_name(const solaris_fakeip_lease_t *lease) { return lease ? lease->entry->name : NULL; }
const solaris_address_t *solaris_fakeip_lease_address(const solaris_fakeip_lease_t *lease) { return lease ? &lease->entry->address : NULL; }
uint64_t solaris_fakeip_lease_epoch(const solaris_fakeip_lease_t *lease) { return lease ? lease->entry->store->options.pool_epoch : 0u; }

static void put32(uint8_t *p, uint32_t v) { for (size_t i = 0; i < 4u; i++) p[i] = (uint8_t)(v >> ((3u - i) * 8u)); }
static void put64(uint8_t *p, uint64_t v) { for (size_t i = 0; i < 8u; i++) p[i] = (uint8_t)(v >> ((7u - i) * 8u)); }
static uint32_t get32(const uint8_t *p) { uint32_t v = 0; for (size_t i = 0; i < 4u; i++) v = (v << 8u) | p[i]; return v; }
static uint64_t get64(const uint8_t *p) { uint64_t v = 0; for (size_t i = 0; i < 8u; i++) v = (v << 8u) | p[i]; return v; }
static int zeroes(const uint8_t *p, size_t n) { for (size_t i = 0; i < n; i++) if (p[i]) return 0; return 1; }
static uint64_t checksum(const uint8_t *p, size_t length)
{
    uint64_t h = hash_bytes(UINT64_C(14695981039346656037), p, 120u);
    const uint8_t zero[8] = {0}; h = hash_bytes(h, zero, sizeof(zero));
    return hash_bytes(h, p + HEADER_SIZE, length - HEADER_SIZE);
}
solaris_status_t solaris_fakeip_seal(solaris_fakeip_store_t *s, uint64_t seal, solaris_buffer_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    if (s->running || has_pins(s)) return SOLARIS_EBUSY;
    if (!s->initialized || !seal || seal <= s->last_seal) return SOLARIS_EACCESS;
    uint64_t now = now_ms(s); observe_all(s, now);
    size_t length = HEADER_SIZE + (size_t)s->count * RECORD_SIZE;
    solaris_buffer_t *buffer; rc = solaris_buffer_allocate(s->options.budget, length, &buffer);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *p = solaris_buffer_mutable_data(buffer); memset(p, 0, length);
    memcpy(p, "SLRFIP01", 8u); put32(p + 8, 1u); put32(p + 12, HEADER_SIZE); put64(p + 16, length);
    put64(p + 24, s->options.pool_epoch); put64(p + 32, seal); put64(p + 40, s->options.quarantine_ms);
    put32(p + 48, s->options.entry_limit); put32(p + 52, s->count);
    memcpy(p + 56, s->options.ipv4.first.ip, 16u); put32(p + 72, s->options.ipv4.count);
    memcpy(p + 76, s->options.ipv6.first.ip, 16u); put32(p + 92, s->options.ipv6.count);
    put32(p + 96, s->cursor4); put32(p + 100, s->cursor6);
    size_t offset = HEADER_SIZE;
    for (fakeip_entry_t *e = s->entries; e; e = e->next, offset += RECORD_SIZE) {
        uint8_t *r = p + offset;
        put32(r, e->address.family); put32(r + 4, e->slot);
        put64(r + 8, remaining(e->visible_until, now)); put64(r + 16, remaining(e->reuse_after, now));
        size_t n = strlen(e->name); put32(r + 24, (uint32_t)n); memcpy(r + 32, e->name, n);
    }
    put64(p + 120, checksum(p, length)); (void)solaris_buffer_set_length(buffer, length); solaris_buffer_publish(buffer);
    s->last_seal = seal; *out = buffer; return SOLARIS_OK;
}
solaris_status_t solaris_fakeip_import(solaris_fakeip_store_t *s, const void *bytes, size_t length, const solaris_fakeip_manifest_t *manifest)
{
    solaris_status_t rc = owner(s); if (rc != SOLARIS_OK) return rc;
    if (s->initialized || s->running || s->count) return SOLARIS_EBUSY;
    if (!bytes || length < HEADER_SIZE || length > HEADER_SIZE + (size_t)s->options.entry_limit * RECORD_SIZE || !manifest) return SOLARIS_EINVAL;
    const uint8_t *p = bytes;
    if (memcmp(p, "SLRFIP01", 8u) || get32(p + 8) != 1u || get32(p + 12) != HEADER_SIZE ||
        get64(p + 16) != length || get32(p + 48) != s->options.entry_limit || get32(p + 52) > s->options.entry_limit ||
        length != HEADER_SIZE + (size_t)get32(p + 52) * RECORD_SIZE || !zeroes(p + 104, 16u) ||
        get64(p + 120) != checksum(p, length)) return SOLARIS_EINVAL;
    if (manifest->clean != 1 || !manifest->seal_id || manifest->pool_epoch != s->options.pool_epoch ||
        manifest->seal_id != manifest->latest_seal_id || get64(p + 24) != manifest->pool_epoch ||
        get64(p + 32) != manifest->seal_id || get64(p + 40) != s->options.quarantine_ms ||
        memcmp(p + 56, s->options.ipv4.first.ip, 16u) || get32(p + 72) != s->options.ipv4.count ||
        memcmp(p + 76, s->options.ipv6.first.ip, 16u) || get32(p + 92) != s->options.ipv6.count) return SOLARIS_EACCESS;
    uint32_t c4 = get32(p + 96), c6 = get32(p + 100);
    if ((s->options.ipv4.count ? c4 >= s->options.ipv4.count : c4 != 0u) ||
        (s->options.ipv6.count ? c6 >= s->options.ipv6.count : c6 != 0u)) return SOLARIS_EINVAL;
    /* Stage a separate indexed store; any allocation/validation failure leaves
     * the destination genuinely unused and eligible for a corrected import. */
    solaris_fakeip_store_t *candidate; rc = solaris_fakeip_create(&s->options, &candidate);
    if (rc != SOLARIS_OK) return rc;
    uint64_t now = now_ms(s);
    for (size_t offset = HEADER_SIZE; offset < length; offset += RECORD_SIZE) {
        const uint8_t *r = p + offset; uint32_t family = get32(r), slot = get32(r + 4), n = get32(r + 24);
        uint64_t ttl = get64(r + 8), hold = get64(r + 16);
        char normalized[254];
        if ((family != 4u && family != 6u) || !n || n > 253u || !zeroes(r + 28, 4u) ||
            !zeroes(r + 32 + n, 256u - n) || normalize((const char *)r + 32, normalized) != SOLARIS_OK ||
            strlen(normalized) != n || memcmp(normalized, r + 32, n) || ttl > DURATION_LIMIT ||
            hold > DURATION_LIMIT + s->options.quarantine_ms || hold < ttl) { rc = SOLARIS_EINVAL; break; }
        const solaris_fakeip_range_t *range = family == 4u ? &s->options.ipv4 : &s->options.ipv6;
        solaris_address_t address;
        if (slot >= range->count || !address_at(range, slot, &address) || find_name(candidate, normalized, family) ||
            find_address(candidate, &address)) { rc = SOLARIS_EINVAL; break; }
        if (now > UINT64_MAX - ttl || now > UINT64_MAX - hold) { rc = SOLARIS_EOVERFLOW; break; }
        fakeip_entry_t *e = solaris_memory_allocate(s->options.budget, sizeof(*e));
        if (!e) { rc = SOLARIS_ENOMEM; break; }
        memset(e, 0, sizeof(*e)); e->store = s; e->address = address; e->slot = slot;
        memcpy(e->name, normalized, n + 1u); atomic_init(&e->pins, 0u);
        e->visible_until = now + ttl; e->reuse_after = now + hold; link_entry(candidate, e);
    }
    if (rc == SOLARIS_OK) {
        memcpy(s->table, candidate->table, s->buckets * 2u * sizeof(*s->table));
        s->entries = candidate->entries; s->count = candidate->count;
        candidate->entries = NULL; candidate->count = 0u;
        s->cursor4 = c4; s->cursor6 = c6; s->last_seal = manifest->seal_id; s->initialized = 1;
    }
    (void)solaris_fakeip_destroy(candidate); return rc;
}
