#include "contracts/dns/cache.h"
#include <string.h>

#define NS_SECOND UINT64_C(1000000000)
typedef struct cache_entry {
    struct cache_entry *previous, *next, *hash_next;
    solaris_dns_cache_key_t key;
    const solaris_dns_wire_t *message;
    uint64_t inserted, expires, stale_until;
    size_t charge;
    uint32_t kind;
} cache_entry_t;
struct solaris_dns_cache {
    solaris_dns_cache_options_t options;
    solaris_dns_cache_stats_t stats;
    cache_entry_t *head, *tail;
    size_t buckets;
    cache_entry_t *table[];
};

solaris_status_t solaris_dns_cache_key_make(const solaris_dns_lookup_view_t *view,
    uint64_t policy, uint64_t upstream, const solaris_dns_wire_t *query, solaris_dns_cache_key_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    solaris_dns_lookup_view_t captured = {0};
    if (view) captured = *view; /* view may be &out->view. */
    memset(out, 0, sizeof(*out));
    if (!view || !query || captured.role < SOLARIS_DNS_ROUTE_TARGET || captured.role > SOLARIS_DNS_CLIENT_QUERY) return SOLARIS_EINVAL;
    const solaris_dns_header_t *header = solaris_dns_wire_header(query);
    const solaris_dns_edns_t *edns = solaris_dns_wire_edns(query);
    if (header->flags & SOLARIS_DNS_QR) return SOLARIS_EINVAL;
    if (header->flags & (uint16_t)~(SOLARIS_DNS_RD | SOLARIS_DNS_CD | SOLARIS_DNS_AD)) return SOLARIS_ENOTSUP;
    if (edns->option_count || edns->options_length || solaris_dns_wire_record_count(query) != (edns->present ? 1u : 0u)) return SOLARIS_ENOTSUP;
    out->view = captured; out->policy_id = policy; out->upstream_id = upstream;
    out->question = *solaris_dns_wire_question(query); out->query_flags = header->flags;
    out->udp_size = edns->udp_size; out->edns_flags = edns->flags;
    out->edns_present = edns->present; out->edns_version = edns->version;
    for (size_t p = 0; p < out->question.name.length;) {
        uint8_t n = out->question.name.bytes[p++];
        for (size_t i = 0; i < n; i++, p++) {
            uint8_t c = out->question.name.bytes[p];
            if (c >= 'A' && c <= 'Z') out->question.name.bytes[p] = (uint8_t)(c + ('a' - 'A'));
        }
    }
    return SOLARIS_OK;
}
int solaris_dns_cache_key_equal(const solaris_dns_cache_key_t *a, const solaris_dns_cache_key_t *b)
{
    if (!a || !b || !a->question.name.length || a->question.name.length > SOLARIS_DNS_MAX_NAME ||
        a->question.name.length != b->question.name.length) return 0;
    return a->view.role == b->view.role && a->view.config_revision == b->view.config_revision &&
        a->view.resolver_revision == b->view.resolver_revision && a->view.network_revision == b->view.network_revision &&
        a->view.selection_revision == b->view.selection_revision && a->policy_id == b->policy_id &&
        a->upstream_id == b->upstream_id && a->question.type == b->question.type && a->question.class_code == b->question.class_code &&
        a->query_flags == b->query_flags && a->udp_size == b->udp_size && a->edns_flags == b->edns_flags &&
        a->edns_present == b->edns_present && a->edns_version == b->edns_version &&
        !memcmp(a->question.name.bytes, b->question.name.bytes, a->question.name.length);
}
static uint64_t hash_word(uint64_t h, uint64_t n)
{ for (size_t i = 0; i < 8; i++) { h ^= n & 255u; h *= UINT64_C(1099511628211); n >>= 8; } return h; }
static size_t bucket(const solaris_dns_cache_t *c, const solaris_dns_cache_key_t *k)
{
    uint64_t h = UINT64_C(14695981039346656037);
    const uint64_t words[] = {k->view.role, k->view.config_revision, k->view.resolver_revision,
        k->view.network_revision, k->view.selection_revision, k->policy_id, k->upstream_id,
        k->question.type, k->question.class_code, k->query_flags, k->udp_size, k->edns_flags, k->edns_present, k->edns_version};
    for (size_t i = 0; i < sizeof(words) / sizeof(*words); i++) h = hash_word(h, words[i]);
    for (size_t i = 0; i < k->question.name.length; i++) { h ^= k->question.name.bytes[i]; h *= UINT64_C(1099511628211); }
    return (size_t)h & (c->buckets - 1u);
}
static solaris_status_t check_owner(const solaris_dns_cache_t *c)
{ return !c ? SOLARIS_EINVAL : solaris_executor_is_owner(c->options.owner) ? SOLARIS_OK : SOLARIS_ETHREAD; }
static solaris_status_t check_query(const solaris_dns_cache_key_t *key, const solaris_dns_wire_t *query)
{
    if (!key) return SOLARIS_EINVAL;
    solaris_dns_cache_key_t expected;
    solaris_status_t rc = solaris_dns_cache_key_make(&key->view, key->policy_id, key->upstream_id, query, &expected);
    return rc != SOLARIS_OK ? rc : solaris_dns_cache_key_equal(key, &expected) ? SOLARIS_OK : SOLARIS_EINVAL;
}
static cache_entry_t *find(solaris_dns_cache_t *c, const solaris_dns_cache_key_t *key)
{
    for (cache_entry_t *e = c->table[bucket(c, key)]; e; e = e->hash_next)
        if (solaris_dns_cache_key_equal(&e->key, key)) return e;
    return NULL;
}
static void unlink_lru(solaris_dns_cache_t *c, cache_entry_t *e)
{
    if (e->previous) e->previous->next = e->next; else c->head = e->next;
    if (e->next) e->next->previous = e->previous; else c->tail = e->previous;
}
static void promote(solaris_dns_cache_t *c, cache_entry_t *e)
{
    e->previous = NULL; e->next = c->head;
    if (c->head) c->head->previous = e; else c->tail = e;
    c->head = e;
}
static void erase(solaris_dns_cache_t *c, cache_entry_t *e)
{
    cache_entry_t **p = &c->table[bucket(c, &e->key)];
    while (*p != e) p = &(*p)->hash_next;
    *p = e->hash_next; unlink_lru(c, e);
    c->stats.entries--; c->stats.charged_bytes -= e->charge;
    solaris_dns_wire_release(e->message); solaris_memory_free(e);
}
void solaris_dns_cache_options_init(solaris_dns_cache_options_t *o)
{
    if (!o) return;
    memset(o, 0, sizeof(*o)); o->entry_limit = 4096u; o->byte_limit = 8u * 1024u * 1024u;
    o->record_limit = 256u; o->cname_depth = 32u; o->stale_window_ms = 300000u;
}
solaris_status_t solaris_dns_cache_create(const solaris_dns_cache_options_t *options, solaris_dns_cache_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!options || !options->owner || !options->budget) return SOLARIS_EINVAL;
    solaris_dns_cache_options_t o = *options;
    if (!o.entry_limit) o.entry_limit = 4096u;
    if (!o.byte_limit) o.byte_limit = 8u * 1024u * 1024u;
    if (!o.record_limit) o.record_limit = 256u;
    if (!o.cname_depth) o.cname_depth = 32u;
    if (o.entry_limit > 65536u || o.byte_limit > 1073741824u || o.record_limit > SOLARIS_DNS_MAX_RECORDS ||
        o.cname_depth > 128u || o.stale_window_ms > 86400000u) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(o.owner)) return SOLARIS_ETHREAD;
    size_t buckets = 2u; while (buckets < o.entry_limit * 2u) buckets *= 2u;
    size_t size = sizeof(solaris_dns_cache_t) + buckets * sizeof(cache_entry_t *);
    solaris_dns_cache_t *c = solaris_memory_allocate(o.budget, size); if (!c) return SOLARIS_ENOMEM;
    memset(c, 0, size); c->options = o; c->buckets = buckets; *out = c; return SOLARIS_OK;
}
solaris_status_t solaris_dns_cache_destroy(solaris_dns_cache_t *c)
{
    solaris_status_t rc = check_owner(c); if (rc != SOLARIS_OK) return rc;
    while (c->tail) erase(c, c->tail);
    solaris_memory_free(c); return SOLARIS_OK;
}
static int covers(const solaris_dns_name_t *zone, const solaris_dns_name_t *name)
{
    for (size_t offset = 0; offset < name->length;) {
        solaris_dns_name_t suffix; memset(&suffix, 0, sizeof(suffix));
        suffix.length = (uint16_t)(name->length - offset); memcpy(suffix.bytes, name->bytes + offset, suffix.length);
        if (solaris_dns_name_equal(zone, &suffix)) return 1;
        offset += (size_t)name->bytes[offset] + 1u;
    }
    return 0;
}
static uint32_t classify(const solaris_dns_cache_t *c, const solaris_dns_wire_t *query,
    const solaris_dns_wire_t *response, solaris_dns_cache_put_result_t *out)
{
    const solaris_dns_header_t *header = solaris_dns_wire_header(response);
    const solaris_dns_edns_t *edns = solaris_dns_wire_edns(response);
    const solaris_dns_question_t *question = solaris_dns_wire_question(query);
    size_t count = solaris_dns_wire_record_count(response);
    if (header->flags & SOLARIS_DNS_TC) return SOLARIS_DNS_CACHE_SKIP_TRUNCATED;
    if (header->rcode != 0u && header->rcode != 3u) return SOLARIS_DNS_CACHE_SKIP_RCODE;
    if (header->flags & SOLARIS_DNS_AD) return SOLARIS_DNS_CACHE_SKIP_AUTHENTICATED;
    if (edns->option_count || edns->options_length) return SOLARIS_DNS_CACHE_SKIP_EDNS;
    if (count > c->options.record_limit) return SOLARIS_DNS_CACHE_SKIP_LIMIT;
    uint32_t ttl = UINT32_MAX;
    size_t rebuilt = 12u + question->name.length + 4u + (solaris_dns_wire_edns(query)->present ? 11u : 0u);
    for (size_t i = 0; i < count; i++) {
        const solaris_dns_record_t *r = solaris_dns_wire_record(response, i);
        if (r->kind == SOLARIS_DNS_RDATA_OPT) continue;
        if (r->kind == SOLARIS_DNS_RDATA_OPAQUE || r->class_code != SOLARIS_DNS_IN || question->class_code != SOLARIS_DNS_IN)
            return SOLARIS_DNS_CACHE_SKIP_RDATA;
        if (!r->ttl) return SOLARIS_DNS_CACHE_SKIP_ZERO_TTL;
        if (r->ttl < ttl) ttl = r->ttl;
        size_t payload = r->kind == SOLARIS_DNS_RDATA_ADDRESS ? (r->type == SOLARIS_DNS_A ? 4u : 16u) :
            r->kind == SOLARIS_DNS_RDATA_NAME ? r->value.target.length :
            (size_t)r->value.soa.primary.length + r->value.soa.mailbox.length + 20u;
        size_t added = r->name.length + 10u + payload;
        if (added > SOLARIS_DNS_MAX_MESSAGE - rebuilt) return SOLARIS_DNS_CACHE_SKIP_LIMIT;
        rebuilt += added;
    }
    solaris_dns_name_t seen[129]; size_t used = 1u; seen[0] = question->name;
    int positive = 0;
    for (;;) {
        const solaris_dns_name_t *terminal = &seen[used - 1u];
        const solaris_dns_record_t *cname = NULL;
        for (size_t i = 0; i < count; i++) {
            const solaris_dns_record_t *r = solaris_dns_wire_record(response, i);
            if (r->section != SOLARIS_DNS_ANSWER || !solaris_dns_name_equal(&r->name, terminal)) continue;
            if (r->type == question->type) positive = 1;
            if (r->type == SOLARIS_DNS_CNAME) {
                if (cname && !solaris_dns_name_equal(&cname->value.target, &r->value.target)) return SOLARIS_DNS_CACHE_SKIP_CHAIN;
                cname = r;
            }
        }
        if (positive) {
            if (cname && question->type != SOLARIS_DNS_CNAME) return SOLARIS_DNS_CACHE_SKIP_CHAIN;
            break;
        }
        if (!cname) break;
        if (used > c->options.cname_depth) return SOLARIS_DNS_CACHE_SKIP_CHAIN;
        for (size_t i = 0; i < used; i++) if (solaris_dns_name_equal(&seen[i], &cname->value.target)) return SOLARIS_DNS_CACHE_SKIP_CHAIN;
        seen[used++] = cname->value.target;
    }
    if (positive) {
        if (header->rcode) return SOLARIS_DNS_CACHE_SKIP_NO_ANSWER;
        out->kind = SOLARIS_DNS_CACHE_POSITIVE;
    } else {
        const solaris_dns_record_t *soa = NULL;
        for (size_t i = 0; i < count; i++) {
            const solaris_dns_record_t *r = solaris_dns_wire_record(response, i);
            if (r->section == SOLARIS_DNS_ANSWER) {
                if (r->type != SOLARIS_DNS_CNAME) return SOLARIS_DNS_CACHE_SKIP_NO_ANSWER;
                int linked = 0;
                for (size_t j = 0; j < used; j++) if (solaris_dns_name_equal(&r->name, &seen[j])) linked = 1;
                if (!linked) return SOLARIS_DNS_CACHE_SKIP_CHAIN;
            }
            if (r->section == SOLARIS_DNS_AUTHORITY && r->type == SOLARIS_DNS_SOA) {
                if (soa || !covers(&r->name, &seen[used - 1u])) return SOLARIS_DNS_CACHE_SKIP_NO_ANSWER;
                soa = r;
            }
        }
        if (!soa) return SOLARIS_DNS_CACHE_SKIP_NO_ANSWER;
        if (!soa->value.soa.minimum) return SOLARIS_DNS_CACHE_SKIP_ZERO_TTL;
        if (soa->value.soa.minimum < ttl) ttl = soa->value.soa.minimum;
        out->kind = header->rcode == 3u ? SOLARIS_DNS_CACHE_NXDOMAIN : SOLARIS_DNS_CACHE_NODATA;
    }
    out->ttl_seconds = ttl; return SOLARIS_DNS_CACHE_STORED;
}
solaris_status_t solaris_dns_cache_put(solaris_dns_cache_t *c, const solaris_dns_cache_key_t *key,
    const solaris_dns_wire_t *query, const solaris_dns_wire_t *response, solaris_dns_cache_put_result_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    solaris_status_t rc = check_owner(c); if (rc != SOLARIS_OK) return rc;
    rc = check_query(key, query); if (rc != SOLARIS_OK) return rc;
    if (!response || solaris_dns_wire_validate_reply(query, response) != SOLARIS_OK) return SOLARIS_EINVAL;
    out->reason = classify(c, query, response, out);
    if (out->reason) {
        if (out->reason != SOLARIS_DNS_CACHE_SKIP_TRUNCATED && out->reason != SOLARIS_DNS_CACHE_SKIP_RCODE) {
            cache_entry_t *old = find(c, key); if (old) erase(c, old);
        }
        c->stats.skipped++; return SOLARIS_OK;
    }
    /* Includes public parsed metadata plus a conservative allowance for the
     * opaque wire/buffer headers, reference counters and allocator prefixes. */
    size_t charge = sizeof(cache_entry_t) + solaris_buffer_length(solaris_dns_wire_buffer(response)) +
        solaris_dns_wire_record_count(response) * sizeof(solaris_dns_record_t) +
        sizeof(solaris_dns_question_t) + sizeof(solaris_dns_header_t) + sizeof(solaris_dns_edns_t) + 16u * sizeof(void *) + 128u;
    if (charge > c->options.byte_limit) {
        cache_entry_t *old = find(c, key); if (old) erase(c, old);
        out->reason = SOLARIS_DNS_CACHE_SKIP_LIMIT; c->stats.skipped++; return SOLARIS_OK;
    }
    uint64_t now = solaris_executor_now_ns(c->options.owner), lifetime = (uint64_t)out->ttl_seconds * NS_SECOND;
    uint64_t stale = c->options.stale_window_ms * UINT64_C(1000000);
    if (now > UINT64_MAX - lifetime || now + lifetime > UINT64_MAX - stale) return SOLARIS_EOVERFLOW;
    cache_entry_t *e = solaris_memory_allocate(c->options.budget, sizeof(*e)); if (!e) return SOLARIS_ENOMEM;
    memset(e, 0, sizeof(*e)); e->key = *key; e->message = response; e->charge = charge; e->kind = out->kind;
    e->inserted = now; e->expires = now + lifetime; e->stale_until = e->expires + stale;
    solaris_dns_wire_retain(response);
    cache_entry_t *old = find(c, key); if (old) erase(c, old);
    while (c->stats.entries == c->options.entry_limit || c->stats.charged_bytes > c->options.byte_limit - charge) {
        erase(c, c->tail); c->stats.evictions++;
    }
    size_t index = bucket(c, key); e->hash_next = c->table[index]; c->table[index] = e; promote(c, e);
    c->stats.entries++; c->stats.charged_bytes += charge; out->stored = 1; return SOLARIS_OK;
}
solaris_status_t solaris_dns_cache_get(solaris_dns_cache_t *c, const solaris_dns_cache_key_t *key,
    const solaris_dns_wire_t *query, int allow_stale, solaris_dns_cache_hit_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    solaris_status_t rc = check_owner(c); if (rc != SOLARIS_OK) return rc;
    rc = check_query(key, query); if (rc != SOLARIS_OK) return rc;
    if (allow_stale != 0 && allow_stale != 1) return SOLARIS_EINVAL;
    cache_entry_t *e = find(c, key); uint64_t now = solaris_executor_now_ns(c->options.owner);
    if (!e) { c->stats.misses++; return SOLARIS_OK; }
    if (now < e->inserted || now >= e->stale_until) { erase(c, e); c->stats.misses++; return SOLARIS_OK; }
    int stale = now >= e->expires;
    if (stale && !allow_stale) { c->stats.misses++; return SOLARIS_OK; }
    size_t count = solaris_dns_wire_record_count(e->message);
    solaris_dns_record_t *records = solaris_memory_allocate(c->options.budget, count * sizeof(*records));
    if (!records) return SOLARIS_ENOMEM;
    size_t selected = 0; uint64_t elapsed = (now - e->inserted) / NS_SECOND;
    for (size_t i = 0; i < count; i++) {
        const solaris_dns_record_t *original = solaris_dns_wire_record(e->message, i);
        if (original->kind == SOLARIS_DNS_RDATA_OPT) continue;
        records[selected] = *original;
        uint32_t ttl = original->ttl;
        if (e->kind != SOLARIS_DNS_CACHE_POSITIVE && original->kind == SOLARIS_DNS_RDATA_SOA && original->value.soa.minimum < ttl)
            ttl = original->value.soa.minimum;
        records[selected++].ttl = stale ? 1u : elapsed < ttl ? (uint32_t)(ttl - elapsed) : 0u;
    }
    const solaris_dns_header_t *header = solaris_dns_wire_header(e->message);
    rc = solaris_dns_wire_make_response(c->options.budget, query,
        (uint16_t)(header->flags & (SOLARIS_DNS_AA | SOLARIS_DNS_RA)), header->rcode, records, selected, &out->wire);
    solaris_memory_free(records);
    if (rc != SOLARIS_OK) return rc;
    out->found = 1u; out->kind = e->kind; out->stale = out->needs_refresh = (uint32_t)stale;
    unlink_lru(c, e); promote(c, e); c->stats.hits++; if (stale) c->stats.stale_hits++;
    return SOLARIS_OK;
}
solaris_status_t solaris_dns_cache_flush(solaris_dns_cache_t *c, uint32_t fields,
    uint64_t network, uint64_t resolver, size_t *removed)
{
    if (removed) *removed = 0;
    solaris_status_t rc = check_owner(c); if (rc != SOLARIS_OK) return rc;
    if (fields & ~(uint32_t)(SOLARIS_DNS_CACHE_FLUSH_NETWORK | SOLARIS_DNS_CACHE_FLUSH_RESOLVER)) return SOLARIS_EINVAL;
    size_t n = 0; cache_entry_t *e = c->head;
    while (e) {
        cache_entry_t *next = e->next;
        if ((!(fields & SOLARIS_DNS_CACHE_FLUSH_NETWORK) || e->key.view.network_revision == network) &&
            (!(fields & SOLARIS_DNS_CACHE_FLUSH_RESOLVER) || e->key.view.resolver_revision == resolver)) { erase(c, e); n++; }
        e = next;
    }
    if (removed) *removed = n;
    return SOLARIS_OK;
}
solaris_status_t solaris_dns_cache_snapshot(solaris_dns_cache_t *c, solaris_dns_cache_stats_t *out)
{
    solaris_status_t rc = check_owner(c); if (rc != SOLARIS_OK) return rc;
    if (!out) return SOLARIS_EINVAL;
    *out = c->stats; return SOLARIS_OK;
}
