#include "contracts/dns/hosts.h"
#include <stdatomic.h>
#include <string.h>

/* Matching order follows fixed mihomo 9f121787bb56 component/trie/domain.go;
 * layer precedence/default localhost follow component/resolver/host.go and
 * config.parseHosts. Construction deliberately rejects duplicate expansions. */
typedef struct host_record host_record_t;
typedef struct host_node {
    struct host_node *child, *sibling, *allocation_next;
    host_record_t *record;
    char label[64];
} host_node_t;
struct host_record {
    uint32_t kind, source, state, hops;
    size_t index, count;
    solaris_address_t *addresses;
    char alias[254], terminal_name[254];
    host_record_t *terminal;
};
struct solaris_hosts {
    atomic_size_t references;
    solaris_budget_t *budget;
    solaris_hosts_options_t options;
    host_node_t roots[2], *nodes;
    size_t node_count, record_count, address_count;
    host_record_t records[];
};
typedef struct domain {
    char text[254];
    uint16_t offset[127], length[127];
    size_t labels;
    int suffix, plus;
} domain_t;

static solaris_status_t diagnostic(solaris_hosts_diagnostic_t *d, solaris_status_t status,
    uint32_t reason, uint32_t source, size_t index, const char *message)
{
    if (d) {
        memset(d, 0, sizeof(*d)); d->status = status; d->reason = reason;
        d->source = source; d->entry_index = index;
        size_t n = strlen(message); if (n >= sizeof(d->message)) n = sizeof(d->message) - 1u;
        memcpy(d->message, message, n);
    }
    return status;
}
static solaris_status_t record_error(solaris_hosts_diagnostic_t *d, const host_record_t *r,
    solaris_status_t status, uint32_t reason, const char *message)
{ return diagnostic(d, status, reason, r->source, r->index, message); }
static int domain_parse(const char *input, int pattern, domain_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!input) return 0;
    size_t n = 0; while (n < 257u && input[n]) n++;
    if (!n || n == 257u) return 0;
    if (input[n - 1u] == '.') n--;
    size_t begin = 0;
    if (pattern && n > 1u && input[0] == '.') { out->suffix = 1; begin = 1u; }
    else if (pattern && n > 2u && input[0] == '+' && input[1] == '.') { out->plus = 1; begin = 2u; }
    if (n <= begin || n - begin > 253u) return 0;
    size_t length = n - begin, label_start = 0;
    for (size_t i = 0; i <= length; i++) {
        unsigned char c = i == length ? 0u : (unsigned char)input[begin + i];
        if (c == '.' || i == length) {
            size_t label = i - label_start;
            if (!label || label > 63u || out->labels == 127u) return 0;
            out->offset[out->labels] = (uint16_t)label_start;
            out->length[out->labels++] = (uint16_t)label;
            if (label == 1u && out->text[label_start] == '*') { if (!pattern) return 0; }
            else for (size_t j = label_start; j < i; j++) if (out->text[j] == '*') return 0;
            label_start = i + 1u;
        } else if (c < 0x21u || c > 0x7eu || c == '+') return 0;
        out->text[i] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
    }
    return 1;
}
static const host_node_t *child(const host_node_t *node, const char *label, size_t n)
{
    for (const host_node_t *p = node->child; p; p = p->sibling)
        if (strlen(p->label) == n && !memcmp(p->label, label, n)) return p;
    return NULL;
}
static host_node_t *ensure_child(solaris_hosts_t *h, host_node_t *node,
    const char *label, size_t n, solaris_status_t *status)
{
    host_node_t *p = (host_node_t *)child(node, label, n); if (p) return p;
    if (h->node_count == h->options.nodes) { *status = SOLARIS_EOVERFLOW; return NULL; }
    p = solaris_memory_allocate(h->budget, sizeof(*p));
    if (!p) { *status = SOLARIS_ENOMEM; return NULL; }
    memset(p, 0, sizeof(*p)); memcpy(p->label, label, n);
    p->sibling = node->child; node->child = p;
    p->allocation_next = h->nodes; h->nodes = p; h->node_count++; return p;
}
static solaris_status_t assign(host_node_t *node, host_record_t *r)
{
    if (node->record && node->record->source != SOLARIS_HOSTS_DEFAULT) return SOLARIS_EINVAL;
    node->record = r; return SOLARIS_OK;
}
static solaris_status_t insert(solaris_hosts_t *h, const domain_t *name, host_record_t *r)
{
    host_node_t *node = &h->roots[r->source == SOLARIS_HOSTS_SYSTEM ? 1u : 0u];
    solaris_status_t rc = SOLARIS_OK;
    for (size_t i = name->labels; i > 0u; i--) {
        node = ensure_child(h, node, name->text + name->offset[i - 1u], name->length[i - 1u], &rc);
        if (!node) return rc;
    }
    if (!name->suffix) { rc = assign(node, r); if (rc != SOLARIS_OK) return rc; }
    if (name->suffix || name->plus) {
        node = ensure_child(h, node, "", 0u, &rc); if (!node) return rc;
        rc = assign(node, r);
    }
    return rc;
}
static host_record_t *search(const host_node_t *node, const domain_t *name, size_t labels)
{
    if (!labels) return node->record;
    const host_node_t *p = child(node, name->text + name->offset[labels - 1u], name->length[labels - 1u]);
    host_record_t *r = p ? search(p, name, labels - 1u) : NULL;
    if (r) return r;
    p = child(node, "*", 1u); r = p ? search(p, name, labels - 1u) : NULL;
    if (r) return r;
    p = child(node, "", 0u); return p ? p->record : NULL;
}
void solaris_hosts_options_init(solaris_hosts_options_t *o)
{
    if (!o) return;
    *o = (solaris_hosts_options_t){SOLARIS_HOSTS_DEFAULT_ENTRIES, SOLARIS_HOSTS_DEFAULT_NODES,
        SOLARIS_HOSTS_DEFAULT_ALIAS_DEPTH, SOLARIS_HOSTS_MAX_ADDRESSES, 65536u};
}
static int normalize_address(const solaris_address_t *in, solaris_address_t *out)
{
    if ((in->family != SOLARIS_ADDRESS_IPV4 && in->family != SOLARIS_ADDRESS_IPV6) ||
        in->scope_id || in->port || in->host[0]) return 0;
    memset(out, 0, sizeof(*out)); out->family = in->family;
    if (in->family == SOLARIS_ADDRESS_IPV4) {
        for (size_t i = 4; i < 16; i++) if (in->ip[i]) return 0;
        memcpy(out->ip, in->ip, 4u);
    } else {
        static const uint8_t mapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
        if (!memcmp(in->ip, mapped, sizeof(mapped))) { out->family = SOLARIS_ADDRESS_IPV4; memcpy(out->ip, in->ip + 12, 4u); }
        else memcpy(out->ip, in->ip, 16u);
    }
    return 1;
}
static solaris_status_t parse_entry(solaris_hosts_t *h, const solaris_hosts_entry_t *input,
    host_record_t *r, solaris_hosts_diagnostic_t *d)
{
    domain_t name;
    if (!domain_parse(input->name, r->source != SOLARIS_HOSTS_SYSTEM, &name))
        return record_error(d, r, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_NAME, "invalid hosts name or pattern");
    r->kind = input->kind;
    if (input->kind == SOLARIS_HOSTS_ADDRESSES) {
        if (!input->addresses || !input->address_count || input->alias)
            return record_error(d, r, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_INPUT, "address entry requires only a nonempty numeric list");
        if (input->address_count > h->options.addresses_per_entry ||
            input->address_count > h->options.address_total - h->address_count)
            return record_error(d, r, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_LIMIT, "hosts address limit exceeded");
        r->addresses = solaris_memory_allocate(h->budget, input->address_count * sizeof(*r->addresses));
        if (!r->addresses) return record_error(d, r, SOLARIS_ENOMEM, SOLARIS_HOSTS_MEMORY, "hosts address allocation failed");
        for (size_t i = 0; i < input->address_count; i++) if (!normalize_address(&input->addresses[i], &r->addresses[i]))
            return record_error(d, r, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_ADDRESS, "hosts address must be numeric without port or scope");
        r->count = input->address_count; h->address_count += r->count;
    } else if (input->kind == SOLARIS_HOSTS_ALIAS) {
        domain_t alias;
        if (input->addresses || input->address_count || !domain_parse(input->alias, 0, &alias))
            return record_error(d, r, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_NAME, "alias entry requires one valid plain domain");
        memcpy(r->alias, alias.text, strlen(alias.text) + 1u);
    } else return record_error(d, r, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_INPUT, "unknown hosts entry kind");
    solaris_status_t rc = insert(h, &name, r);
    if (rc != SOLARIS_OK) return record_error(d, r, rc,
        rc == SOLARIS_ENOMEM ? SOLARIS_HOSTS_MEMORY : rc == SOLARIS_EOVERFLOW ? SOLARIS_HOSTS_LIMIT : SOLARIS_HOSTS_DUPLICATE,
        rc == SOLARIS_ENOMEM ? "hosts trie allocation failed" : rc == SOLARIS_EOVERFLOW ? "hosts node limit exceeded" : "duplicate normalized hosts pattern");
    return SOLARIS_OK;
}
static solaris_status_t resolve(solaris_hosts_t *h, host_record_t *r, uint32_t depth, solaris_hosts_diagnostic_t *d)
{
    if (r->state == 2u) return SOLARIS_OK;
    if (r->state == 1u) return record_error(d, r, SOLARIS_EINVAL, SOLARIS_HOSTS_ALIAS_CYCLE, "hosts alias cycle");
    if (r->kind == SOLARIS_HOSTS_ADDRESSES) { r->state = 2u; r->terminal = r; return SOLARIS_OK; }
    if (depth >= h->options.alias_depth)
        return record_error(d, r, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_ALIAS_DEPTH, "hosts alias depth exceeded");
    r->state = 1u;
    domain_t target; (void)domain_parse(r->alias, 0, &target);
    host_record_t *next = search(&h->roots[r->source == SOLARIS_HOSTS_SYSTEM ? 1u : 0u], &target, target.labels);
    r->hops = 1u;
    if (next) {
        solaris_status_t rc = resolve(h, next, depth + 1u, d); if (rc != SOLARIS_OK) return rc;
        r->hops += next->hops; r->terminal = next->terminal;
        if (r->hops > h->options.alias_depth)
            return record_error(d, r, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_ALIAS_DEPTH, "hosts alias depth exceeded");
        const char *terminal = next->kind == SOLARIS_HOSTS_ALIAS ? next->terminal_name : r->alias;
        memcpy(r->terminal_name, terminal, strlen(terminal) + 1u);
    } else memcpy(r->terminal_name, r->alias, strlen(r->alias) + 1u);
    r->state = 2u; return SOLARIS_OK;
}
solaris_status_t solaris_hosts_build(solaris_budget_t *budget, const solaris_hosts_entry_t *config,
    size_t config_count, const solaris_hosts_entry_t *system, size_t system_count,
    const solaris_hosts_options_t *options, solaris_hosts_t **out, solaris_hosts_diagnostic_t *d)
{
    if (d) { memset(d, 0, sizeof(*d)); d->entry_index = SIZE_MAX; }
    if (!out) return diagnostic(d, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_INPUT, 0, SIZE_MAX, "missing hosts output");
    *out = NULL;
    if (!budget || (config_count && !config) || (system_count && !system))
        return diagnostic(d, SOLARIS_EINVAL, SOLARIS_HOSTS_INVALID_INPUT, 0, SIZE_MAX, "invalid hosts input arrays");
    solaris_hosts_options_t o; solaris_hosts_options_init(&o);
    if (options) {
        if (options->entries) o.entries = options->entries;
        if (options->nodes) o.nodes = options->nodes;
        if (options->alias_depth) o.alias_depth = options->alias_depth;
        if (options->addresses_per_entry) o.addresses_per_entry = options->addresses_per_entry;
        if (options->address_total) o.address_total = options->address_total;
    }
    if (o.entries > 65536u || o.nodes > 1048576u || o.alias_depth > 128u ||
        o.addresses_per_entry > SOLARIS_HOSTS_MAX_ADDRESSES || o.address_total > 1048576u)
        return diagnostic(d, SOLARIS_EINVAL, SOLARIS_HOSTS_LIMIT, 0, SIZE_MAX, "invalid hosts limits");
    if (config_count >= o.entries || system_count >= o.entries || config_count + system_count >= o.entries)
        return diagnostic(d, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_LIMIT, 0, SIZE_MAX, "hosts entry limit exceeded");
    if (o.nodes < 3u) return diagnostic(d, SOLARIS_EOVERFLOW, SOLARIS_HOSTS_LIMIT, 0, SIZE_MAX, "hosts node limit excludes localhost");
    size_t count = 1u + config_count + system_count;
    solaris_hosts_t *h = solaris_memory_allocate(budget, sizeof(*h) + count * sizeof(*h->records));
    if (!h) return diagnostic(d, SOLARIS_ENOMEM, SOLARIS_HOSTS_MEMORY, 0, SIZE_MAX, "hosts snapshot allocation failed");
    memset(h, 0, sizeof(*h) + count * sizeof(*h->records)); atomic_init(&h->references, 1u);
    h->budget = budget; h->options = o; h->record_count = count; h->node_count = 2u;
    solaris_address_t loopback; memset(&loopback, 0, sizeof(loopback));
    loopback.family = SOLARIS_ADDRESS_IPV4; loopback.ip[0] = 127; loopback.ip[3] = 1;
    solaris_hosts_entry_t builtin = {"localhost", SOLARIS_HOSTS_ADDRESSES, &loopback, 1u, NULL};
    h->records[0].source = SOLARIS_HOSTS_DEFAULT; h->records[0].index = SIZE_MAX;
    solaris_status_t rc = parse_entry(h, &builtin, &h->records[0], d);
    for (size_t i = 0; rc == SOLARIS_OK && i < config_count + system_count; i++) {
        host_record_t *r = &h->records[i + 1u];
        r->source = i < config_count ? SOLARIS_HOSTS_CONFIG : SOLARIS_HOSTS_SYSTEM;
        r->index = i < config_count ? i : i - config_count;
        rc = parse_entry(h, i < config_count ? &config[i] : &system[i - config_count], r, d);
    }
    for (size_t i = 0; rc == SOLARIS_OK && i < count; i++) rc = resolve(h, &h->records[i], 0u, d);
    if (rc != SOLARIS_OK) { solaris_hosts_release(h); return rc; }
    *out = h; return SOLARIS_OK;
}
void solaris_hosts_retain(const solaris_hosts_t *hosts)
{
    if (hosts) (void)atomic_fetch_add_explicit(&((solaris_hosts_t *)hosts)->references, 1u, memory_order_relaxed);
}
void solaris_hosts_release(const solaris_hosts_t *hosts)
{
    solaris_hosts_t *h = (solaris_hosts_t *)hosts;
    if (!h || atomic_fetch_sub_explicit(&h->references, 1u, memory_order_acq_rel) != 1u) return;
    host_node_t *p = h->nodes;
    while (p) { host_node_t *next = p->allocation_next; solaris_memory_free(p); p = next; }
    for (size_t i = 0; i < h->record_count; i++) solaris_memory_free(h->records[i].addresses);
    solaris_memory_free(h);
}
solaris_status_t solaris_hosts_lookup(const solaris_hosts_t *h, const char *name, uint32_t family, solaris_hosts_result_t *out)
{
    if (!out) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out)); out->entry_index = SIZE_MAX;
    if (!h || (family != 0u && family != SOLARIS_ADDRESS_IPV4 && family != SOLARIS_ADDRESS_IPV6)) return SOLARIS_EINVAL;
    domain_t parsed; if (!domain_parse(name, 0, &parsed)) return SOLARIS_EINVAL;
    host_record_t *r = search(&h->roots[0], &parsed, parsed.labels);
    if (!r) r = search(&h->roots[1], &parsed, parsed.labels);
    if (!r) return SOLARIS_OK;
    out->matched = 1u; out->source = r->source; out->entry_index = r->index; out->alias_hops = r->hops;
    memcpy(out->first_alias, r->alias, strlen(r->alias) + 1u);
    const char *terminal = r->kind == SOLARIS_HOSTS_ALIAS ? r->terminal_name : parsed.text;
    memcpy(out->terminal_name, terminal, strlen(terminal) + 1u);
    out->kind = r->terminal ? SOLARIS_HOSTS_ADDRESSES : SOLARIS_HOSTS_ALIAS;
    if (r->terminal) for (size_t i = 0; i < r->terminal->count; i++) {
        const solaris_address_t *a = &r->terminal->addresses[i];
        if (!family || family == a->family) out->addresses[out->address_count++] = *a;
    }
    return SOLARIS_OK;
}
