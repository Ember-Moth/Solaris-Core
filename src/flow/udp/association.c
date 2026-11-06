#include "contracts/flow/udp.h"
#include <assert.h>
#include <string.h>
#include <uv.h>

enum { WORKER_LIMIT = 32, PUMP_BUDGET = 64 };
typedef struct association association_t;
typedef struct mapping mapping_t;
typedef struct lane {
    association_t *association;
    solaris_datagram_t *channel;
    solaris_deadline_t *deadline;
    uint64_t due;
    uint32_t family;
    int ready;
} lane_t;
typedef struct packet {
    struct packet *next;
    association_t *association;
    solaris_address_t target;
    solaris_slice_t payload;
    solaris_io_done_fn done;
    void *context;
    uint64_t sequence;
} packet_t;
struct mapping {
    mapping_t *next;
    association_t *association;
    solaris_address_t original, actual;
    void *request;
    uint64_t due;
    uint64_t failed_through;
    solaris_status_t status;
    int resolved;
    lane_t lane;
};
struct association {
    association_t *next;
    solaris_udp_dispatcher_t *dispatcher;
    solaris_executor_t *owner;
    solaris_udp_key_t key;
    solaris_udp_reply_endpoint_t reply;
    solaris_udp_plan_t plan;
    solaris_scope_t scope;
    solaris_deferred_t pump;
    solaris_deadline_t *idle;
    uint64_t idle_due;
    lane_t lanes[3];
    mapping_t *mappings;
    size_t mapping_count;
    uint32_t capabilities;
    solaris_status_t status;
    int initialized, closing, scheduler_lease, active;
    /* Protected by dispatcher mutex, including stats and ingress queue. */
    packet_t *head, *tail;
    int scheduled, close_requested;
    solaris_udp_snapshot_t stats;
};
struct solaris_udp_dispatcher {
    uv_mutex_t mutex;
    solaris_udp_dispatcher_options_t options;
    solaris_executor_t *workers[WORKER_LIMIT];
    void *engine_context;
    association_t *entries;
    size_t entries_count, references;
    uint64_t next_id;
    int closed;
};

static void pump(void *context);
static void close_entry(association_t *entry, solaris_status_t status);
static void touch(association_t *entry);

static solaris_status_t normalize_address(const solaris_address_t *input, solaris_address_t *out, int numeric)
{
    if (input == NULL) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    out->family = input->family; out->port = input->port;
    if (input->family == SOLARIS_ADDRESS_IPV4) memcpy(out->ip, input->ip, 4u);
    else if (input->family == SOLARIS_ADDRESS_IPV6) {
        memcpy(out->ip, input->ip, 16u); out->scope_id = input->scope_id;
    } else if (!numeric && input->family == SOLARIS_ADDRESS_DOMAIN &&
               memchr(input->host, '\0', sizeof(input->host)) != NULL) {
        return solaris_address_parse(input->host, input->port, out);
    } else return SOLARIS_EINVAL;
    return SOLARIS_OK;
}
static solaris_status_t normalize_key(const solaris_udp_key_t *input, solaris_udp_key_t *out)
{
    if (input == NULL) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    out->inbound_id = input->inbound_id; out->inbound_generation = input->inbound_generation;
    out->client_id = input->client_id;
    return normalize_address(&input->source, &out->source, 1);
}
static int equal_key(const solaris_udp_key_t *a, const solaris_udp_key_t *b)
{
    return a->inbound_id == b->inbound_id && a->inbound_generation == b->inbound_generation &&
           a->client_id == b->client_id && solaris_address_equal(&a->source, &b->source);
}
static uint64_t hash_part(uint64_t hash, uint64_t value)
{
    for (unsigned i = 0; i < 8u; ++i) { hash ^= value & 255u; hash *= UINT64_C(1099511628211); value >>= 8u; }
    return hash;
}
static uint64_t key_hash(const solaris_udp_key_t *key)
{
    uint64_t hash = hash_part(UINT64_C(14695981039346656037), key->inbound_id);
    hash = hash_part(hash, key->inbound_generation); hash = hash_part(hash, key->client_id);
    hash = hash_part(hash, key->source.family); hash = hash_part(hash, key->source.scope_id);
    hash = hash_part(hash, key->source.port);
    for (size_t i = 0; i < (key->source.family == SOLARIS_ADDRESS_IPV4 ? 4u : 16u); ++i)
        hash = hash_part(hash, key->source.ip[i]);
    return hash;
}
static association_t *find_entry(solaris_udp_dispatcher_t *dispatcher, const solaris_udp_key_t *key)
{
    for (association_t *entry = dispatcher->entries; entry != NULL; entry = entry->next)
        if (equal_key(&entry->key, key)) return entry;
    return NULL;
}
static solaris_status_t schedule_locked(association_t *entry)
{
    if (entry->scheduled) return SOLARIS_OK;
    entry->scheduled = 1;
    solaris_status_t rc = solaris_executor_defer(entry->owner, &entry->pump);
    if (rc != SOLARIS_OK) entry->scheduled = 0;
    return rc;
}
static void schedule(association_t *entry)
{
    uv_mutex_lock(&entry->dispatcher->mutex);
    solaris_status_t rc = schedule_locked(entry);
    uv_mutex_unlock(&entry->dispatcher->mutex);
    assert(rc == SOLARIS_OK); (void)rc;
}
static int close_requested(association_t *entry)
{
    uv_mutex_lock(&entry->dispatcher->mutex);
    int result = entry->close_requested;
    uv_mutex_unlock(&entry->dispatcher->mutex);
    return result;
}
static solaris_status_t due_after(association_t *entry, uint64_t milliseconds, uint64_t *out)
{
    uint64_t now = solaris_executor_now_ns(entry->owner), duration = milliseconds * UINT64_C(1000000);
    if (duration > UINT64_MAX - now) return SOLARIS_EOVERFLOW;
    *out = now + duration;
    return SOLARIS_OK;
}
static solaris_status_t system_resolve(void *context, solaris_executor_t *owner,
                                       const solaris_address_t *target, uint64_t timeout_ms,
                                       solaris_resolve_fn callback, void *user, void **out)
{
    (void)context;
    solaris_resolve_t *request = NULL;
    solaris_status_t rc = solaris_resolve_start(owner, target, timeout_ms, callback, user, &request);
    *out = request;
    return rc;
}
static void system_cancel_resolve(void *context, void *request)
{ (void)context; solaris_resolve_cancel(request); }

static void unlink_entry_locked(association_t *entry)
{
    solaris_udp_dispatcher_t *dispatcher = entry->dispatcher;
    association_t **cursor = &dispatcher->entries;
    while (*cursor != NULL && *cursor != entry) cursor = &(*cursor)->next;
    assert(*cursor == entry);
    *cursor = entry->next;
    dispatcher->entries_count--;
}
static void destroy_entry(void *context)
{
    association_t *entry = context;
    solaris_udp_dispatcher_t *dispatcher = entry->dispatcher;
    uv_mutex_lock(&dispatcher->mutex);
    assert(!entry->scheduled && entry->head == NULL && entry->stats.pending_packets == 0u);
    unlink_entry_locked(entry);
    solaris_udp_snapshot_t stats = entry->stats;
    uv_mutex_unlock(&dispatcher->mutex);
    if (entry->plan.release != NULL) entry->plan.release(entry->plan.context);
    if (dispatcher->options.on_close != NULL)
        dispatcher->options.on_close(dispatcher->options.context, &entry->key, &stats, entry->status);
    entry->reply.release(entry->reply.context);
    mapping_t *mapping = entry->mappings;
    while (mapping != NULL) { mapping_t *next = mapping->next; solaris_memory_free(mapping); mapping = next; }
    solaris_memory_free(entry);
    uv_mutex_lock(&dispatcher->mutex);
    assert(dispatcher->references != 0u);
    dispatcher->references--;
    uv_mutex_unlock(&dispatcher->mutex);
}
static void cancel_lane(lane_t *lane)
{
    if (lane->channel != NULL) (void)solaris_datagram_close(lane->channel);
    if (lane->deadline != NULL) solaris_deadline_cancel(lane->deadline);
}
static void cancel_entry(void *context)
{
    association_t *entry = context;
    entry->closing = 1;
    if (entry->status == SOLARIS_OK) entry->status = SOLARIS_ECANCELLED;
    uv_mutex_lock(&entry->dispatcher->mutex);
    entry->close_requested = 1; entry->stats.closing = 1u;
    uv_mutex_unlock(&entry->dispatcher->mutex);
    if (entry->idle != NULL) solaris_deadline_cancel(entry->idle);
    for (size_t i = 0; i < 3u; ++i) cancel_lane(&entry->lanes[i]);
    for (mapping_t *mapping = entry->mappings; mapping != NULL; mapping = mapping->next) {
        cancel_lane(&mapping->lane);
        if (mapping->request != NULL)
            entry->dispatcher->options.cancel_resolve(entry->dispatcher->options.context, mapping->request);
    }
    schedule(entry);
}
static void close_entry(association_t *entry, solaris_status_t status)
{
    if (entry->closing) return;
    entry->status = status;
    if (entry->initialized) solaris_scope_cancel(&entry->scope);
    else cancel_entry(entry);
}
static void finish_packet(packet_t *packet, solaris_status_t status)
{
    association_t *entry = packet->association;
    uv_mutex_lock(&entry->dispatcher->mutex);
    assert(entry->stats.pending_packets != 0u && entry->stats.pending_bytes >= packet->payload.length);
    entry->stats.pending_packets--; entry->stats.pending_bytes -= packet->payload.length;
    if (status == SOLARIS_OK) entry->stats.sent++;
    else entry->stats.failed++;
    uv_mutex_unlock(&entry->dispatcher->mutex);
    packet->done(packet->context, status);
    solaris_buffer_release(packet->payload.buffer);
    solaris_memory_free(packet);
}
static void sent(void *context, solaris_status_t status)
{
    packet_t *packet = context;
    association_t *entry = packet->association;
    if (status == SOLARIS_OK && !entry->closing) touch(entry);
    finish_packet(packet, status);
    /* Channel on_close is after all send completions and holds our scope. */
}
static void idle_expired(void *context, solaris_status_t status)
{
    association_t *entry = context;
    entry->idle = NULL;
    if (status == SOLARIS_OK && !entry->closing) {
        uint64_t now = solaris_executor_now_ns(entry->owner);
        if (now >= entry->idle_due) close_entry(entry, SOLARIS_ETIMEDOUT);
        else {
            uint64_t delay = (entry->idle_due - now) / UINT64_C(1000000) + 1u;
            solaris_scope_retain(&entry->scope);
            solaris_status_t rc = solaris_deadline_start(entry->owner, delay, idle_expired, entry, &entry->idle);
            if (rc != SOLARIS_OK) { solaris_scope_release(&entry->scope); close_entry(entry, rc); }
        }
    }
    solaris_scope_release(&entry->scope);
}
static void touch(association_t *entry)
{
    solaris_status_t rc = due_after(entry, entry->dispatcher->options.idle_timeout_ms, &entry->idle_due);
    if (rc != SOLARIS_OK) { close_entry(entry, rc); return; }
    if (entry->idle == NULL) {
        solaris_scope_retain(&entry->scope);
        rc = solaris_deadline_start(entry->owner, entry->dispatcher->options.idle_timeout_ms,
                                     idle_expired, entry, &entry->idle);
        if (rc != SOLARIS_OK) { solaris_scope_release(&entry->scope); close_entry(entry, rc); }
    }
}

static void lane_timeout(void *context, solaris_status_t status)
{
    lane_t *lane = context;
    association_t *entry = lane->association;
    lane->deadline = NULL;
    if (status == SOLARIS_OK && !entry->closing && !lane->ready) close_entry(entry, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&entry->scope);
}
static void lane_opened(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    lane_t *lane = context;
    association_t *entry = lane->association;
    assert(channel == lane->channel);
    if (lane->deadline != NULL) solaris_deadline_cancel(lane->deadline);
    if (entry->closing) return;
    if (close_requested(entry)) { close_entry(entry, SOLARIS_ECANCELLED); return; }
    if (status == SOLARIS_OK && solaris_executor_now_ns(entry->owner) >= lane->due) status = SOLARIS_ETIMEDOUT;
    if (status != SOLARIS_OK) { close_entry(entry, status); return; }
    lane->ready = 1;
    entry->active = 1;
    uv_mutex_lock(&entry->dispatcher->mutex);
    entry->stats.active_lanes++;
    uv_mutex_unlock(&entry->dispatcher->mutex);
    solaris_address_t local;
    if ((entry->capabilities & SOLARIS_OUTBOUND_DATAGRAM_MULTI) && solaris_datagram_local_address(channel, &local) == SOLARIS_OK) {
        uv_mutex_lock(&entry->dispatcher->mutex);
        if (local.family == SOLARIS_ADDRESS_IPV4) entry->stats.ipv4_local_port = local.port;
        if (local.family == SOLARIS_ADDRESS_IPV6) entry->stats.ipv6_local_port = local.port;
        uv_mutex_unlock(&entry->dispatcher->mutex);
    }
    touch(entry);
    schedule(entry);
}
static void lane_packet(void *context, solaris_datagram_t *channel,
                          const solaris_address_t *peer, const solaris_buffer_t *payload)
{
    lane_t *lane = context;
    association_t *entry = lane->association;
    assert(channel == lane->channel);
    if (entry->closing || close_requested(entry)) return;
    solaris_address_t canonical;
    if (normalize_address(peer, &canonical, 0) != SOLARIS_OK) return;
    solaris_status_t rc = entry->reply.send(entry->reply.context, entry->reply.generation, &entry->key, &canonical, payload);
    uv_mutex_lock(&entry->dispatcher->mutex);
    if (rc == SOLARIS_OK) entry->stats.received++;
    else entry->stats.reply_dropped++;
    uv_mutex_unlock(&entry->dispatcher->mutex);
    if (rc == SOLARIS_OK && !entry->closing) touch(entry);
}
static void lane_writable(void *context, solaris_datagram_t *channel)
{
    lane_t *lane = context;
    assert(channel == lane->channel);
    if (!lane->association->closing) schedule(lane->association);
}
static void lane_closed(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    lane_t *lane = context;
    association_t *entry = lane->association;
    assert(channel == lane->channel);
    if (lane->ready) {
        uv_mutex_lock(&entry->dispatcher->mutex);
        entry->stats.active_lanes--;
        uv_mutex_unlock(&entry->dispatcher->mutex);
    }
    lane->channel = NULL; lane->ready = 0;
    if (!entry->closing) close_entry(entry, status == SOLARIS_OK ? SOLARIS_ECLOSED : status);
    solaris_scope_release(&entry->scope);
}
static const solaris_datagram_callbacks_t lane_callbacks = {lane_opened, lane_packet, lane_writable, lane_closed};

static solaris_status_t ensure_lane(association_t *entry, mapping_t *mapping, lane_t **out)
{
    uint32_t family = mapping->actual.family;
    size_t index = family == SOLARIS_ADDRESS_IPV4 ? 0u : family == SOLARIS_ADDRESS_IPV6 ? 1u : 2u;
    lane_t *lane = (entry->capabilities & SOLARIS_OUTBOUND_DATAGRAM_MULTI) ? &entry->lanes[index] : &mapping->lane;
    *out = lane;
    if (lane->channel != NULL) return SOLARIS_OK;
    lane->association = entry; lane->family = family;
    solaris_status_t rc = due_after(entry, entry->dispatcher->options.open_timeout_ms, &lane->due);
    if (rc != SOLARIS_OK) return rc;
    solaris_scope_retain(&entry->scope);
    rc = solaris_deadline_start(entry->owner, entry->dispatcher->options.open_timeout_ms,
                                 lane_timeout, lane, &lane->deadline);
    if (rc != SOLARIS_OK) { solaris_scope_release(&entry->scope); return rc; }
    solaris_scope_retain(&entry->scope);
    rc = solaris_outbound_open_datagram(entry->plan.outbound, family, &lane_callbacks, lane, &lane->channel);
    if (rc != SOLARIS_OK) solaris_scope_release(&entry->scope);
    return rc;
}

static void resolved(void *context, solaris_status_t status, const solaris_address_t *addresses, size_t count)
{
    mapping_t *mapping = context;
    association_t *entry = mapping->association;
    mapping->request = NULL;
    if (!entry->closing) {
        if (status == SOLARIS_OK && solaris_executor_now_ns(entry->owner) >= mapping->due) status = SOLARIS_ETIMEDOUT;
        if (status == SOLARIS_OK) {
            /* Prefer IPv4 for the minimal system-resolver path, with IPv6
             * fallback. DNS policy and configurable racing are later layers. */
            size_t selected = count;
            for (size_t i = 0; i < count; ++i) {
                if (addresses[i].family == SOLARIS_ADDRESS_IPV4) { selected = i; break; }
                if (addresses[i].family == SOLARIS_ADDRESS_IPV6 && selected == count) selected = i;
            }
            if (selected == count) status = SOLARIS_EIO;
            else {
                status = normalize_address(&addresses[selected], &mapping->actual, 1);
                mapping->actual.port = mapping->original.port;
            }
        }
        mapping->status = status; mapping->resolved = 1;
        uv_mutex_lock(&entry->dispatcher->mutex);
        mapping->failed_through = entry->stats.accepted;
        uv_mutex_unlock(&entry->dispatcher->mutex);
        schedule(entry);
    }
    solaris_scope_release(&entry->scope);
}
static solaris_status_t get_mapping(association_t *entry, const packet_t *packet, mapping_t **out)
{
    mapping_t *mapping = entry->mappings;
    while (mapping != NULL && !solaris_address_equal(&mapping->original, &packet->target)) mapping = mapping->next;
    if (mapping == NULL) {
        if (entry->mapping_count == entry->dispatcher->options.mapping_limit) return SOLARIS_EAGAIN;
        mapping = solaris_memory_allocate(entry->dispatcher->options.budget, sizeof(*mapping));
        if (mapping == NULL) return SOLARIS_ENOMEM;
        memset(mapping, 0, sizeof(*mapping));
        mapping->association = entry; mapping->original = packet->target;
        mapping->next = entry->mappings; entry->mappings = mapping; entry->mapping_count++;
        uv_mutex_lock(&entry->dispatcher->mutex);
        entry->stats.mappings = entry->mapping_count;
        uv_mutex_unlock(&entry->dispatcher->mutex);
        if (packet->target.family != SOLARIS_ADDRESS_DOMAIN || (entry->capabilities & SOLARIS_OUTBOUND_DATAGRAM_DOMAIN)) {
            mapping->actual = packet->target; mapping->resolved = 1;
        }
    }
    *out = mapping;
    if (mapping->resolved && mapping->status != SOLARIS_OK && packet->sequence > mapping->failed_through)
        mapping->resolved = 0; /* newly admitted packets may retry a failed DNS lookup */
    if (!mapping->resolved && mapping->request == NULL) {
        solaris_status_t rc = due_after(entry, entry->dispatcher->options.dns_timeout_ms, &mapping->due);
        if (rc == SOLARIS_OK) {
            solaris_scope_retain(&entry->scope);
            rc = entry->dispatcher->options.resolve(entry->dispatcher->options.context, entry->owner,
                    &mapping->original, entry->dispatcher->options.dns_timeout_ms, resolved, mapping, &mapping->request);
            if (rc != SOLARIS_OK) solaris_scope_release(&entry->scope);
        }
        if (rc != SOLARIS_OK) {
            mapping->status = rc; mapping->resolved = 1;
            uv_mutex_lock(&entry->dispatcher->mutex);
            mapping->failed_through = entry->stats.accepted;
            uv_mutex_unlock(&entry->dispatcher->mutex);
        }
    }
    return SOLARIS_OK;
}

static solaris_status_t initialize_entry(association_t *entry, const solaris_address_t *target)
{
    solaris_status_t rc = solaris_scope_init(&entry->scope, entry->owner, cancel_entry, destroy_entry, entry);
    if (rc != SOLARIS_OK) return rc;
    entry->initialized = 1; entry->scheduler_lease = 1;
    solaris_scope_retain(&entry->scope);
    rc = entry->dispatcher->options.select(entry->dispatcher->options.context, entry->owner,
                                            &entry->key, target, &entry->plan);
    if (rc != SOLARIS_OK) return rc;
    if (entry->plan.outbound == NULL || entry->plan.outbound->owner != entry->owner || entry->plan.release == NULL)
        return SOLARIS_EINVAL;
    rc = solaris_outbound_capabilities(entry->plan.outbound, &entry->capabilities);
    if (rc != SOLARIS_OK) return rc;
    uv_mutex_lock(&entry->dispatcher->mutex);
    entry->stats.mapping_mode = (entry->capabilities & SOLARIS_OUTBOUND_DATAGRAM_MULTI) ?
        SOLARIS_UDP_ASSOCIATION_LANES : SOLARIS_UDP_DESTINATION_LANES;
    uv_mutex_unlock(&entry->dispatcher->mutex);
    return (entry->capabilities & SOLARIS_OUTBOUND_DATAGRAM) ? SOLARIS_OK : SOLARIS_ENOTSUP;
}
static packet_t *queue_head(association_t *entry, int remove)
{
    uv_mutex_lock(&entry->dispatcher->mutex);
    packet_t *packet = entry->head;
    if (remove && packet != NULL) {
        entry->head = packet->next;
        if (entry->head == NULL) entry->tail = NULL;
    }
    uv_mutex_unlock(&entry->dispatcher->mutex);
    return packet;
}
static void pump(void *context)
{
    association_t *entry = context;
    assert(solaris_executor_is_owner(entry->owner));
    if (close_requested(entry) || !solaris_executor_accepting(entry->owner)) close_entry(entry, SOLARIS_ECANCELLED);
    packet_t *first = queue_head(entry, 0);
    if (!entry->closing && !entry->initialized && first != NULL) {
        solaris_status_t rc = initialize_entry(entry, &first->target);
        if (rc != SOLARIS_OK) close_entry(entry, rc);
    }
    int blocked = 0;
    for (size_t i = 0; i < PUMP_BUDGET; ++i) {
        packet_t *packet = queue_head(entry, 0);
        if (packet == NULL) break;
        if (close_requested(entry)) close_entry(entry, SOLARIS_ECANCELLED);
        if (entry->closing) { (void)queue_head(entry, 1); finish_packet(packet, entry->status); continue; }
        mapping_t *mapping = NULL;
        solaris_status_t rc = get_mapping(entry, packet, &mapping);
        if (rc == SOLARIS_OK && !mapping->resolved) { blocked = 1; break; }
        if (rc == SOLARIS_OK) rc = mapping->status;
        if (rc != SOLARIS_OK) {
            (void)queue_head(entry, 1); finish_packet(packet, rc);
            /* A failed initial lookup must not leave a dormant association
             * with neither a channel nor an idle/open timer. */
            if (!entry->active && queue_head(entry, 0) == NULL) close_entry(entry, rc);
            continue;
        }
        lane_t *lane;
        rc = ensure_lane(entry, mapping, &lane);
        if (rc != SOLARIS_OK) { close_entry(entry, rc); continue; }
        if (!lane->ready) { blocked = 1; break; }
        rc = solaris_datagram_send(lane->channel, &mapping->actual, &packet->payload, sent, packet);
        if (rc == SOLARIS_EAGAIN) { blocked = 1; break; }
        (void)queue_head(entry, 1);
        if (rc != SOLARIS_OK) {
            finish_packet(packet, rc);
            if (rc == SOLARIS_ECLOSED) close_entry(entry, rc);
        }
    }
    uv_mutex_lock(&entry->dispatcher->mutex);
    entry->scheduled = 0;
    int again = (entry->head != NULL && (!blocked || entry->closing)) || (entry->close_requested && !entry->closing);
    if (again) {
        solaris_status_t rc = schedule_locked(entry);
        assert(rc == SOLARIS_OK); (void)rc;
    }
    int finished = entry->closing && !entry->scheduled;
    uv_mutex_unlock(&entry->dispatcher->mutex);
    if (finished) {
        if (!entry->initialized) destroy_entry(entry);
        else if (entry->scheduler_lease) { entry->scheduler_lease = 0; solaris_scope_release(&entry->scope); }
    }
}

static void initial_pump(void *context, solaris_status_t status)
{
    association_t *entry = context;
    if (status != SOLARIS_OK) close_entry(entry, status);
    pump(entry);
}
static int valid_workers(solaris_executor_t *const *workers, size_t count, void *engine_context)
{
    if (workers == NULL || count == 0u || count > WORKER_LIMIT) return 0;
    for (size_t i = 0; i < count; ++i) {
        if (workers[i] == NULL || solaris_executor_context(workers[i]) != engine_context) return 0;
        for (size_t j = 0; j < i; ++j) if (workers[i] == workers[j]) return 0;
    }
    return 1;
}
solaris_status_t solaris_udp_dispatcher_create(const solaris_udp_dispatcher_options_t *options,
                                                solaris_udp_dispatcher_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (options == NULL || options->budget == NULL || options->select == NULL || options->workers == NULL ||
        options->worker_count == 0u || options->workers[0] == NULL ||
        ((options->resolve == NULL) != (options->cancel_resolve == NULL))) return SOLARIS_EINVAL;
    void *engine_context = solaris_executor_context(options->workers[0]);
    if (!valid_workers(options->workers, options->worker_count, engine_context)) return SOLARIS_EINVAL;
    solaris_udp_dispatcher_options_t normalized = *options;
    if (normalized.association_limit == 0u) normalized.association_limit = 1024u;
    if (normalized.mapping_limit == 0u) normalized.mapping_limit = 32u;
    if (normalized.pending_packet_limit == 0u) normalized.pending_packet_limit = 64u;
    if (normalized.pending_byte_limit == 0u) normalized.pending_byte_limit = 256u * 1024u;
    if (normalized.idle_timeout_ms == 0u) normalized.idle_timeout_ms = 300000u;
    if (normalized.open_timeout_ms == 0u) normalized.open_timeout_ms = 10000u;
    if (normalized.dns_timeout_ms == 0u) normalized.dns_timeout_ms = 5000u;
    if (normalized.association_limit > 4096u || normalized.mapping_limit > 128u ||
        normalized.pending_packet_limit > 4096u || normalized.pending_byte_limit > UINT32_MAX ||
        normalized.idle_timeout_ms > UINT64_MAX / UINT64_C(1000000) ||
        normalized.open_timeout_ms > UINT64_MAX / UINT64_C(1000000) ||
        normalized.dns_timeout_ms > UINT64_MAX / UINT64_C(1000000)) return SOLARIS_EINVAL;
    if (normalized.resolve == NULL) { normalized.resolve = system_resolve; normalized.cancel_resolve = system_cancel_resolve; }
    solaris_udp_dispatcher_t *dispatcher = solaris_memory_allocate(options->budget, sizeof(*dispatcher));
    if (dispatcher == NULL) return SOLARIS_ENOMEM;
    memset(dispatcher, 0, sizeof(*dispatcher));
    if (uv_mutex_init(&dispatcher->mutex) != 0) { solaris_memory_free(dispatcher); return SOLARIS_EIO; }
    dispatcher->options = normalized; dispatcher->engine_context = engine_context;
    memcpy(dispatcher->workers, options->workers, options->worker_count * sizeof(*options->workers));
    dispatcher->options.workers = dispatcher->workers;
    *out = dispatcher;
    return SOLARIS_OK;
}
solaris_status_t solaris_udp_dispatcher_set_workers(solaris_udp_dispatcher_t *dispatcher,
                                                     solaris_executor_t *const *workers, size_t count)
{
    if (dispatcher == NULL || !valid_workers(workers, count, dispatcher->engine_context)) return SOLARIS_EINVAL;
    uv_mutex_lock(&dispatcher->mutex);
    solaris_status_t rc = SOLARIS_OK;
    if (dispatcher->closed) rc = SOLARIS_ECLOSED;
    else {
        memcpy(dispatcher->workers, workers, count * sizeof(*workers));
        dispatcher->options.worker_count = count;
    }
    uv_mutex_unlock(&dispatcher->mutex);
    return rc;
}
static int same_reply(const solaris_udp_reply_endpoint_t *a, const solaris_udp_reply_endpoint_t *b)
{
    return a->context == b->context && a->generation == b->generation && a->send == b->send &&
           a->retain == b->retain && a->release == b->release;
}
solaris_status_t solaris_udp_submit(solaris_udp_dispatcher_t *dispatcher, const solaris_udp_key_t *key,
                                    const solaris_address_t *target, const solaris_slice_t *payload,
                                    const solaris_udp_reply_endpoint_t *reply,
                                    solaris_io_done_fn done, void *context, uint64_t *association_id)
{
    if (association_id != NULL) *association_id = 0u;
    solaris_udp_key_t normalized_key;
    solaris_address_t normalized_target;
    if (dispatcher == NULL || !solaris_slice_valid(payload) || done == NULL || reply == NULL ||
        reply->send == NULL || reply->retain == NULL || reply->release == NULL ||
        normalize_key(key, &normalized_key) != SOLARIS_OK || normalize_address(target, &normalized_target, 0) != SOLARIS_OK ||
        normalized_target.port == 0u) return SOLARIS_EINVAL;
    if (payload->length > 65527u) return SOLARIS_EMSGSIZE;
    reply->retain(reply->context);
    int transfer_reply = 0, new_entry = 0;
    packet_t *packet = NULL;
    association_t *entry = NULL;
    solaris_status_t rc = SOLARIS_OK;
    uv_mutex_lock(&dispatcher->mutex);
    if (dispatcher->closed) { rc = SOLARIS_ECLOSED; goto done; }
    entry = find_entry(dispatcher, &normalized_key);
    if (entry != NULL && entry->close_requested) { rc = SOLARIS_ECLOSED; goto done; }
    if (entry != NULL && !same_reply(&entry->reply, reply)) { rc = SOLARIS_EBUSY; goto done; }
    solaris_executor_t *owner = entry == NULL ? dispatcher->workers[key_hash(&normalized_key) % dispatcher->options.worker_count] : entry->owner;
    if (!solaris_executor_accepting(owner)) { rc = SOLARIS_ECLOSED; goto done; }
    if (payload->length > dispatcher->options.pending_byte_limit ||
        (entry != NULL && (entry->stats.pending_packets >= dispatcher->options.pending_packet_limit ||
         entry->stats.pending_bytes > dispatcher->options.pending_byte_limit - payload->length))) {
        if (entry != NULL) entry->stats.queue_rejections++;
        rc = SOLARIS_EAGAIN; goto done;
    }
    if (entry == NULL) {
        if (dispatcher->references == dispatcher->options.association_limit) { rc = SOLARIS_EAGAIN; goto done; }
        if (dispatcher->next_id == UINT64_MAX) { rc = SOLARIS_EOVERFLOW; goto done; }
        entry = solaris_memory_allocate(dispatcher->options.budget, sizeof(*entry));
        if (entry == NULL) { rc = SOLARIS_ENOMEM; goto done; }
        memset(entry, 0, sizeof(*entry)); new_entry = 1;
        entry->dispatcher = dispatcher; entry->owner = owner; entry->key = normalized_key;
        entry->reply = *reply;
        entry->pump.run = pump; entry->pump.context = entry;
        entry->stats.id = ++dispatcher->next_id; entry->stats.worker_id = solaris_executor_id(owner);
    }
    if (entry->stats.accepted == UINT64_MAX) { rc = SOLARIS_EOVERFLOW; goto done; }
    packet = solaris_memory_allocate(dispatcher->options.budget, sizeof(*packet));
    if (packet == NULL) { rc = SOLARIS_ENOMEM; goto done; }
    memset(packet, 0, sizeof(*packet)); packet->association = entry;
    packet->target = normalized_target; packet->payload = *payload; packet->done = done; packet->context = context;
    /* The first callback uses ordinary admission, so a concurrent engine stop
     * cannot publish its barrier before this not-yet-scoped entry is drained. */
    if (new_entry) {
        entry->scheduled = 1;
        rc = solaris_executor_post(owner, initial_pump, entry);
        if (rc != SOLARIS_OK) goto done;
        entry->next = dispatcher->entries; dispatcher->entries = entry;
        dispatcher->entries_count++; dispatcher->references++;
        transfer_reply = 1;
    } else {
        rc = schedule_locked(entry);
        if (rc != SOLARIS_OK) goto done;
    }
    solaris_buffer_retain(payload->buffer);
    packet->sequence = ++entry->stats.accepted;
    entry->stats.pending_packets++; entry->stats.pending_bytes += payload->length;
    if (entry->tail != NULL) entry->tail->next = packet;
    else entry->head = packet;
    entry->tail = packet;
    if (association_id != NULL) *association_id = entry->stats.id;
done:
    uv_mutex_unlock(&dispatcher->mutex);
    if (rc != SOLARIS_OK) { solaris_memory_free(packet); if (new_entry) solaris_memory_free(entry); }
    if (!transfer_reply) reply->release(reply->context);
    return rc;
}
solaris_status_t solaris_udp_submit_batch(solaris_udp_dispatcher_t *dispatcher, const solaris_udp_key_t *key,
                                          const solaris_datagram_message_t *messages, size_t count,
                                          const solaris_udp_reply_endpoint_t *reply, size_t *accepted)
{
    if (accepted == NULL) return SOLARIS_EINVAL;
    *accepted = 0u;
    solaris_udp_key_t normalized;
    if (dispatcher == NULL || normalize_key(key, &normalized) != SOLARIS_OK || reply == NULL ||
        reply->retain == NULL || reply->release == NULL || reply->send == NULL ||
        (messages == NULL && count != 0u)) return SOLARIS_EINVAL;
    for (size_t i = 0; i < count; ++i) {
        solaris_status_t rc = solaris_udp_submit(dispatcher, key, &messages[i].destination, &messages[i].data,
                                                  reply, messages[i].done, messages[i].context, NULL);
        if (rc != SOLARIS_OK) return rc;
        (*accepted)++;
    }
    return SOLARIS_OK;
}
solaris_status_t solaris_udp_association_snapshot(solaris_udp_dispatcher_t *dispatcher,
                                                  const solaris_udp_key_t *key, solaris_udp_snapshot_t *out)
{
    solaris_udp_key_t normalized;
    if (dispatcher == NULL || out == NULL || normalize_key(key, &normalized) != SOLARIS_OK) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    uv_mutex_lock(&dispatcher->mutex);
    association_t *entry = find_entry(dispatcher, &normalized);
    if (entry != NULL) *out = entry->stats;
    uv_mutex_unlock(&dispatcher->mutex);
    return entry == NULL ? SOLARIS_ECLOSED : SOLARIS_OK;
}
solaris_status_t solaris_udp_association_close(solaris_udp_dispatcher_t *dispatcher,
                                               const solaris_udp_key_t *key, uint64_t id)
{
    solaris_udp_key_t normalized;
    if (dispatcher == NULL || normalize_key(key, &normalized) != SOLARIS_OK) return SOLARIS_EINVAL;
    uv_mutex_lock(&dispatcher->mutex);
    association_t *entry = find_entry(dispatcher, &normalized);
    solaris_status_t rc = SOLARIS_ECLOSED;
    if (entry != NULL && entry->stats.id == id) {
        rc = SOLARIS_OK;
        if (!entry->close_requested) {
            entry->close_requested = 1; entry->stats.closing = 1u;
            rc = schedule_locked(entry);
        }
    }
    uv_mutex_unlock(&dispatcher->mutex);
    return rc;
}
solaris_status_t solaris_udp_dispatcher_close(solaris_udp_dispatcher_t *dispatcher)
{
    if (dispatcher == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&dispatcher->mutex);
    dispatcher->closed = 1;
    solaris_status_t result = SOLARIS_OK;
    for (association_t *entry = dispatcher->entries; entry != NULL; entry = entry->next) {
        if (!entry->close_requested) {
            entry->close_requested = 1; entry->stats.closing = 1u;
            solaris_status_t rc = schedule_locked(entry);
            if (rc != SOLARIS_OK) result = rc;
        }
    }
    uv_mutex_unlock(&dispatcher->mutex);
    return result;
}
solaris_status_t solaris_udp_dispatcher_destroy(solaris_udp_dispatcher_t *dispatcher)
{
    if (dispatcher == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&dispatcher->mutex);
    if (dispatcher->references != 0u) { uv_mutex_unlock(&dispatcher->mutex); return SOLARIS_EBUSY; }
    dispatcher->closed = 1;
    uv_mutex_unlock(&dispatcher->mutex);
    uv_mutex_destroy(&dispatcher->mutex);
    solaris_memory_free(dispatcher);
    return SOLARIS_OK;
}
