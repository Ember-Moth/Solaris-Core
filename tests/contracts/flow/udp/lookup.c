#include "contracts/flow/udp.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { NORMAL, HOLD, SOFT_FAIL, TERMINAL_ASYNC, TERMINAL_REJECT, BAD_COUNT, BAD_NULL, BAD_ADDRESS, BAD_ZERO, LEGACY };
typedef struct fixture fixture_t;
typedef struct captured {
    fixture_t *fixture;
    uint64_t revision;
    unsigned references, acquires, plans, lookups, cancels, pending;
} captured_t;
typedef struct resolution {
    solaris_deferred_t completion;
    captured_t *captured;
    solaris_resolve_fn callback;
    void *context;
    solaris_status_t status;
    int cancelled;
} resolution_t;
typedef struct channel {
    solaris_datagram_t datagram;
    solaris_datagram_callbacks_t callbacks;
    void *context;
    fixture_t *fixture;
    solaris_deferred_t opened, written, closed;
    solaris_io_done_fn done;
    void *user;
    const solaris_buffer_t *buffer;
    int closing, writing;
} channel_t;
struct fixture {
    solaris_budget_t *budget;
    solaris_executor_t *owner;
    solaris_outbound_t outbound;
    solaris_udp_dispatcher_t *dispatcher;
    solaris_udp_key_t key;
    solaris_udp_reply_endpoint_t reply;
    captured_t old, current;
    captured_t *admission;
    resolution_t *held;
    channel_t channels[8];
    solaris_address_t target, destinations[32];
    solaris_status_t statuses[32], terminal, final_status;
    unsigned mode, sends, opens, live_channels, legacy_calls, legacy_cancels, closes;
    atomic_uint reply_refs;
    solaris_test_event_t sent, closed, fence, resolving, cancelled;
    solaris_status_t submit_status;
    int malformed_route;
};
static void schedule(fixture_t *f, solaris_deferred_t *node, void (*run)(void *), void *context)
{ *node = (solaris_deferred_t){.run = run, .context = context}; CHECK(solaris_executor_defer(f->owner, node) == SOLARIS_OK); }
static void opened(void *context)
{ channel_t *c = context; c->callbacks.on_open(c->context, &c->datagram, c->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); }
static void written(void *context)
{
    channel_t *c = context; const solaris_buffer_t *buffer = c->buffer; c->buffer = NULL; c->writing = 0;
    c->done(c->user, c->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); solaris_buffer_release(buffer);
}
static void channel_closed(void *context)
{ channel_t *c = context; CHECK(!c->writing); c->fixture->live_channels--; c->callbacks.on_close(c->context, &c->datagram, SOLARIS_ECANCELLED); }
static solaris_status_t send_packet(void *context, const solaris_address_t *target, const solaris_slice_t *payload, solaris_io_done_fn done, void *user)
{
    channel_t *c = context;
    if (c->closing) return SOLARIS_ECLOSED;
    if (c->writing) return SOLARIS_EAGAIN;
    fixture_t *f = c->fixture; CHECK(f->sends < 32u); f->destinations[f->sends] = *target;
    c->done = done; c->user = user; c->buffer = payload->buffer; solaris_buffer_retain(c->buffer); c->writing = 1;
    schedule(f, &c->written, written, c); return SOLARIS_OK;
}
static solaris_status_t reading(void *context, int enabled) { (void)context; (void)enabled; return SOLARIS_OK; }
static solaris_status_t close_channel(void *context)
{
    channel_t *c = context; if (!c->closing) { c->closing = 1; schedule(c->fixture, &c->closed, channel_closed, c); } return SOLARIS_OK;
}
static solaris_status_t snapshot(void *context, solaris_io_snapshot_t *out)
{ (void)context; memset(out, 0, sizeof(*out)); out->max_message_bytes = 65507u; return SOLARIS_OK; }
static solaris_status_t local(void *context, solaris_address_t *out)
{ (void)context; return solaris_address_parse("127.0.0.1", 50000u, out); }
static const solaris_datagram_ops_t datagram_ops = {send_packet, reading, close_channel, snapshot, local};
static uint32_t capabilities(void *context)
{ (void)context; return SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_LOCAL_RESOLUTION; }
static solaris_status_t open_stream(void *context, const solaris_address_t *target, const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{ (void)context; (void)target; (void)callbacks; (void)user; (void)out; return SOLARIS_ENOTSUP; }
static solaris_status_t open_datagram(void *context, uint32_t family, const solaris_datagram_callbacks_t *callbacks, void *user, solaris_datagram_t **out)
{
    fixture_t *f = context; CHECK((family == 4u || family == 6u) && f->opens < 8u);
    channel_t *c = &f->channels[f->opens++]; c->fixture = f; c->callbacks = *callbacks; c->context = user;
    c->datagram = (solaris_datagram_t){&datagram_ops, c, f->owner}; f->live_channels++;
    *out = &c->datagram; schedule(f, &c->opened, opened, c); return SOLARIS_OK;
}
static void retire(void *context) { (void)context; }
static const solaris_outbound_ops_t outbound_ops = {capabilities, open_stream, open_datagram, retire};
static void release_plan(void *context)
{ captured_t *c = context; CHECK(c->plans && !c->pending); c->plans--; }
static void retain_context(void *context) { captured_t *c = context; CHECK(solaris_executor_is_owner(c->fixture->owner)); c->references++; }
static void release_context(void *context)
{ captured_t *c = context; CHECK(c->references && solaris_executor_is_owner(c->fixture->owner)); if (--c->references == 0) CHECK(!c->pending); }
static solaris_status_t acquire(void *context, solaris_executor_t *owner, uint64_t target, solaris_dial_plan_t *plan, uint32_t *caps)
{
    captured_t *c = context; CHECK(owner == c->fixture->owner && target == 99u);
    c->acquires++; c->plans++; *caps = capabilities(NULL);
    *plan = (solaris_dial_plan_t){.outbound = &c->fixture->outbound, .context = c, .release = release_plan, .node_id = c->revision}; return SOLARIS_OK;
}
static solaris_status_t select_plan(void *context, solaris_executor_t *owner, const solaris_udp_key_t *key, const solaris_address_t *target, solaris_udp_plan_t *out)
{ fixture_t *f = context; (void)key; (void)target; uint32_t caps; return acquire(f->admission, owner, 99u, out, &caps); }
static void deliver_resolution(void *context)
{
    resolution_t *r = context; captured_t *c = r->captured; fixture_t *f = c->fixture;
    solaris_address_t addresses[2]; CHECK(solaris_address_parse("::1", 1u, &addresses[0]) == SOLARIS_OK);
    addresses[0].ip[15] = (uint8_t)c->revision;
    CHECK(solaris_address_parse("127.0.0.1", 1u, &addresses[1]) == SOLARIS_OK); addresses[1].ip[3] = (uint8_t)c->revision;
    if (f->mode == BAD_ADDRESS) addresses[1].family = SOLARIS_ADDRESS_DOMAIN;
    c->pending--; if (f->held == r) f->held = NULL;
    r->callback(r->context, r->status, f->mode == BAD_NULL ? NULL : addresses,
        f->mode == BAD_COUNT ? SOLARIS_RESOLVER_MAX_ADDRESSES + 1u : f->mode == BAD_ZERO ? 0u : 2u);
    solaris_memory_free(r);
}
static solaris_status_t lookup(void *context, solaris_executor_t *owner, const solaris_dns_lookup_view_t *view,
    const solaris_address_t *target, uint64_t deadline, solaris_resolve_fn callback, void *user, void **out)
{
    captured_t *c = context; fixture_t *f = c->fixture; *out = NULL;
    CHECK(owner == f->owner && c->references && target->family == SOLARIS_ADDRESS_DOMAIN);
    CHECK(view->role == SOLARIS_DNS_DIRECT_TARGET && view->config_revision == c->revision && view->resolver_revision == c->revision + 100u &&
        view->network_revision == 3u && view->selection_revision == c->revision + 200u);
    uint64_t now = solaris_executor_now_ns(owner); CHECK(deadline > now && deadline - now <= UINT64_C(50000000));
    c->lookups++;
    if (f->mode == TERMINAL_REJECT) return f->terminal;
    resolution_t *r = solaris_memory_allocate(f->budget, sizeof(*r)); CHECK(r); memset(r, 0, sizeof(*r));
    r->captured = c; r->callback = callback; r->context = user;
    r->status = f->mode == TERMINAL_ASYNC ? f->terminal : f->mode == SOFT_FAIL && c->lookups == 1u ? SOLARIS_EIO : SOLARIS_OK;
    c->pending++; *out = r;
    if (f->mode == HOLD) { f->held = r; solaris_test_event_signal(&f->resolving); }
    else schedule(f, &r->completion, deliver_resolution, r);
    return SOLARIS_OK;
}
static void cancel_lookup(void *context, void *request)
{
    captured_t *c = context; resolution_t *r = request; CHECK(r->captured == c && c->references && !r->cancelled);
    r->cancelled = 1; c->cancels++; solaris_test_event_signal(&c->fixture->cancelled);
}
static solaris_status_t legacy_resolve(void *context, solaris_executor_t *owner, const solaris_address_t *target,
    uint64_t timeout, solaris_resolve_fn callback, void *user, void **out)
{
    fixture_t *f = context; f->legacy_calls++;
    if (f->mode != LEGACY) {
        fprintf(stderr, "post-reload mapping used dispatcher view %llu instead of captured view %llu\n",
            (unsigned long long)f->admission->revision, (unsigned long long)f->old.revision);
        CHECK(f->mode == LEGACY);
    }
    CHECK(owner == f->owner && timeout == 50u && target->family == SOLARIS_ADDRESS_DOMAIN);
    resolution_t *r = solaris_memory_allocate(f->budget, sizeof(*r)); CHECK(r); memset(r, 0, sizeof(*r));
    r->captured = f->admission; r->callback = callback; r->context = user; r->captured->pending++; *out = r;
    schedule(f, &r->completion, deliver_resolution, r); return SOLARIS_OK;
}
static void legacy_cancel(void *context, void *request) { fixture_t *f = context; f->legacy_cancels++; cancel_lookup(f->admission, request); }
static void reply_retain(void *context) { atomic_fetch_add(&((fixture_t *)context)->reply_refs, 1u); }
static void reply_release(void *context) { CHECK(atomic_fetch_sub(&((fixture_t *)context)->reply_refs, 1u) > 1u); }
static solaris_status_t reply(void *context, uint64_t generation, const solaris_udp_key_t *key,
    const solaris_address_t *peer, const solaris_buffer_t *buffer)
{ (void)context; (void)generation; (void)key; (void)peer; (void)buffer; return SOLARIS_OK; }
static void sent(void *context, solaris_status_t status)
{ fixture_t *f = context; CHECK(f->sends < 32u); f->statuses[f->sends++] = status; solaris_test_event_signal(&f->sent); }
static void closed(void *context, const solaris_udp_key_t *key, const solaris_udp_snapshot_t *snapshot, solaris_status_t status)
{
    fixture_t *f = context; (void)key; CHECK(!snapshot->pending_packets && !f->live_channels);
    f->closes++; f->final_status = status; solaris_test_event_signal(&f->closed);
}
static void fence_task(void *context, solaris_status_t status) { CHECK(status == SOLARIS_OK); solaris_test_event_signal(&((fixture_t *)context)->fence); }
static void fence(fixture_t *f) { CHECK(solaris_executor_post(f->owner, fence_task, f) == SOLARIS_OK); solaris_test_event_wait(&f->fence); }
static void submit_task(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == SOLARIS_OK); captured_t *c = f->admission;
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(f->budget, "x", 1u, &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 1u};
    solaris_route_options_t route = {.owner = f->owner, .mode = SOLARIS_MODE_DIRECT, .direct_target = 99u, .timeout_ms = 1000u,
        .context = c, .retain = retain_context, .release = release_context, .acquire = acquire,
        .dial_lookup = {c, lookup, cancel_lookup},
        .dial_lookup_view = {SOLARIS_DNS_PROXY_SERVER, c->revision, c->revision + 100u, 3u, c->revision + 200u}};
    route.metadata.config_revision = c->revision; route.metadata.selection_revision = c->revision + 200u;
    if (f->malformed_route == 1) route.dial_lookup.cancel = NULL;
    if (f->malformed_route == 2) route.retain = route.release = NULL;
    if (f->malformed_route == 3) route.dial_lookup.start = NULL;
    f->submit_status = f->mode == LEGACY ? solaris_udp_submit(f->dispatcher, &f->key, &f->target, &slice, &f->reply, sent, f, NULL) :
        solaris_udp_submit_routed(f->dispatcher, &f->key, &f->target, &slice, &f->reply, sent, f, NULL, &route);
    solaris_buffer_release(buffer); solaris_test_event_signal(&f->fence);
}
static void submit(fixture_t *f, const char *name)
{
    CHECK(solaris_address_parse(name, 1234u, &f->target) == SOLARIS_OK);
    CHECK(solaris_executor_post(f->owner, submit_task, f) == SOLARIS_OK); solaris_test_event_wait(&f->fence);
    CHECK(f->submit_status == SOLARIS_OK);
}
static void init(fixture_t *f, unsigned mode)
{
    memset(f, 0, sizeof(*f)); f->mode = mode; atomic_init(&f->reply_refs, 1u);
    CHECK(solaris_budget_create(8u * 1024u * 1024u, NULL, &f->budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.id = 0, .owner_context = f, .queue_capacity = 64u, .resource_limit = 128u, .budget = f->budget};
    CHECK(solaris_executor_create(&options, &f->owner) == SOLARIS_OK && solaris_executor_activate(f->owner, 1u) == SOLARIS_OK);
    CHECK(!solaris_test_event_init(&f->sent, 0) && !solaris_test_event_init(&f->closed, 0) && !solaris_test_event_init(&f->fence, 0) &&
        !solaris_test_event_init(&f->resolving, 0) && !solaris_test_event_init(&f->cancelled, 0));
    f->old.fixture = f; f->old.revision = 7u; f->current.fixture = f; f->current.revision = 19u; f->admission = &f->old;
    f->outbound = (solaris_outbound_t){&outbound_ops, f, f->owner};
    f->key.inbound_id = 1u; f->key.inbound_generation = 1u; f->key.client_id = 1u;
    CHECK(solaris_address_parse("10.0.0.1", 4321u, &f->key.source) == SOLARIS_OK);
    f->reply = (solaris_udp_reply_endpoint_t){f, 1u, reply_retain, reply_release, reply};
    solaris_udp_dispatcher_options_t dispatcher = {.workers = &f->owner, .worker_count = 1u, .budget = f->budget,
        .association_limit = 4u, .mapping_limit = 8u, .pending_byte_limit = 65536u, .pending_packet_limit = 8u,
        .idle_timeout_ms = 10000u, .open_timeout_ms = 1000u, .dns_timeout_ms = 50u, .context = f,
        .select = select_plan, .on_close = closed, .resolve = legacy_resolve, .cancel_resolve = legacy_cancel};
    CHECK(solaris_udp_dispatcher_create(&dispatcher, &f->dispatcher) == SOLARIS_OK);
}
static void finish(fixture_t *f)
{
    CHECK(solaris_udp_dispatcher_close(f->dispatcher) == SOLARIS_OK);
    CHECK(solaris_executor_quiesce(f->owner) == SOLARIS_OK);
    CHECK(solaris_udp_dispatcher_destroy(f->dispatcher) == SOLARIS_OK);
    CHECK(!f->old.references && !f->current.references && !f->old.plans && !f->current.plans && atomic_load(&f->reply_refs) == 1u);
    CHECK(solaris_executor_destroy(f->owner) == SOLARIS_OK && !solaris_budget_used(f->budget)); solaris_budget_release(f->budget);
    solaris_test_event_destroy(&f->sent); solaris_test_event_destroy(&f->closed); solaris_test_event_destroy(&f->fence);
    solaris_test_event_destroy(&f->resolving); solaris_test_event_destroy(&f->cancelled);
}
static void captured_view(int first_domain)
{
    fixture_t f; init(&f, NORMAL);
    submit(&f, first_domain ? "a.test" : "127.0.0.1"); solaris_test_event_wait(&f.sent); fence(&f);
    CHECK(f.statuses[0] == SOLARIS_OK);
    f.admission = &f.current;
    submit(&f, "b.test"); solaris_test_event_wait(&f.sent); fence(&f);
    CHECK(f.statuses[1] == SOLARIS_OK && f.destinations[1].family == 6u && f.destinations[1].ip[15] == 7u);
    CHECK(f.old.references == 1u && f.old.plans == 1u && f.old.acquires == 1u && !f.current.references && !f.current.lookups);
    submit(&f, first_domain ? "a.test" : "127.0.0.1"); solaris_test_event_wait(&f.sent); fence(&f);
    CHECK(f.old.lookups == (first_domain ? 2u : 1u) && !f.legacy_calls);
    solaris_udp_snapshot_t snapshot;
    CHECK(solaris_udp_association_snapshot(f.dispatcher, &f.key, &snapshot) == SOLARIS_OK);
    CHECK(solaris_udp_association_close(f.dispatcher, &f.key, snapshot.id) == SOLARIS_OK); solaris_test_event_wait(&f.closed); fence(&f);
    CHECK(!f.old.references && !f.old.plans);
    f.key.client_id++;
    submit(&f, "c.test"); solaris_test_event_wait(&f.sent); fence(&f);
    CHECK(f.current.lookups == 1u && f.current.references == 1u && f.destinations[3].family == 6u && f.destinations[3].ip[15] == 19u);
    finish(&f);
}
static void submit_batch(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == SOLARIS_OK);
    for (unsigned i = 0; i < 3; i++) { submit_task(f, SOLARIS_OK); CHECK(f->submit_status == SOLARIS_OK); }
}
static void batch(fixture_t *f)
{
    CHECK(solaris_address_parse("b.test", 1234u, &f->target) == SOLARIS_OK);
    CHECK(solaris_executor_post(f->owner, submit_batch, f) == SOLARIS_OK);
    for (unsigned i = 0; i < 3; i++) solaris_test_event_wait(&f->fence);
}
static void terminal_case(solaris_status_t terminal, int reject)
{
    fixture_t f; init(&f, reject ? TERMINAL_REJECT : TERMINAL_ASYNC); f.terminal = terminal;
    submit(&f, "127.0.0.1"); solaris_test_event_wait(&f.sent); fence(&f); f.admission = &f.current;
    batch(&f);
    for (unsigned i = 0; i < 3; i++) solaris_test_event_wait(&f.sent);
    solaris_test_event_wait(&f.closed); fence(&f);
    CHECK(f.final_status == terminal && f.closes == 1u && f.old.lookups == 1u && f.old.acquires == 1u && !f.legacy_calls);
    CHECK(f.opens == 1u && !f.old.references && !f.old.plans);
    for (unsigned i = 1; i <= 3; i++) CHECK(f.statuses[i] == terminal);
    finish(&f);
}
static void soft_retry(void)
{
    fixture_t f; init(&f, SOFT_FAIL); submit(&f, "127.0.0.1"); solaris_test_event_wait(&f.sent); fence(&f);
    f.admission = &f.current; batch(&f);
    for (unsigned i = 0; i < 3; i++) solaris_test_event_wait(&f.sent);
    fence(&f); CHECK(!f.closes && f.old.lookups == 1u && f.old.references == 1u);
    for (unsigned i = 1; i <= 3; i++) CHECK(f.statuses[i] == SOLARIS_EIO);
    submit(&f, "b.test"); solaris_test_event_wait(&f.sent); fence(&f);
    CHECK(f.statuses[4] == SOLARIS_OK && f.old.lookups == 2u && !f.current.lookups && f.old.acquires == 1u);
    CHECK(f.destinations[4].family == 6u && f.destinations[4].ip[15] == 7u); finish(&f);
}
static void cancelled_lookup(void)
{
    fixture_t f; init(&f, HOLD); submit(&f, "127.0.0.1"); solaris_test_event_wait(&f.sent); fence(&f);
    f.admission = &f.current; submit(&f, "held.test"); solaris_test_event_wait(&f.resolving);
    solaris_udp_snapshot_t snapshot; CHECK(solaris_udp_association_snapshot(f.dispatcher, &f.key, &snapshot) == SOLARIS_OK);
    CHECK(solaris_udp_association_close(f.dispatcher, &f.key, snapshot.id) == SOLARIS_OK);
    solaris_test_event_wait(&f.cancelled); solaris_test_event_wait(&f.sent); fence(&f);
    CHECK(f.old.references == 1u && f.old.pending == 1u && f.old.cancels == 1u && !f.legacy_cancels && !f.closes);
    CHECK(solaris_udp_dispatcher_destroy(f.dispatcher) == SOLARIS_EBUSY);
    CHECK(solaris_executor_begin_quiesce(f.owner) == SOLARIS_OK && !solaris_executor_is_quiescent(f.owner));
    resolution_t *held = f.held; CHECK(held);
    /* Deliberately report late success after cancellation; it cannot open a
     * new lane, and the captured context remains pinned through this callback. */
    schedule(&f, &held->completion, deliver_resolution, held);
    solaris_test_event_wait(&f.closed); CHECK(solaris_executor_wait_quiescent(f.owner) == SOLARIS_OK);
    CHECK(f.opens == 1u && f.final_status == SOLARIS_ECANCELLED && f.statuses[1] == SOLARIS_ECANCELLED);
    CHECK(!f.old.references && !f.old.pending); finish(&f);
}
static void malformed_results(unsigned mode)
{
    fixture_t f; init(&f, mode); submit(&f, "127.0.0.1"); solaris_test_event_wait(&f.sent); fence(&f);
    submit(&f, "bad.test"); solaris_test_event_wait(&f.sent); fence(&f);
    CHECK(f.statuses[1] == (mode == BAD_COUNT ? SOLARIS_EOVERFLOW : mode == BAD_ZERO ? SOLARIS_EIO : SOLARIS_EINVAL));
    CHECK(f.opens == 1u && f.old.lookups == 1u && !f.closes && f.old.references == 1u); finish(&f);
}
static void rejected_hooks(void)
{
    fixture_t f; init(&f, NORMAL); CHECK(solaris_address_parse("bad.test", 1234u, &f.target) == SOLARIS_OK);
    for (int mode = 1; mode <= 3; mode++) {
        f.malformed_route = mode; CHECK(solaris_executor_post(f.owner, submit_task, &f) == SOLARIS_OK); solaris_test_event_wait(&f.fence); fence(&f);
        CHECK(f.submit_status == SOLARIS_EINVAL && !f.old.references && !f.old.acquires && !f.sends && atomic_load(&f.reply_refs) == 1u);
    }
    finish(&f);
}
static void legacy_order(void)
{
    fixture_t f; init(&f, LEGACY); submit(&f, "legacy.test"); solaris_test_event_wait(&f.sent); fence(&f);
    CHECK(f.statuses[0] == SOLARIS_OK && f.legacy_calls == 1u && f.destinations[0].family == 4u && f.destinations[0].ip[3] == 7u);
    finish(&f);
}
int main(void)
{
    captured_view(0); captured_view(1);
    const solaris_status_t terminal[] = {SOLARIS_ENETWORK_CHANGED, SOLARIS_EACCESS, SOLARIS_ECLOSED, SOLARIS_ECANCELLED};
    for (size_t i = 0; i < sizeof(terminal) / sizeof(*terminal); i++) { terminal_case(terminal[i], 0); terminal_case(terminal[i], 1); }
    soft_retry(); cancelled_lookup();
    malformed_results(BAD_COUNT); malformed_results(BAD_NULL); malformed_results(BAD_ADDRESS); malformed_results(BAD_ZERO);
    rejected_hooks(); legacy_order();
    puts("UDP captured DNS: 18 routing/view/cancellation contract groups passed"); return 0;
}
