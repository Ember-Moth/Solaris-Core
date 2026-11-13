#include "transport/socket/tcp.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { SUCCESS, DENIED, INVALID_COUNT, INVALID_FAMILY, CANCEL, NETWORK_CHANGE, REJECTED, STRICT_MISSING, NUMERIC };
typedef struct fixture {
    solaris_budget_t *budget;
    solaris_executor_t *owner;
    solaris_tcp_listener_t *listener;
    solaris_stream_t *stream;
    solaris_deferred_t response;
    solaris_resolve_fn callback;
    void *user;
    solaris_address_t answer;
    solaris_test_event_t done;
    solaris_status_t expected, submit;
    int mode, starting;
    unsigned lookups, cancels, opens, closes, policies;
} fixture_t;
static void response(void *context)
{
    fixture_t *f = context;
    CHECK(!f->starting && solaris_executor_is_owner(f->owner));
    solaris_status_t status = f->mode == NETWORK_CHANGE ? SOLARIS_ENETWORK_CHANGED : SOLARIS_OK;
    size_t count = f->mode == INVALID_COUNT ? SOLARIS_RESOLVER_MAX_ADDRESSES + 1 : 1;
    /* Cancellation deliberately returns the original success to prove that
     * no late resolver result can reopen a cancelled physical dial. */
    f->callback(f->user, status, &f->answer, count);
}
static solaris_status_t lookup(void *context, solaris_executor_t *owner,
    const solaris_dns_lookup_view_t *view, const solaris_address_t *target,
    uint64_t deadline, solaris_resolve_fn callback, void *user, void **request)
{
    fixture_t *f = context; *request = NULL;
    CHECK(f->starting && owner == f->owner && solaris_executor_is_owner(owner));
    CHECK(target->family == SOLARIS_ADDRESS_DOMAIN && !strcmp(target->host, "no-os-lookup.invalid"));
    CHECK(view->role == SOLARIS_DNS_PROXY_SERVER && view->config_revision == 3 &&
          view->resolver_revision == 4 && view->network_revision == 5 && view->selection_revision == 6);
    CHECK(deadline > solaris_executor_now_ns(owner));
    CHECK(deadline - solaris_executor_now_ns(owner) <= UINT64_C(1000000000));
    ++f->lookups;
    if (f->mode == REJECTED) return SOLARIS_EACCESS;
    f->callback = callback; f->user = user; *request = f;
    if (f->mode != CANCEL) CHECK(solaris_executor_defer(owner, &f->response) == SOLARIS_OK);
    return SOLARIS_OK;
}
static void cancel_lookup(void *context, void *request)
{
    fixture_t *f = context; CHECK(request == f && solaris_executor_is_owner(f->owner));
    CHECK(++f->cancels == 1);
    CHECK(solaris_executor_defer(f->owner, &f->response) == SOLARIS_OK);
}
static solaris_status_t policy(void *context, uintptr_t fd, uint32_t family, uint32_t kind)
{
    fixture_t *f = context; (void)fd;
    CHECK(solaris_executor_is_owner(f->owner) && family == SOLARIS_ADDRESS_IPV4 && kind == SOLARIS_SOCKET_TCP);
    ++f->policies;
    return f->mode == DENIED ? SOLARIS_EACCESS : SOLARIS_OK;
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    fixture_t *f = context; CHECK(!f->starting && stream == f->stream);
    CHECK(solaris_executor_is_owner(f->owner) && ++f->opens == 1 && status == f->expected);
    if (status == SOLARIS_OK) CHECK(solaris_stream_close(stream) == SOLARIS_OK);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{ (void)context; (void)stream; (void)buffer; CHECK(0); }
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    fixture_t *f = context; (void)status; CHECK(stream == f->stream && f->opens == 1 && ++f->closes == 1);
    f->stream = NULL;
    solaris_test_event_signal(&f->done);
}
static const solaris_stream_callbacks_t callbacks = {.on_open = opened, .on_data = data, .on_close = closed};
static solaris_status_t accept_peer(void *context, const solaris_address_t *peer, const solaris_address_t *local,
    solaris_stream_t *stream, solaris_stream_callbacks_t *out, void **user)
{ (void)context; (void)peer; (void)local; (void)stream; (void)out; (void)user; return SOLARIS_EACCESS; }
static void listener_closed(void *context, solaris_status_t status)
{ (void)status; ((fixture_t *)context)->listener = NULL; }
static void start(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == SOLARIS_OK);
    solaris_address_t bind, bound, target;
    CHECK(solaris_address_parse("127.0.0.1", 0, &bind) == SOLARIS_OK);
    CHECK(solaris_tcp_listener_open(f->owner, &bind, NULL, accept_peer, listener_closed, f, &f->listener, &bound) == SOLARIS_OK);
    CHECK(solaris_address_parse("no-os-lookup.invalid", bound.port, &target) == SOLARIS_OK);
    f->answer = bound; f->answer.port = 0; /* DNS does not choose the service port. */
    if (f->mode == INVALID_FAMILY) f->answer = target;
    solaris_dialer_options_t options; solaris_dialer_options_init(&options);
    options.lookup = (solaris_dns_lookup_t){f, lookup, cancel_lookup};
    options.lookup_view = (solaris_dns_lookup_view_t){SOLARIS_DNS_PROXY_SERVER, 3, 4, 5, 6};
    options.require_lookup = 1; options.open_timeout_ms = 1000;
    options.prepare_socket = policy; options.policy_context = f;
    if (f->mode == STRICT_MISSING || f->mode == NUMERIC) memset(&options.lookup, 0, sizeof(options.lookup));
    if (f->mode == NUMERIC) target = bound;
    f->starting = 1;
    f->submit = solaris_dialer_open_stream(f->owner, &options, &target, &callbacks, f, &f->stream);
    f->starting = 0;
    if (f->mode == STRICT_MISSING || f->mode == REJECTED) {
        CHECK(f->submit == (f->mode == STRICT_MISSING ? SOLARIS_ENOTSUP : SOLARIS_EACCESS));
        CHECK(!f->stream && !f->opens && !f->closes);
        solaris_test_event_signal(&f->done);
    } else {
        CHECK(f->submit == SOLARIS_OK && f->stream);
        if (f->mode == CANCEL) CHECK(solaris_stream_close(f->stream) == SOLARIS_OK);
    }
}
static void run(int mode)
{
    fixture_t f = {.mode = mode};
    f.expected = mode == SUCCESS || mode == NUMERIC ? SOLARIS_OK : mode == CANCEL ? SOLARIS_ECANCELLED :
        mode == NETWORK_CHANGE ? SOLARIS_ENETWORK_CHANGED : mode == INVALID_COUNT || mode == INVALID_FAMILY ? SOLARIS_EINVAL : SOLARIS_EACCESS;
    CHECK(solaris_budget_create(1024 * 1024, NULL, &f.budget) == SOLARIS_OK);
    solaris_executor_options_t options = {.id = 1, .queue_capacity = 8, .resource_limit = 32, .budget = f.budget};
    CHECK(solaris_executor_create(&options, &f.owner) == SOLARIS_OK);
    CHECK(solaris_test_event_init(&f.done, 0) == 0);
    f.response = (solaris_deferred_t){.run = response, .context = &f};
    CHECK(solaris_executor_activate(f.owner, 1) == SOLARIS_OK);
    CHECK(solaris_executor_post(f.owner, start, &f) == SOLARIS_OK);
    solaris_test_event_wait(&f.done);
    CHECK(solaris_executor_quiesce(f.owner) == SOLARIS_OK);
    CHECK(solaris_executor_destroy(f.owner) == SOLARIS_OK);
    CHECK(!f.listener && !f.stream && !solaris_budget_used(f.budget));
    CHECK(f.lookups == (mode == STRICT_MISSING || mode == NUMERIC ? 0u : 1u));
    CHECK(f.policies == (mode == SUCCESS || mode == NUMERIC || mode == DENIED ? 1u : 0u));
    CHECK(f.cancels == (mode == CANCEL ? 1u : 0u));
    if (mode == STRICT_MISSING || mode == REJECTED) CHECK(!f.opens && !f.closes);
    else CHECK(f.opens == 1 && f.closes == 1);
    solaris_budget_release(f.budget); solaris_test_event_destroy(&f.done);
}
int main(void)
{
    solaris_dialer_options_t input, output; solaris_dialer_options_init(&input);
    input.lookup.start = lookup;
    CHECK(solaris_dialer_options_normalize(&input, &output) == SOLARIS_EINVAL);
    input.lookup.cancel = cancel_lookup; input.lookup_view.role = 99;
    CHECK(solaris_dialer_options_normalize(&input, &output) == SOLARIS_EINVAL);
    for (int mode = SUCCESS; mode <= NUMERIC; ++mode) run(mode);
    puts("DNS lookup injection: roles/revisions, strict no-fallback, numeric bootstrap, deferred cancellation and malformed results passed");
    return 0;
}
