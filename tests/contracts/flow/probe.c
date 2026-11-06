#include "observe/probe/http.h"
#include "observe/probe/http_codec.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { SUCCESS, INTERIM, HTTP_ERROR, MALFORMED, TRUNCATED, OVERSIZED, TIMEOUT, CANCEL_WRITE, STOP_WRITE,
    LATE_OPEN, LATE_RESPONSE, REJECT, RESPONSE_BEFORE_WRITE, CANCEL_BEFORE, BAD_URL, NO_DOMAIN, ALLOCATE };
typedef struct environment environment_t;
typedef struct mock_stream {
    environment_t *env;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, written, readable, closed;
    solaris_io_done_fn done;
    void *user;
    const solaris_buffer_t *request;
    size_t offset;
    int busy, reading, closing;
} mock_stream_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget, *fixture_budget;
    solaris_tracker_t *tracker;
    solaris_select_control_t *health;
    solaris_outbound_t outbound;
    solaris_http_probe_t *probe;
    solaris_http_probe_result_t result;
    mock_stream_t mock;
    solaris_deferred_t late;
    solaris_test_event_t ready, pending, cancelled, complete;
    atomic_uint done, releases;
    atomic_uint_fast64_t clock;
    int mode, fail_at, allocations, initial_failure;
    solaris_status_t start_status;
    char response[16450];
    size_t response_size;
};
static void queue(environment_t *env, solaris_deferred_t *node, void (*run)(void *), void *context)
{ node->run = run; node->context = context; CHECK(solaris_executor_defer(env->owner, node) == SOLARIS_OK); }
static void *allocate(void *context, size_t size)
{ environment_t *env = context; if (++env->allocations == env->fail_at) return NULL; return malloc(size); }
static uint64_t now_ns(void *context) { return atomic_load(&((environment_t *)context)->clock); }
static void released(void *context) { environment_t *env = context; CHECK(solaris_executor_is_owner(env->owner)); atomic_fetch_add(&env->releases, 1u); }
static void mock_opened(void *context)
{
    mock_stream_t *mock = context;
    if (mock->env->mode == LATE_OPEN) atomic_store(&mock->env->clock, UINT64_C(11000000));
    mock->callbacks.on_open(mock->context, &mock->stream, SOLARIS_OK);
}
static void mock_closed(void *context)
{ mock_stream_t *mock = context; CHECK(!mock->busy); mock->callbacks.on_close(mock->context, &mock->stream, SOLARIS_OK); }
static void mock_readable(void *context)
{
    mock_stream_t *mock = context; environment_t *env = mock->env;
    if (mock->closing || !mock->reading || mock->offset == env->response_size) return;
    size_t count = env->response_size - mock->offset, chunk = env->mode == OVERSIZED ? 97u : 3u;
    if (count > chunk) count = chunk;
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(env->fixture_budget, env->response + mock->offset, count, &buffer) == SOLARIS_OK);
    mock->offset += count;
    if (env->mode == LATE_RESPONSE) atomic_store(&env->clock, UINT64_C(11000000));
    mock->callbacks.on_data(mock->context, &mock->stream, buffer); solaris_buffer_release(buffer);
    if (mock->offset == env->response_size) {
        if (env->mode == TRUNCATED && !mock->closing) mock->callbacks.on_eof(mock->context, &mock->stream);
        if (env->mode == RESPONSE_BEFORE_WRITE) solaris_test_event_signal(&env->pending);
    } else if (mock->reading && !mock->closing) queue(env, &mock->readable, mock_readable, mock);
}
static void mock_written(void *context)
{
    mock_stream_t *mock = context; CHECK(mock->busy); mock->busy = 0;
    const solaris_buffer_t *request = mock->request; mock->request = NULL;
    mock->done(mock->user, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); solaris_buffer_release(request);
    if (mock->closing) { if (!mock->closed.queued) queue(mock->env, &mock->closed, mock_closed, mock); }
    else if (mock->env->mode == TIMEOUT) solaris_test_event_signal(&mock->env->pending);
    else if (mock->reading && !mock->readable.queued) queue(mock->env, &mock->readable, mock_readable, mock);
}
static solaris_status_t mock_write(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    mock_stream_t *mock = state; CHECK(!mock->busy);
    const char expected[] = "HEAD /health?x=1 HTTP/1.1\r\nHost: example.test:8080\r\nConnection: close\r\nUser-Agent: Solaris\r\n\r\n";
    CHECK(slice->length == sizeof(expected) - 1u && memcmp(solaris_buffer_data(slice->buffer) + slice->offset, expected, slice->length) == 0);
    mock->busy = 1; mock->done = done; mock->user = context; mock->request = slice->buffer; solaris_buffer_retain(slice->buffer);
    if (mock->env->mode == CANCEL_WRITE || mock->env->mode == STOP_WRITE) solaris_test_event_signal(&mock->env->pending);
    else if (mock->env->mode == RESPONSE_BEFORE_WRITE) queue(mock->env, &mock->readable, mock_readable, mock);
    else queue(mock->env, &mock->written, mock_written, mock);
    return SOLARIS_OK;
}
static solaris_status_t mock_shutdown(void *state, solaris_io_done_fn done, void *context)
{ (void)state; (void)done; (void)context; return SOLARIS_ENOTSUP; }
static solaris_status_t mock_read(void *state, int enabled) { ((mock_stream_t *)state)->reading = enabled; return SOLARIS_OK; }
static solaris_status_t mock_close(void *state)
{
    mock_stream_t *mock = state;
    if (!mock->closing) {
        mock->closing = 1; solaris_test_event_signal(&mock->env->cancelled);
        if (!mock->busy) queue(mock->env, &mock->closed, mock_closed, mock);
    }
    return SOLARIS_OK;
}
static solaris_status_t mock_snapshot(void *state, solaris_io_snapshot_t *out)
{ (void)state; memset(out, 0, sizeof(*out)); out->max_message_bytes = 4096u; return SOLARIS_OK; }
static const solaris_stream_ops_t mock_ops = {mock_write, mock_shutdown, mock_read, mock_close, mock_snapshot, NULL};
static uint32_t caps(void *state) { return SOLARIS_OUTBOUND_STREAM | (((environment_t *)state)->mode == NO_DOMAIN ? 0u : SOLARIS_OUTBOUND_STREAM_DOMAIN); }
static solaris_status_t open_stream(void *context, const solaris_address_t *target,
    const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    environment_t *env = context; CHECK(target->family == SOLARIS_ADDRESS_DOMAIN && target->port == 8080u && strcmp(target->host, "example.test") == 0);
    *out = NULL; if (env->mode == REJECT) return SOLARIS_EACCESS;
    mock_stream_t *mock = &env->mock; mock->env = env; mock->stream = (solaris_stream_t){&mock_ops, mock, env->owner};
    mock->callbacks = *callbacks; mock->context = user; mock->reading = 1; *out = &mock->stream;
    queue(env, &mock->opened, mock_opened, mock); return SOLARIS_OK;
}
static solaris_status_t open_datagram(void *context, uint32_t family, const solaris_datagram_callbacks_t *callbacks, void *user, solaris_datagram_t **out)
{ (void)context; (void)family; (void)callbacks; (void)user; *out = NULL; return SOLARIS_ENOTSUP; }
static void retire(void *state) { (void)state; }
static const solaris_outbound_ops_t outbound_ops = {caps, open_stream, open_datagram, retire};
static void done(void *context, solaris_http_probe_t *probe, const solaris_http_probe_result_t *result)
{
    environment_t *env = context; CHECK(probe == env->probe && atomic_fetch_add(&env->done, 1u) == 0u);
    env->result = *result; solaris_test_event_signal(&env->complete);
}
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    solaris_dial_plan_t source = {.outbound = &env->outbound, .context = env, .release = released, .node_id = 1u, .selection_revision = 7u};
    char url[128] = "http://example.test:8080/health?x=1#ignored";
    solaris_http_probe_options_t options = {.url = env->mode == BAD_URL ? "http://user@example.test/" : url,
        .timeout_ms = 10u, .tracker = env->tracker, .health = env->health};
    env->allocations = 0; env->fail_at = env->initial_failure;
    env->start_status = solaris_http_probe_start(env->owner, &source, &options, done, env, &env->probe);
    if (env->start_status == SOLARIS_OK) {
        CHECK(source.outbound == NULL && env->probe != NULL);
        if (env->mode == CANCEL_BEFORE) CHECK(solaris_http_probe_cancel(env->probe) == SOLARIS_OK);
    } else {
        CHECK(source.outbound == &env->outbound && env->probe == NULL && (env->mode == BAD_URL || env->mode == NO_DOMAIN || env->mode == ALLOCATE));
        CHECK(solaris_dial_plan_release(&source) == SOLARIS_OK); solaris_test_event_signal(&env->complete);
    }
    memset(url, 'x', sizeof(url)); solaris_test_event_signal(&env->ready);
}
static void cancel(void *context, solaris_status_t status)
{ environment_t *env = context; CHECK(status == SOLARIS_OK && solaris_http_probe_cancel(env->probe) == SOLARIS_OK); }
static void run(int mode, int allocation)
{
    environment_t env = {.mode = mode, .initial_failure = allocation}; atomic_init(&env.done, 0u); atomic_init(&env.releases, 0u); atomic_init(&env.clock, 0u);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = &env; services.allocate = allocate; services.now_ns = now_ns;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &services, &env.budget) == SOLARIS_OK && solaris_budget_create(65536u, NULL, &env.fixture_budget) == SOLARIS_OK);
    CHECK(solaris_tracker_create(env.budget, 2u, 2u, &env.tracker) == SOLARIS_OK);
    solaris_select_member_t members[] = {{1u,"probe-target"},{2u,"selected"}};
    CHECK(solaris_select_control_create(env.budget, members, 2u, 2u, &env.health) == SOLARIS_OK);
    solaris_test_event_t *events[] = {&env.ready, &env.pending, &env.cancelled, &env.complete};
    for (size_t i = 0u; i < 4u; ++i) CHECK(solaris_test_event_init(events[i], 0u) == 0);
    solaris_executor_options_t options = {.id = 1u, .queue_capacity = 2u, .resource_limit = 64u, .budget = env.budget, .services = &services};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK && solaris_executor_activate(env.owner, 1u) == SOLARIS_OK);
    env.outbound = (solaris_outbound_t){&outbound_ops, &env, env.owner};
    const char *response = mode == INTERIM ? "HTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /other\r\n\r\n" :
        mode == HTTP_ERROR ? "HTTP/1.1 500 Broken\r\n\r\n" : mode == MALFORMED ? "HTTP/1.1 204 Fine\r\n folded: invalid\r\n\r\n" :
        mode == TRUNCATED ? "HTTP/1.1 204 Fine\r\nX-Header: partial" : "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    strcpy(env.response, response); env.response_size = strlen(response);
    if (mode == OVERSIZED) { memset(env.response, 'a', sizeof(env.response)); env.response_size = sizeof(env.response); }
    CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK); solaris_test_event_wait(&env.ready);
    if (mode == TIMEOUT || mode == CANCEL_WRITE || mode == STOP_WRITE || mode == RESPONSE_BEFORE_WRITE) {
        solaris_test_event_wait(&env.pending); CHECK(atomic_load(&env.done) == 0u);
        CHECK(solaris_http_probe_cancel(env.probe) == SOLARIS_ETHREAD);
        if (mode == TIMEOUT) { atomic_store(&env.clock, UINT64_C(11000000)); solaris_executor_wake(env.owner); }
        else if (mode == RESPONSE_BEFORE_WRITE) { atomic_store(&env.clock, UINT64_C(6000000)); queue(&env, &env.late, mock_written, &env.mock); }
        else {
            if (mode == STOP_WRITE) CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK);
            else CHECK(solaris_executor_post(env.owner, cancel, &env) == SOLARIS_OK);
            solaris_test_event_wait(&env.cancelled); CHECK(atomic_load(&env.done) == 0u && atomic_load(&env.releases) == 0u);
            queue(&env, &env.late, mock_written, &env.mock);
        }
    }
    solaris_test_event_wait(&env.complete);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    CHECK(atomic_load(&env.releases) == 1u);
    solaris_select_snapshot_t selected; CHECK(solaris_select_snapshot(env.health, &selected) == SOLARIS_OK && selected.selected_id == 2u && selected.revision == 1u);
    solaris_select_member_snapshot_t health; CHECK(solaris_select_member_snapshot(env.health, 0u, &health) == SOLARIS_OK && !health.checking);
    if (env.start_status == SOLARIS_OK) {
        CHECK(atomic_load(&env.done) == 1u && env.result.node_id == 1u && env.result.selection_revision == 7u);
        solaris_status_t expected = mode == HTTP_ERROR || mode == MALFORMED || mode == TRUNCATED ? SOLARIS_EIO :
            mode == OVERSIZED ? SOLARIS_EMSGSIZE : mode == TIMEOUT || mode == LATE_OPEN || mode == LATE_RESPONSE ? SOLARIS_ETIMEDOUT :
            mode == CANCEL_WRITE || mode == STOP_WRITE || mode == CANCEL_BEFORE ? SOLARIS_ECANCELLED : mode == REJECT ? SOLARIS_EACCESS : SOLARIS_OK;
        if (mode == ALLOCATE) CHECK(env.result.status == SOLARIS_OK || env.result.status == SOLARIS_ENOMEM);
        else CHECK(env.result.status == expected);
        if (env.result.status == SOLARIS_OK) CHECK(env.result.http_status == (mode == INTERIM ? 302u : 204u) && env.result.bytes_written != 0u && env.result.bytes_read != 0u && health.health == SOLARIS_HEALTH_PASS);
        if (mode == RESPONSE_BEFORE_WRITE) CHECK(env.result.duration_ns == UINT64_C(6000000));
        if (mode == TIMEOUT || mode == LATE_OPEN || mode == LATE_RESPONSE) CHECK(env.result.duration_ns == UINT64_C(11000000));
        if (mode == CANCEL_WRITE || mode == STOP_WRITE || mode == CANCEL_BEFORE) CHECK(health.health == SOLARIS_HEALTH_UNKNOWN);
    } else CHECK(atomic_load(&env.done) == 0u && health.health == SOLARIS_HEALTH_UNKNOWN);
    solaris_tracker_totals_t users, probes; CHECK(solaris_tracker_totals(env.tracker, SOLARIS_FLOW_USER, &users) == SOLARIS_OK && users.created == 0u);
    CHECK(solaris_tracker_totals(env.tracker, SOLARIS_FLOW_PROBE, &probes) == SOLARIS_OK && probes.active == 0u && probes.created == probes.closed);
    CHECK(solaris_tracker_destroy(env.tracker) == SOLARIS_OK); solaris_select_control_release(env.health);
    for (size_t i = 0u; i < 4u; ++i) solaris_test_event_destroy(events[i]);
    CHECK(solaris_budget_used(env.budget) == 0u && solaris_budget_used(env.fixture_budget) == 0u);
    solaris_budget_release(env.budget); solaris_budget_release(env.fixture_budget);
}
static void codecs(void)
{
    solaris_budget_t *budget; CHECK(solaris_budget_create(65536u, NULL, &budget) == SOLARIS_OK);
    const char *bad[] = {"http://", "ftp://example.com", "http://user:pass@example.com", "http://host:0/", "http://host:65536/", "http://[::1", "http://::1/", "http://host/\r\nX:yes", "http://host/space here", "http://[fe80::1%25en0]/"};
    for (size_t i = 0u; i < sizeof(bad) / sizeof(bad[0]); ++i) { solaris_buffer_t *request; solaris_http_probe_target_t target; CHECK(solaris_http_probe_request(budget, bad[i], &target, &request) != SOLARIS_OK && request == NULL); }
    solaris_buffer_t *request; solaris_http_probe_target_t target;
    CHECK(solaris_http_probe_request(budget, "https://[::1]:8443?x=1#ignored", &target, &request) == SOLARIS_OK);
    CHECK(target.tls && target.address.family == SOLARIS_ADDRESS_IPV6 && target.address.port == 8443u);
    const char prefix[] = "HEAD /?x=1 HTTP/1.1\r\nHost: [::1]:8443\r\n";
    CHECK(memcmp(solaris_buffer_data(request), prefix, sizeof(prefix) - 1u) == 0); solaris_buffer_release(request);
    const char *headers[] = {"HTTP/2 200 OK\r\n\r\n", "HTTP/1.1 099 Invalid\r\n\r\n", "HTTP/1.1 200 OK\r\nMissingColon\r\n\r\n", "HTTP/1.1 200 OK\r\n: empty\r\n\r\n", "HTTP/1.1 200 OK\n\n"};
    for (size_t i = 0u; i < sizeof(headers) / sizeof(headers[0]); ++i) { uint16_t status; CHECK(solaris_http_probe_response((const uint8_t *)headers[i], strlen(headers[i]), &status) == SOLARIS_EIO); }
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
}
int main(void)
{
    codecs(); for (int mode = SUCCESS; mode < ALLOCATE; ++mode) run(mode, 0);
    for (int allocation = 1; allocation <= 9; ++allocation) run(ALLOCATE, allocation);
    puts("HTTP probe: URL/header validation, request/response completion, deadlines, cancellation, health and separate traffic passed"); return 0;
}
