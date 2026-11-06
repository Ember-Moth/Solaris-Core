#include "contracts/module/module.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { NORMAL, PAUSED, ACK_EOF, CANCEL_BEFORE, CANCEL_GREETING, CANCEL_APP, STOP_APP, LATE_METHOD, LATE_REPLY, PARTIAL_EOF, REJECT, ALLOCATE };
typedef struct environment environment_t;
typedef struct mock_stream {
    environment_t *env;
    solaris_stream_t stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_deferred_t opened, written, readable, writable, shutdown, closed;
    solaris_slice_t slice;
    solaris_io_done_fn done, shutdown_done;
    void *user, *shutdown_user;
    uint8_t input[64];
    size_t begin, end;
    unsigned int phase, current_phase;
    int busy, closing, reading, pressured, input_eof, eof_delivered;
} mock_stream_t;
struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget, *fixture_budget;
    solaris_module_config_t *config;
    solaris_stream_t *stream;
    solaris_test_event_t ready, pending, cancelled, complete;
    solaris_deferred_t late, resume;
    mock_stream_t mock;
    atomic_uint opens, closes;
    atomic_uint_fast64_t clock;
    unsigned int factory_calls, writes, completions, eof, shutdowns, writable;
    size_t received;
    int mode, failure, fail_at, allocations;
    solaris_status_t start_status, open_status, close_status;
};
static void queue(environment_t *env, solaris_deferred_t *node, void (*run)(void *), void *context)
{ node->run = run; node->context = context; CHECK(solaris_executor_defer(env->owner, node) == SOLARIS_OK); }
static uint64_t now_ns(void *context) { return atomic_load(&((environment_t *)context)->clock); }
static void *allocate(void *context, size_t size)
{ environment_t *env = context; if (++env->allocations == env->fail_at) return NULL; return malloc(size); }
static void mock_opened(void *context)
{ mock_stream_t *mock = context; mock->callbacks.on_open(mock->context, &mock->stream, SOLARIS_OK); }
static void mock_closed(void *context)
{ mock_stream_t *mock = context; CHECK(!mock->busy); mock->callbacks.on_close(mock->context, &mock->stream, SOLARIS_OK); }
static void mock_readable(void *context)
{
    mock_stream_t *mock = context; environment_t *env = mock->env;
    if (mock->closing || !mock->reading) return;
    if (mock->begin < mock->end) {
        size_t size = mock->end - mock->begin;
        if (env->mode != ACK_EOF && size > 3u) size = mock->current_phase < 2u ? 1u : 3u;
        solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(env->fixture_budget, mock->input + mock->begin, size, &buffer) == SOLARIS_OK);
        mock->begin += size;
        if ((env->mode == LATE_METHOD && mock->current_phase == 0u) || (env->mode == LATE_REPLY && mock->current_phase == 2u))
            atomic_store(&env->clock, UINT64_C(11000000));
        mock->callbacks.on_data(mock->context, &mock->stream, buffer); solaris_buffer_release(buffer);
    }
    if (mock->begin == mock->end && mock->input_eof && !mock->eof_delivered && !mock->closing) {
        mock->eof_delivered = 1; mock->callbacks.on_eof(mock->context, &mock->stream);
        if (env->mode == ACK_EOF) solaris_test_event_signal(&env->pending);
    }
    if (!mock->closing && mock->reading && mock->begin < mock->end && !mock->readable.queued) queue(env, &mock->readable, mock_readable, mock);
}
static void mock_written(void *context)
{
    mock_stream_t *mock = context; CHECK(mock->busy); mock->busy = 0;
    const solaris_buffer_t *buffer = mock->slice.buffer; mock->slice.buffer = NULL;
    mock->done(mock->user, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); solaris_buffer_release(buffer);
    if (mock->closing && !mock->closed.queued) queue(mock->env, &mock->closed, mock_closed, mock);
}
static void mock_writable(void *context)
{ mock_stream_t *mock = context; if (!mock->closing) mock->callbacks.on_writable(mock->context, &mock->stream); }
static void append(mock_stream_t *mock, const uint8_t *data, size_t size)
{
    if (mock->end + size > sizeof(mock->input)) {
        memmove(mock->input, mock->input + mock->begin, mock->end - mock->begin); mock->end -= mock->begin; mock->begin = 0u;
    }
    CHECK(mock->end + size <= sizeof(mock->input)); memcpy(mock->input + mock->end, data, size); mock->end += size;
}
static solaris_status_t mock_write(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    mock_stream_t *mock = state; environment_t *env = mock->env;
    if (mock->closing) return SOLARIS_ECLOSED;
    if (!mock->pressured) { mock->pressured = 1; queue(env, &mock->writable, mock_writable, mock); return SOLARIS_EAGAIN; }
    CHECK(!mock->busy); mock->busy = 1; mock->slice = *slice; solaris_buffer_retain(slice->buffer); mock->done = done; mock->user = context;
    unsigned int phase = mock->phase++; mock->current_phase = phase;
    const uint8_t *data = solaris_buffer_data(slice->buffer) + slice->offset;
    static const uint8_t greeting[] = {5,1,2}, auth[] = {1,7,'s','o','l','a','r','i','s',8,'p','a','s','s','w','o','r','d'}, request[] = {5,1,0,1,127,0,0,1,0,80};
    if (phase == 0u) { CHECK(slice->length == sizeof(greeting) && memcmp(data, greeting, sizeof(greeting)) == 0); const uint8_t reply[] = {5,2}; append(mock, reply, 2u); }
    else if (phase == 1u) { CHECK(slice->length == sizeof(auth) && memcmp(data, auth, sizeof(auth)) == 0); const uint8_t reply[] = {1,0}; append(mock, reply, 2u); }
    else if (phase == 2u) {
        CHECK(slice->length == sizeof(request) && memcmp(data, request, sizeof(request)) == 0);
        const uint8_t reply[] = {5,0,0,1,0,0,0,0,0,0,'e','a','r','l','y'};
        append(mock, reply, env->mode == PARTIAL_EOF ? 5u : sizeof(reply));
        if (env->mode == ACK_EOF || env->mode == PARTIAL_EOF) mock->input_eof = 1;
    } else {
        CHECK(phase == 3u && slice->length == 7u && memcmp(data, "payload", 7u) == 0);
        if (env->mode != ACK_EOF && env->mode != CANCEL_APP && env->mode != STOP_APP) {
            append(mock, (const uint8_t *)"payload", 7u); mock->input_eof = 1;
        }
    }
    int held = (env->mode == CANCEL_GREETING && phase == 0u) || ((env->mode == CANCEL_APP || env->mode == STOP_APP) && phase == 3u) || (env->mode == ACK_EOF && phase == 2u);
    if (!held) queue(env, &mock->written, mock_written, mock);
    else if (env->mode != ACK_EOF) solaris_test_event_signal(&env->pending);
    if (mock->reading && !mock->readable.queued && mock->begin < mock->end) queue(env, &mock->readable, mock_readable, mock);
    return SOLARIS_OK;
}
static void mock_shutdown_done(void *context)
{ mock_stream_t *mock = context; mock->shutdown_done(mock->shutdown_user, mock->closing ? SOLARIS_ECANCELLED : SOLARIS_OK); }
static solaris_status_t mock_shutdown(void *state, solaris_io_done_fn done, void *context)
{ mock_stream_t *mock = state; mock->shutdown_done = done; mock->shutdown_user = context; queue(mock->env, &mock->shutdown, mock_shutdown_done, mock); return SOLARIS_OK; }
static solaris_status_t mock_read(void *state, int enabled)
{
    mock_stream_t *mock = state; mock->reading = enabled;
    if (enabled && !mock->closing && !mock->readable.queued && (mock->begin < mock->end || (mock->input_eof && !mock->eof_delivered)))
        queue(mock->env, &mock->readable, mock_readable, mock);
    return SOLARIS_OK;
}
static solaris_status_t mock_close(void *state)
{
    mock_stream_t *mock = state;
    if (!mock->closing) {
        mock->closing = 1; solaris_test_event_signal(&mock->env->cancelled);
        if (!mock->busy && !mock->closed.queued) queue(mock->env, &mock->closed, mock_closed, mock);
    }
    return SOLARIS_OK;
}
static solaris_status_t mock_snapshot(void *state, solaris_io_snapshot_t *out) { (void)state; memset(out, 0, sizeof(*out)); return SOLARIS_OK; }
static const solaris_stream_ops_t mock_ops = {mock_write, mock_shutdown, mock_read, mock_close, mock_snapshot, NULL};
static solaris_status_t factory(void *context, solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    environment_t *env = context; *out = NULL; CHECK(owner == env->owner && peer->port == 1080u && options->pending_byte_limit >= 513u); env->factory_calls++;
    if (env->mode == REJECT) return SOLARIS_EACCESS;
    mock_stream_t *mock = &env->mock; mock->env = env; mock->stream = (solaris_stream_t){&mock_ops, mock, owner};
    mock->callbacks = *callbacks; mock->context = user; mock->reading = 1; *out = &mock->stream;
    queue(env, &mock->opened, mock_opened, mock); return SOLARIS_OK;
}
static void written(void *context, solaris_status_t status)
{
    environment_t *env = context;
    if (env->mode == ALLOCATE) CHECK(status == SOLARIS_OK || status == SOLARIS_ENOMEM || status == SOLARIS_ECANCELLED);
    else CHECK(status == ((env->mode == CANCEL_APP || env->mode == STOP_APP) ? SOLARIS_ECANCELLED : SOLARIS_OK));
    env->completions++;
}
static void shutdown_done(void *context, solaris_status_t status) { CHECK(status == SOLARIS_OK); ((environment_t *)context)->shutdowns++; }
static void resumed(void *context)
{ environment_t *env = context; CHECK(env->received == 0u); CHECK(solaris_stream_set_reading(env->stream, 1) == SOLARIS_OK); }
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    environment_t *env = context; CHECK(stream == env->stream && atomic_fetch_add(&env->opens, 1u) == 0u); env->open_status = status;
    if (status != SOLARIS_OK) return;
    if (env->mode == PAUSED) queue(env, &env->resume, resumed, env);
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(env->fixture_budget, "payload", 7u, &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, 7u}; solaris_status_t rc = solaris_stream_write(stream, &slice, written, env);
    if (rc == SOLARIS_OK) { env->writes++; CHECK(solaris_stream_write(stream, &slice, written, env) == SOLARIS_EAGAIN); }
    else { CHECK(env->mode == ALLOCATE && rc == SOLARIS_ENOMEM); CHECK(solaris_stream_close(stream) == SOLARIS_OK); }
    solaris_buffer_release(buffer);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    environment_t *env = context; CHECK(stream == env->stream && atomic_load(&env->opens) == 1u);
    const char *expected = "earlypayload"; size_t size = solaris_buffer_length(buffer), goal = env->mode == ACK_EOF ? 5u : 12u;
    CHECK(env->received + size <= goal && memcmp(solaris_buffer_data(buffer), expected + env->received, size) == 0); env->received += size;
    if (env->received == goal) {
        solaris_status_t status = solaris_stream_shutdown_write(stream, shutdown_done, env);
        if (status != SOLARIS_OK) {
            CHECK(env->mode == ALLOCATE && status == SOLARIS_ENOMEM);
            CHECK(solaris_stream_close(stream) == SOLARIS_OK);
        }
    }
}
static void eof(void *context, solaris_stream_t *stream) { environment_t *env = context; CHECK(stream == env->stream); env->eof++; }
static void writable(void *context, solaris_stream_t *stream) { environment_t *env = context; CHECK(stream == env->stream); env->writable++; }
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    environment_t *env = context; CHECK(stream == env->stream && atomic_fetch_add(&env->closes, 1u) == 0u); env->close_status = status;
    CHECK(env->completions == env->writes); solaris_io_snapshot_t stats;
    CHECK(solaris_stream_get_snapshot(stream, &stats) == SOLARIS_OK && stats.pending_bytes == 0u && stats.pending_requests == 0u);
    solaris_test_event_signal(&env->complete);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, eof, writable, closed};
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = env->owner, .carrier = {.context = env, .open = factory},
        .dialer = {.pending_byte_limit = 7u, .pending_request_limit = 1u, .open_timeout_ms = 10u}};
    env->allocations = 0; env->fail_at = env->failure;
    solaris_module_instance_t *instance = NULL; env->start_status = solaris_module_create(env->config, &services, NULL, NULL, &instance, NULL);
    if (env->start_status == SOLARIS_OK) {
        uint32_t caps; CHECK(solaris_outbound_capabilities(solaris_module_outbound(instance), &caps) == SOLARIS_OK && (caps & SOLARIS_OUTBOUND_STREAM) && env->factory_calls == 0u);
        solaris_address_t target; CHECK(solaris_address_parse("127.0.0.1", 80u, &target) == SOLARIS_OK);
        env->start_status = solaris_outbound_open_stream(solaris_module_outbound(instance), &target, &callbacks, env, &env->stream);
        CHECK(solaris_module_retire(instance) == SOLARIS_OK);
    }
    if (env->start_status != SOLARIS_OK) { CHECK(env->stream == NULL && (env->mode == REJECT || env->mode == ALLOCATE)); solaris_test_event_signal(&env->complete); }
    else if (env->mode == CANCEL_BEFORE) CHECK(solaris_stream_close(env->stream) == SOLARIS_OK);
    else if (env->mode == PAUSED) CHECK(solaris_stream_set_reading(env->stream, 0) == SOLARIS_OK);
    solaris_test_event_signal(&env->ready);
}
static void cancel(void *context, solaris_status_t status) { environment_t *env = context; CHECK(status == SOLARIS_OK && solaris_stream_close(env->stream) == SOLARIS_OK); }
static solaris_config_field_t field(const char *name, const char *text)
{ solaris_config_field_t f = {.name = name, .value = {.kind = SOLARIS_CONFIG_STRING}}; f.value.value.string.data = text; f.value.value.string.length = strlen(text); return f; }
static void run(int mode, int failure)
{
    environment_t env = {.mode = mode, .failure = failure}; atomic_init(&env.opens, 0u); atomic_init(&env.closes, 0u); atomic_init(&env.clock, 0u);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = &env; services.allocate = allocate; services.now_ns = now_ns;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &services, &env.budget) == SOLARIS_OK && solaris_budget_create(4096u, NULL, &env.fixture_budget) == SOLARIS_OK);
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(env.budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[] = {field("server", "127.0.0.1"), {.name = "port", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 1080}}, field("username", "solaris"), field("password", "password")};
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {fields, 4u}};
    CHECK(solaris_registry_compile(registry, "socks5", &view, &env.config, NULL) == SOLARIS_OK); solaris_registry_destroy(registry);
    solaris_test_event_t *events[] = {&env.ready, &env.pending, &env.cancelled, &env.complete};
    for (size_t i = 0u; i < 4u; ++i) CHECK(solaris_test_event_init(events[i], 0u) == 0);
    solaris_executor_options_t options = {.id = 0u, .queue_capacity = 2u, .resource_limit = 64u, .budget = env.budget, .services = &services};
    CHECK(solaris_executor_create(&options, &env.owner) == SOLARIS_OK && solaris_executor_activate(env.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK); solaris_test_event_wait(&env.ready); solaris_module_config_release(env.config);
    if (mode == ACK_EOF || mode == CANCEL_GREETING || mode == CANCEL_APP || mode == STOP_APP) {
        solaris_test_event_wait(&env.pending); CHECK(atomic_load(&env.closes) == 0u);
        if (mode == ACK_EOF) CHECK(atomic_load(&env.opens) == 0u);
        else {
            if (mode == STOP_APP) CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK);
            else CHECK(solaris_executor_post(env.owner, cancel, &env) == SOLARIS_OK);
            solaris_test_event_wait(&env.cancelled); CHECK(atomic_load(&env.closes) == 0u);
        }
        queue(&env, &env.late, mock_written, &env.mock);
    }
    solaris_test_event_wait(&env.complete);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK && solaris_executor_destroy(env.owner) == SOLARIS_OK);
    if (env.start_status == SOLARIS_OK) {
        CHECK(atomic_load(&env.opens) == 1u && atomic_load(&env.closes) == 1u);
        if (mode == NORMAL || mode == PAUSED || mode == ACK_EOF) CHECK(env.open_status == SOLARIS_OK && env.close_status == SOLARIS_OK && env.writes == 1u && env.completions == 1u && env.shutdowns == 1u && env.eof == 1u && env.received == (mode == ACK_EOF ? 5u : 12u));
        else if (mode == LATE_METHOD || mode == LATE_REPLY) CHECK(env.open_status == SOLARIS_ETIMEDOUT && env.close_status == SOLARIS_ETIMEDOUT);
        else if (mode == PARTIAL_EOF) CHECK(env.open_status == SOLARIS_EIO && env.close_status == SOLARIS_EIO);
        else if (mode == STOP_APP) CHECK(env.close_status == SOLARIS_ECANCELLED);
        else if (mode == ALLOCATE) CHECK(env.close_status == SOLARIS_OK || env.close_status == SOLARIS_ENOMEM);
        else CHECK(env.close_status == SOLARIS_OK);
    } else CHECK(atomic_load(&env.opens) == 0u && atomic_load(&env.closes) == 0u);
    for (size_t i = 0u; i < 4u; ++i) solaris_test_event_destroy(events[i]);
    CHECK(solaris_budget_used(env.budget) == 0u && solaris_budget_used(env.fixture_budget) == 0u);
    solaris_budget_release(env.budget); solaris_budget_release(env.fixture_budget);
}
int main(void)
{
    for (int mode = NORMAL; mode < ALLOCATE; ++mode) run(mode, 0);
    for (int failure = 1; failure <= 12; ++failure) run(ALLOCATE, failure);
    puts("SOCKS5 stream: multi-round handshake, split/coalesced replies, EOF, backpressure, absolute deadlines and cancellation barriers passed"); return 0;
}
