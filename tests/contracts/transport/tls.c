#include "transport/tls/tls.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define PAYLOAD_BYTES 196613u
enum { TLS_ECHO, TLS_WRONG_NAME, TLS_UNTRUSTED, TLS_STALL, TLS_STOP, TLS_WRITE_CANCEL, TLS_TRUNCATED, TLS_REJECT_CARRIER };
typedef struct tls_case {
    solaris_executor_t *owner;
    solaris_tls_context_t *trust;
    solaris_stream_t *stream;
    solaris_address_t peer;
    solaris_test_event_t done, ready, stop_pending, stop_resume;
    solaris_stream_callbacks_t lower_callbacks;
    void *lower_context;
    solaris_deadline_t *resume;
    int mode;
    unsigned int opens, closes, writes, eof, shutdowns, writable, policy_calls;
    size_t received;
    solaris_status_t open_status, close_status;
} tls_case_t;

static unsigned char content(size_t i) { return (unsigned char)((i * 37u + 17u) & 255u); }
static void written(void *context, solaris_status_t status)
{
    tls_case_t *test = context;
    CHECK(status == (test->mode == TLS_WRITE_CANCEL ? SOLARIS_ECANCELLED : SOLARIS_OK));
    test->writes++;
}
static void shutdown_done(void *context, solaris_status_t status)
{ CHECK(status == SOLARIS_OK); ((tls_case_t *)context)->shutdowns++; }
static void resume(void *context, solaris_status_t status)
{
    tls_case_t *test = context; test->resume = NULL;
    CHECK(status == SOLARIS_OK && test->received == 0u);
    CHECK(solaris_stream_set_reading(test->stream, 1) == SOLARIS_OK);
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    tls_case_t *test = context;
    CHECK(stream == test->stream && ++test->opens == 1u);
    test->open_status = status;
    if (status != SOLARIS_OK) return;
    if (test->mode == TLS_TRUNCATED) return;
    CHECK(test->mode == TLS_ECHO || test->mode == TLS_WRITE_CANCEL);
    solaris_buffer_t *buffer;
    CHECK(solaris_buffer_allocate(solaris_executor_budget(test->owner), PAYLOAD_BYTES, &buffer) == SOLARIS_OK);
    unsigned char *bytes = solaris_buffer_mutable_data(buffer);
    for (size_t i = 0u; i < PAYLOAD_BYTES; ++i) bytes[i] = content(i);
    CHECK(solaris_buffer_set_length(buffer, PAYLOAD_BYTES) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, PAYLOAD_BYTES};
    CHECK(solaris_stream_write(stream, &slice, written, test) == SOLARIS_OK);
    CHECK(solaris_stream_write(stream, &slice, written, test) == SOLARIS_EAGAIN);
    solaris_buffer_release(buffer);
    if (test->mode == TLS_WRITE_CANCEL) { CHECK(solaris_stream_close(stream) == SOLARIS_OK); return; }
    CHECK(solaris_stream_set_reading(stream, 0) == SOLARIS_OK);
    CHECK(solaris_deadline_start(test->owner, 20u, resume, test, &test->resume) == SOLARIS_OK);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    tls_case_t *test = context;
    CHECK(test->mode == TLS_ECHO && stream == test->stream);
    size_t length = solaris_buffer_length(buffer);
    CHECK(test->received + length <= PAYLOAD_BYTES);
    for (size_t i = 0u; i < length; ++i) CHECK(solaris_buffer_data(buffer)[i] == content(test->received + i));
    test->received += length;
    if (test->received == PAYLOAD_BYTES)
        CHECK(solaris_stream_shutdown_write(stream, shutdown_done, test) == SOLARIS_OK);
}
static void eof(void *context, solaris_stream_t *stream)
{ tls_case_t *test = context; CHECK(stream == test->stream); test->eof++; }
static void writable(void *context, solaris_stream_t *stream)
{ tls_case_t *test = context; CHECK(stream == test->stream); test->writable++; }
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    tls_case_t *test = context;
    CHECK(stream == test->stream && ++test->closes == 1u);
    test->close_status = status;
    solaris_io_snapshot_t snapshot;
    CHECK(solaris_stream_get_snapshot(stream, &snapshot) == SOLARIS_OK);
    CHECK(snapshot.pending_bytes == 0u && snapshot.pending_requests == 0u);
    if (test->mode == TLS_ECHO) {
        CHECK(snapshot.bytes_written == PAYLOAD_BYTES && snapshot.bytes_read == PAYLOAD_BYTES);
        CHECK(snapshot.read_eof && snapshot.write_shutdown);
    }
    solaris_test_event_signal(&test->done);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, eof, writable, closed};
static solaris_status_t policy(void *context, uintptr_t socket, uint32_t family, uint32_t kind)
{
    (void)socket; (void)family;
    tls_case_t *test = context;
    CHECK(kind == SOLARIS_SOCKET_TCP && solaris_executor_is_owner(test->owner));
    test->policy_calls++; return SOLARIS_OK;
}
static solaris_status_t reject(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *cb, void *callback_context, solaris_stream_t **out)
{
    (void)context; (void)owner; (void)options; (void)peer; (void)cb; (void)callback_context;
    *out = NULL; return SOLARIS_EACCESS;
}
static void stop_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    tls_case_t *test = context; CHECK(status == SOLARIS_OK);
    test->lower_callbacks.on_open(test->lower_context, stream, status);
    /* The TLS pump is queued, but admission closes before it can run. */
    solaris_test_event_signal(&test->stop_pending); solaris_test_event_wait(&test->stop_resume);
}
static void stop_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{ tls_case_t *test = context; test->lower_callbacks.on_data(test->lower_context, stream, buffer); }
static void stop_eof(void *context, solaris_stream_t *stream)
{ tls_case_t *test = context; test->lower_callbacks.on_eof(test->lower_context, stream); }
static void stop_writable(void *context, solaris_stream_t *stream)
{ tls_case_t *test = context; test->lower_callbacks.on_writable(test->lower_context, stream); }
static void stop_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{ tls_case_t *test = context; test->lower_callbacks.on_close(test->lower_context, stream, status); }
static const solaris_stream_callbacks_t stop_callbacks = {stop_opened, stop_data, stop_eof, stop_writable, stop_closed};
static solaris_status_t stop_factory(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *cb, void *user, solaris_stream_t **out)
{
    tls_case_t *test = context; test->lower_callbacks = *cb; test->lower_context = user;
    return solaris_dialer_open_stream(owner, options, peer, &stop_callbacks, test, out);
}
static void start(void *context, solaris_status_t status)
{
    tls_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_dialer_options_t options;
    solaris_dialer_options_init(&options);
    options.pending_byte_limit = PAYLOAD_BYTES;
    options.pending_request_limit = 1u;
    options.read_chunk_size = 733u;
    options.open_timeout_ms = test->mode == TLS_STALL ? 30u : 2000u;
    options.prepare_socket = policy; options.policy_context = test;
    solaris_stream_factory_t factory = {.open = test->mode == TLS_STOP ? stop_factory : reject, .context = test};
    solaris_status_t rc = solaris_tls_open(test->owner, test->trust,
        test->mode == TLS_WRONG_NAME ? "wrong.example" : "localhost",
        SOLARIS_TLS_1_2,
        test->mode == TLS_REJECT_CARRIER || test->mode == TLS_STOP ? &factory : NULL, &options, &test->peer,
        &callbacks, test, &test->stream);
    if (test->mode == TLS_REJECT_CARRIER) { CHECK(rc == SOLARIS_EACCESS && test->stream == NULL); }
    else CHECK(rc == SOLARIS_OK && test->stream != NULL);
    solaris_test_event_signal(&test->ready);
}
static void run_case(solaris_budget_t *budget, solaris_tls_context_t *trust, int mode, uint16_t port)
{
    tls_case_t test = {.trust = trust, .mode = mode};
    CHECK(solaris_test_event_init(&test.done, 0u) == 0);
    CHECK(solaris_test_event_init(&test.ready, 0u) == 0);
    CHECK(solaris_test_event_init(&test.stop_pending, 0u) == 0 && solaris_test_event_init(&test.stop_resume, 0u) == 0);
    solaris_executor_options_t options = {.id = 2u, .queue_capacity = 16u, .resource_limit = 64u, .budget = budget};
    CHECK(solaris_executor_create(&options, &test.owner) == SOLARIS_OK);
    CHECK(solaris_executor_activate(test.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_address_parse("127.0.0.1", port, &test.peer) == SOLARIS_OK);
    CHECK(solaris_executor_post(test.owner, start, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.ready);
    if (mode == TLS_STOP) {
        solaris_test_event_wait(&test.stop_pending); CHECK(solaris_executor_begin_quiesce(test.owner) == SOLARIS_OK);
        solaris_test_event_signal(&test.stop_resume);
    }
    if (mode == TLS_REJECT_CARRIER) CHECK(solaris_executor_quiesce(test.owner) == SOLARIS_OK);
    if (mode != TLS_REJECT_CARRIER) solaris_test_event_wait(&test.done);
    CHECK(solaris_executor_quiesce(test.owner) == SOLARIS_OK);
    CHECK(solaris_executor_destroy(test.owner) == SOLARIS_OK);
    CHECK(test.resume == NULL);
    if (mode == TLS_REJECT_CARRIER) CHECK(test.opens == 0u && test.closes == 0u && test.policy_calls == 0u);
    else {
        CHECK(test.opens == 1u && test.closes == 1u && test.policy_calls == 1u);
        if (mode == TLS_WRONG_NAME || mode == TLS_UNTRUSTED) CHECK(test.open_status == SOLARIS_EACCESS);
        if (mode == TLS_STALL) CHECK(test.open_status == SOLARIS_ETIMEDOUT);
        if (mode == TLS_STOP) {
            if (test.open_status != SOLARIS_ECANCELLED || test.close_status != SOLARIS_ECANCELLED)
                fprintf(stderr, "TLS stop open=%d close=%d\n", test.open_status, test.close_status);
            CHECK(test.open_status == SOLARIS_ECANCELLED && test.close_status == SOLARIS_ECANCELLED);
        }
        if (mode == TLS_TRUNCATED) CHECK(test.open_status == SOLARIS_OK && test.close_status == SOLARIS_EIO && test.eof == 0u);
        if (mode == TLS_WRITE_CANCEL) CHECK(test.writes == 1u && test.close_status == SOLARIS_OK);
        if (mode == TLS_ECHO) CHECK(test.open_status == SOLARIS_OK && test.close_status == SOLARIS_OK &&
            test.writes == 1u && test.shutdowns == 1u && test.eof == 1u && test.writable == 1u);
    }
    solaris_test_event_destroy(&test.done); solaris_test_event_destroy(&test.ready);
    solaris_test_event_destroy(&test.stop_pending); solaris_test_event_destroy(&test.stop_resume);
    printf("TLS case %d passed\n", mode); fflush(stdout);
}
int main(int argc, char **argv)
{
    CHECK(argc == 6);
    FILE *file = fopen(argv[1], "rb"); CHECK(file != NULL);
    char pem[16384]; size_t size = fread(pem, 1u, sizeof(pem), file); CHECK(size > 0u && size < sizeof(pem)); fclose(file);
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(8u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    solaris_tls_context_t *trust = NULL;
    CHECK(solaris_tls_context_create(budget, "bad", 3u, &trust) == SOLARIS_EINVAL && trust == NULL);
    CHECK(solaris_tls_context_create(budget, pem, size, &trust) == SOLARIS_OK);
    size_t baseline = solaris_budget_used(budget);
    for (int mode = 0; mode <= TLS_REJECT_CARRIER; ++mode) {
        int index = mode == TLS_UNTRUSTED ? 3 : mode == TLS_STALL || mode == TLS_STOP ? 4 : mode == TLS_TRUNCATED ? 5 : 2;
        run_case(budget, trust, mode, (uint16_t)atoi(argv[index]));
        CHECK(solaris_budget_used(budget) == baseline);
    }
    solaris_tls_context_release(trust);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
    return 0;
}
