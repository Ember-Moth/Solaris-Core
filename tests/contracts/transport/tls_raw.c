#include "transport/tls/tls.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
enum { WRAPPED = 32, UPLOAD = 65541, REMAINING = 1000, DOWNLOAD = 20003, PREFIX = 7 };
typedef struct fixture {
    solaris_executor_t *owner;
    solaris_tls_context_t *trust;
    solaris_stream_t *stream;
    solaris_address_t peer;
    solaris_test_event_t done;
    solaris_deadline_t *resume;
    unsigned int opened, wrapped, barrier, uploaded, shutdown, eof, closed;
    size_t received;
    int cancel;
} fixture_t;
static uint8_t pattern(size_t i) { return (uint8_t)(i * 43u + 69u); }
static void maybe_finish(fixture_t *f)
{
    if (!f->cancel && f->received == PREFIX + REMAINING + DOWNLOAD && f->uploaded && !f->shutdown)
        CHECK(solaris_stream_shutdown_write(f->stream, NULL, NULL) == SOLARIS_EINVAL);
}
static void shutdown_done(void *context, solaris_status_t status)
{ fixture_t *f = context; CHECK(status == SOLARIS_OK && ++f->shutdown == 1u); }
static void finish_if_ready(fixture_t *f)
{
    maybe_finish(f);
    if (!f->cancel && f->received == PREFIX + REMAINING + DOWNLOAD && f->uploaded && !f->shutdown)
        CHECK(solaris_stream_shutdown_write(f->stream, shutdown_done, f) == SOLARIS_OK);
}
static void wrapped(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == (f->cancel ? SOLARIS_ECANCELLED : SOLARIS_OK));
    CHECK(++f->wrapped == 1u && f->barrier == 0u);
}
static void switched(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == (f->cancel ? SOLARIS_ECANCELLED : SOLARIS_OK));
    CHECK(f->wrapped == 1u && ++f->barrier == 1u && f->uploaded == 0u);
    if (!f->cancel) { solaris_io_snapshot_t stats; CHECK(solaris_stream_get_snapshot(f->stream, &stats) == SOLARIS_OK && stats.raw_write); }
}
static void uploaded(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == (f->cancel ? SOLARIS_ECANCELLED : SOLARIS_OK));
    CHECK(f->barrier == 1u && ++f->uploaded == 1u); finish_if_ready(f);
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    fixture_t *f = context; CHECK(stream == f->stream && status == SOLARIS_OK && ++f->opened == 1u);
    uint32_t caps; CHECK(solaris_stream_raw_capabilities(stream, &caps) == SOLARIS_OK && caps == 3u);
    solaris_buffer_t *buffer; CHECK(solaris_buffer_allocate(solaris_executor_budget(f->owner), WRAPPED + UPLOAD, &buffer) == SOLARIS_OK);
    for (size_t i = 0u; i < WRAPPED + UPLOAD; ++i) solaris_buffer_mutable_data(buffer)[i] = pattern(i);
    CHECK(solaris_buffer_set_length(buffer, WRAPPED + UPLOAD) == SOLARIS_OK);
    solaris_slice_t first = {buffer, 0u, WRAPPED}, second = {buffer, WRAPPED, UPLOAD};
    CHECK(solaris_stream_write(stream, &first, wrapped, f) == SOLARIS_OK);
    CHECK(solaris_stream_write_raw(stream, switched, f) == SOLARIS_OK);
    CHECK(solaris_stream_write_raw(stream, switched, f) == SOLARIS_EBUSY);
    CHECK(solaris_stream_write(stream, &second, uploaded, f) == SOLARIS_OK);
    CHECK(solaris_stream_write(stream, &second, uploaded, f) == SOLARIS_EAGAIN);
    solaris_buffer_release(buffer);
    if (f->cancel) CHECK(solaris_stream_close(stream) == SOLARIS_OK);
}
static void resumed(void *context, solaris_status_t status)
{ fixture_t *f = context; f->resume = NULL; CHECK(status == SOLARIS_OK && f->received == PREFIX); CHECK(solaris_stream_set_reading(f->stream, 1) == SOLARIS_OK); }
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    fixture_t *f = context; CHECK(!f->cancel && stream == f->stream);
    size_t count = solaris_buffer_length(buffer); const uint8_t *bytes = solaris_buffer_data(buffer);
    CHECK(solaris_buffer_mutable_data((solaris_buffer_t *)buffer) == NULL);
    if (f->received == 0u) {
        CHECK(count == PREFIX && memcmp(bytes, "SWITCH!", PREFIX) == 0);
        CHECK(solaris_stream_set_reading(stream, 0) == SOLARIS_OK);
        CHECK(solaris_stream_read_raw(stream) == SOLARIS_OK && solaris_stream_read_raw(stream) == SOLARIS_OK);
        CHECK(solaris_deadline_start(f->owner, 5u, resumed, f, &f->resume) == SOLARIS_OK);
    } else {
        CHECK(f->received + count <= PREFIX + REMAINING + DOWNLOAD);
        for (size_t i = 0u; i < count; ++i) {
            size_t offset = f->received + i - PREFIX;
            uint8_t expected = offset < REMAINING ? (uint8_t)(offset * 31u + 19u) : pattern(offset - REMAINING);
            CHECK(bytes[i] == expected);
        }
    }
    f->received += count; finish_if_ready(f);
}
static void eof(void *context, solaris_stream_t *stream)
{ fixture_t *f = context; CHECK(stream == f->stream && ++f->eof == 1u && f->received == PREFIX + REMAINING + DOWNLOAD); }
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    fixture_t *f = context; CHECK(stream == f->stream && status == SOLARIS_OK && ++f->closed == 1u);
    CHECK(f->wrapped == 1u && f->barrier == 1u && f->uploaded == 1u && f->resume == NULL);
    solaris_io_snapshot_t stats; CHECK(solaris_stream_get_snapshot(stream, &stats) == SOLARIS_OK);
    CHECK(stats.pending_bytes == 0u && stats.pending_requests == 0u);
    if (!f->cancel) CHECK(stats.raw_read && stats.raw_write && stats.read_eof && stats.write_shutdown &&
        stats.bytes_written == WRAPPED + UPLOAD && stats.bytes_read == PREFIX + REMAINING + DOWNLOAD && f->shutdown == 1u && f->eof == 1u);
    else CHECK(stats.bytes_written == 0u && stats.bytes_read == 0u && f->shutdown == 0u && f->eof == 0u);
    solaris_test_event_signal(&f->done);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, eof, NULL, closed};
static void start(void *context, solaris_status_t status)
{
    fixture_t *f = context; CHECK(status == SOLARIS_OK);
    solaris_dialer_options_t options = {.pending_byte_limit = WRAPPED + UPLOAD, .pending_request_limit = 2u,
        .read_chunk_size = PREFIX, .open_timeout_ms = 2000u};
    CHECK(solaris_tls_open(f->owner, f->trust, "localhost", SOLARIS_TLS_1_2, NULL, &options, &f->peer, &callbacks, f, &f->stream) == SOLARIS_OK);
}
int main(int argc, char **argv)
{
    CHECK(argc == 4); fixture_t f = {.cancel = atoi(argv[3])}; solaris_budget_t *budget;
    CHECK(solaris_budget_create(8u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    char pem[16384]; FILE *file = fopen(argv[2], "rb"); CHECK(file != NULL);
    size_t n = fread(pem, 1u, sizeof(pem), file); CHECK(feof(file)); fclose(file);
    CHECK(solaris_tls_context_create(budget, pem, n, &f.trust) == SOLARIS_OK);
    CHECK(solaris_test_event_init(&f.done, 0u) == 0);
    solaris_executor_options_t options = {.id = 0u, .queue_capacity = 16u, .resource_limit = 128u, .budget = budget};
    CHECK(solaris_executor_create(&options, &f.owner) == SOLARIS_OK && solaris_executor_activate(f.owner, 1u) == SOLARIS_OK);
    CHECK(solaris_address_parse("127.0.0.1", (uint16_t)atoi(argv[1]), &f.peer) == SOLARIS_OK);
    CHECK(solaris_executor_post(f.owner, start, &f) == SOLARIS_OK); solaris_test_event_wait(&f.done);
    CHECK(solaris_executor_quiesce(f.owner) == SOLARIS_OK && solaris_executor_destroy(f.owner) == SOLARIS_OK);
    solaris_tls_context_release(f.trust); solaris_test_event_destroy(&f.done);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
    puts("TLS raw: ordered write barrier, pending plaintext before coalesced raw bytes, pause, half-close and cancellation passed"); return 0;
}
