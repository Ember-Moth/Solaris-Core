#include "contracts/inbound/tun_stack.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

typedef struct fixture fixture_t;
typedef struct connection { fixture_t *test; solaris_stream_t *stream; uint32_t id; } connection_t;
struct fixture {
    solaris_engine_t *engine;
    solaris_executor_t *owners[2];
    solaris_tun_stack_t *stack;
    connection_t connections[64];
    uint32_t next_id;
    int emit_mode;
    uv_mutex_t output;
    solaris_test_event_t ready;
    atomic_int fail_after;
};
typedef struct command { fixture_t *test; uint8_t type; uint8_t *bytes; uint32_t length; solaris_executor_t *owner; } command_t;
typedef struct completion { connection_t *connection; uint32_t token; } completion_t;
static uint32_t read32(const uint8_t *bytes) { return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) | bytes[3]; }
static void put32(uint8_t *bytes, uint32_t n) { bytes[0] = (uint8_t)(n >> 24); bytes[1] = (uint8_t)(n >> 16); bytes[2] = (uint8_t)(n >> 8); bytes[3] = (uint8_t)n; }
static void event(fixture_t *test, uint8_t type, const void *bytes, uint32_t length)
{
    uint8_t header[5]; header[0] = type; put32(header + 1u, length);
    uv_mutex_lock(&test->output);
    CHECK(fwrite(header, 1u, sizeof(header), stdout) == sizeof(header));
    CHECK(length == 0u || fwrite(bytes, 1u, length, stdout) == length); CHECK(fflush(stdout) == 0);
    uv_mutex_unlock(&test->output);
}
static void status_event(fixture_t *test, uint8_t type, uint32_t id, solaris_status_t status)
{ uint8_t bytes[8]; put32(bytes, id); put32(bytes + 4u, (uint32_t)status); event(test, type, bytes, sizeof(bytes)); }
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    connection_t *connection = context; connection->stream = stream;
    status_event(connection->test, 'O', connection->id, status);
    if (connection->test->emit_mode == 6) CHECK(solaris_stream_close(stream) == SOLARIS_OK);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    connection_t *connection = context; CHECK(connection->stream == stream);
    if (connection->test->emit_mode == 4) connection->test->stack->ops->close(connection->test->stack->state);
    size_t length = solaris_buffer_length(buffer); uint8_t *bytes = malloc(length + 4u); CHECK(bytes != NULL);
    put32(bytes, connection->id); memcpy(bytes + 4u, solaris_buffer_data(buffer), length);
    event(connection->test, 'D', bytes, (uint32_t)(length + 4u)); free(bytes);
}
static void eof(void *context, solaris_stream_t *stream)
{ connection_t *connection = context; CHECK(connection->stream == stream); status_event(connection->test, 'E', connection->id, SOLARIS_OK); }
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    connection_t *connection = context; CHECK(connection->stream == stream);
    connection->stream = NULL; status_event(connection->test, 'C', connection->id, status);
}
static void written(void *context, solaris_status_t status)
{
    completion_t *completion = context;
    status_event(completion->connection->test, 'W', completion->token, status); free(completion);
}
static solaris_status_t emit(void *context, const uint8_t *bytes, size_t length)
{
    fixture_t *test = context;
    if (test->emit_mode == 1) return SOLARIS_EAGAIN;
    if (test->emit_mode == 2) test->stack->ops->close(test->stack->state);
    if (test->emit_mode == 3) CHECK(test->stack->ops->input(test->stack->state, bytes, length) == SOLARIS_EBUSY);
    event(context, 'P', bytes, (uint32_t)length); return SOLARIS_OK;
}
static solaris_status_t accept_connection(void *context, const solaris_address_t *source, const solaris_address_t *destination,
    solaris_stream_callbacks_t *callbacks, void **stream_context)
{
    fixture_t *test = context; if (test->emit_mode == 5) return SOLARIS_EACCESS;
    CHECK(test->next_id < 64u);
    connection_t *connection = &test->connections[test->next_id];
    connection->test = test; connection->id = test->next_id++;
    CHECK(source->port != 0u && destination->port != 0u);
    *callbacks = (solaris_stream_callbacks_t){.on_open = opened, .on_data = data, .on_eof = eof, .on_close = closed};
    *stream_context = connection; return SOLARIS_OK;
}
static void stack_closed(void *context, solaris_status_t status)
{ fixture_t *test = context; test->stack = NULL; status_event(test, 'S', 0u, status); }
static void *allocate(void *context, size_t size)
{
    fixture_t *test = context; int remaining = atomic_load(&test->fail_after);
    if (remaining == 0) return NULL;
    if (remaining > 0) atomic_fetch_sub(&test->fail_after, 1);
    return malloc(size);
}
static void execute(void *context, solaris_status_t posted_status)
{
    command_t *command = context; fixture_t *test = command->test; solaris_status_t rc = posted_status;
    if (rc != SOLARIS_OK) goto done;
    if (command->type == 'N' || command->type == 'B' || command->type == 'X') {
        solaris_tun_stack_options_t options = {.owner = command->owner, .context = test, .emit = emit,
            .accept = accept_connection, .on_close = stack_closed, .mtu = 1500u, .flow_limit = 8u,
            .pending_byte_limit = 32768u, .idle_timeout_ms = 10000u};
        if (command->length == 4u) options.idle_timeout_ms = read32(command->bytes);
        CHECK(solaris_address_parse("198.18.0.1", 0u, &options.address4) == SOLARIS_OK);
        CHECK(solaris_address_parse("fd00::1", 0u, &options.address6) == SOLARIS_OK);
        solaris_tun_stack_t *stack = NULL; rc = solaris_tun_lwip_create(&options, &stack);
        if (command->type == 'N' && rc == SOLARIS_OK) test->stack = stack;
        else CHECK(stack == NULL);
    } else if (command->type == 'G') {
        CHECK(command->length == 4u); test->emit_mode = (int)read32(command->bytes);
    } else if (command->type == 'M') {
        CHECK(command->length == 4u); atomic_store(&test->fail_after, (int32_t)read32(command->bytes));
    } else if (command->type == 'P') {
        CHECK(test->stack != NULL); rc = test->stack->ops->input(test->stack->state, command->bytes, command->length);
    } else if (command->type == 'S') {
        CHECK(test->stack != NULL); test->stack->ops->close(test->stack->state);
    } else {
        CHECK(command->length >= 4u); uint32_t id = read32(command->bytes); CHECK(id < test->next_id);
        connection_t *connection = &test->connections[id]; CHECK(connection->stream != NULL);
        if (command->type == 'R') rc = solaris_stream_set_reading(connection->stream, 1);
        else if (command->type == 'C') rc = solaris_stream_close(connection->stream);
        else if (command->type == 'F' || command->type == 'W') {
            CHECK(command->length >= 8u); completion_t *completion = malloc(sizeof(*completion)); CHECK(completion != NULL);
            completion->connection = connection; completion->token = read32(command->bytes + 4u);
            if (command->type == 'F') rc = solaris_stream_shutdown_write(connection->stream, written, completion);
            else {
                solaris_buffer_t *buffer = NULL;
                rc = solaris_buffer_copy(solaris_executor_budget(command->owner), command->bytes + 8u, command->length - 8u, &buffer);
                if (rc == SOLARIS_OK) {
                    solaris_slice_t slice = {.buffer = buffer, .length = command->length - 8u};
                    rc = solaris_stream_write(connection->stream, &slice, written, completion);
                }
                solaris_buffer_release(buffer);
            }
            if (rc != SOLARIS_OK) free(completion);
        } else CHECK(0);
    }
done:
    status_event(test, 'A', command->type, rc); solaris_test_event_signal(&test->ready);
}
int main(void)
{
    fixture_t test = {0}; atomic_init(&test.fail_after, -1);
    CHECK(uv_mutex_init(&test.output) == 0 && solaris_test_event_init(&test.ready, 0u) == 0);
    solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = &test; services.allocate = allocate;
    solaris_engine_options_t options; solaris_engine_options_init(&options); options.io_workers = 2u;
    CHECK(solaris_runtime_create(&options, NULL, &services, &test.engine, NULL) == SOLARIS_OK);
    uint64_t operation; CHECK(solaris_engine_start(test.engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(test.engine, 5000u, NULL) == SOLARIS_OK);
    test.owners[0] = solaris_runtime_executor(test.engine, 0u); test.owners[1] = solaris_runtime_executor(test.engine, 1u);
    uint8_t header[5];
    while (fread(header, 1u, sizeof(header), stdin) == sizeof(header)) {
        uint32_t length = read32(header + 1u); CHECK(length <= 65536u);
        uint8_t *bytes = malloc(length == 0u ? 1u : length); CHECK(bytes != NULL);
        CHECK(fread(bytes, 1u, length, stdin) == length);
        if (header[0] == 'T') { free(bytes); break; }
        command_t command = {.test = &test, .type = header[0], .bytes = bytes, .length = length,
            .owner = test.owners[header[0] == 'X' ? 1u : 0u]};
        CHECK(solaris_executor_post(command.owner, execute, &command) == SOLARIS_OK); solaris_test_event_wait(&test.ready); free(bytes);
    }
    atomic_store(&test.fail_after, -1);
    CHECK(solaris_engine_stop(test.engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(test.engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(test.stack == NULL);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(test.engine, &snapshot, NULL) == SOLARIS_OK && snapshot.io_buffer_bytes == 0u);
    CHECK(solaris_engine_destroy(test.engine, NULL) == SOLARIS_OK);
    event(&test, 'Z', NULL, 0u); solaris_test_event_destroy(&test.ready); uv_mutex_destroy(&test.output); return 0;
}
