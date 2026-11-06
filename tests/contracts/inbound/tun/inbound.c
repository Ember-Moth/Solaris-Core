#include "contracts/inbound/tun.h"
#include "contracts/module/module.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x)                                                                                             \
    do {                                                                                                     \
        if (!(x)) {                                                                                          \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                          \
            abort();                                                                                         \
        }                                                                                                    \
    } while (0)
typedef struct fixture {
    solaris_engine_t *engine;
    solaris_executor_t *owner;
    solaris_tun_t *tun;
    solaris_module_instance_t *module;
    uv_mutex_t output;
    solaris_test_event_t ready;
    uint32_t connections, mode;
    atomic_int fail_after;
} fixture_t;
typedef struct command {
    fixture_t *test;
    uint8_t type;
    uint8_t *bytes;
    uint32_t length;
} command_t;
static uint32_t read32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24u | (uint32_t)p[1] << 16u | (uint32_t)p[2] << 8u | p[3];
}
static void put32(uint8_t *p, uint32_t n)
{
    p[0] = (uint8_t)(n >> 24u);
    p[1] = (uint8_t)(n >> 16u);
    p[2] = (uint8_t)(n >> 8u);
    p[3] = (uint8_t)n;
}
static void event(fixture_t *test, uint8_t type, const void *bytes, uint32_t length)
{
    uint8_t header[5];
    header[0] = type;
    put32(header + 1, length);
    uv_mutex_lock(&test->output);
    CHECK(fwrite(header, 1, sizeof(header), stdout) == sizeof(header));
    CHECK(!length || fwrite(bytes, 1, length, stdout) == length);
    CHECK(!fflush(stdout));
    uv_mutex_unlock(&test->output);
}
static void status_event(fixture_t *test, uint8_t type, uint32_t id, solaris_status_t status)
{
    uint8_t p[8];
    put32(p, id);
    put32(p + 4, (uint32_t)status);
    event(test, type, p, sizeof(p));
}
static solaris_status_t emit(void *context, const uint8_t *bytes, size_t length)
{
    fixture_t *test = context;
    if (test->mode == 1)
        return SOLARIS_EAGAIN;
    if (test->mode == 2)
        CHECK(solaris_tun_close(test->tun) == SOLARIS_OK);
    if (test->mode == 5)
        CHECK(solaris_tun_input(test->tun, bytes, length) == SOLARIS_EBUSY);
    event(test, 'P', bytes, (uint32_t)length);
    return SOLARIS_OK;
}
static solaris_status_t select_plan(void *context, solaris_executor_t *owner, uint8_t protocol,
                                    const solaris_address_t *source, const solaris_address_t *destination,
                                    solaris_dial_plan_t *out)
{
    fixture_t *test = context;
    CHECK(owner == test->owner && source->port && destination->port);
    if (test->mode == 3)
        return SOLARIS_EACCESS;
    solaris_status_t rc = solaris_module_plan_acquire(test->module, 1, out);
    if (test->mode == 4)
        CHECK(solaris_tun_close(test->tun) == SOLARIS_OK);
    if (protocol == 6)
        status_event(test, 'O', test->connections++, rc);
    return rc;
}
static void closed(void *context, const solaris_tun_snapshot_t *snapshot, solaris_status_t status)
{
    fixture_t *test = context;
    CHECK(!snapshot->active_tcp);
    test->tun = NULL;
    status_event(test, 'S', 0, status);
}
static void *allocate(void *context, size_t size)
{
    fixture_t *test = context;
    int remaining = atomic_load(&test->fail_after);
    if (!remaining)
        return NULL;
    if (remaining > 0)
        atomic_fetch_sub(&test->fail_after, 1);
    return malloc(size);
}
static void execute(void *context, solaris_status_t status)
{
    command_t *command = context;
    fixture_t *test = command->test;
    solaris_status_t rc = status;
    if (rc != SOLARIS_OK)
        goto done;
    if (command->type == 'N') {
        CHECK(!test->tun);
        if (!test->module) {
            solaris_registry_t *registry;
            solaris_module_config_t *config;
            CHECK(solaris_builtin_registry_create(solaris_executor_budget(test->owner), &registry, NULL) ==
                  SOLARIS_OK);
            solaris_config_field_t field = {.name = "read-chunk-size",
                                            .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 4096}};
            solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP,
                                          .value.map = {.fields = &field, .count = 1}};
            CHECK(solaris_registry_compile(registry, "direct", &view, &config, NULL) == SOLARIS_OK);
            solaris_module_services_t services = {.owner = test->owner};
            CHECK(solaris_module_create(config, &services, NULL, NULL, &test->module, NULL) == SOLARIS_OK);
            solaris_module_config_release(config);
            solaris_registry_destroy(registry);
        }
        solaris_tun_options_t options;
        solaris_tun_options_init(&options);
        options.owner = test->owner;
        options.context = test;
        options.emit = emit;
        options.select = select_plan;
        options.on_close = closed;
        options.tcp_flow_limit = 16;
        options.idle_timeout_ms = 10000;
        CHECK(solaris_address_parse("198.18.0.1", 0, &options.address4) == SOLARIS_OK);
        if (!command->length || command->bytes[0] != 4)
            CHECK(solaris_address_parse("fd00::1", 0, &options.address6) == SOLARIS_OK);
        if (command->length && (command->bytes[0] == 2 || command->bytes[0] == 3)) {
            options.stack = SOLARIS_TUN_STACK_SYSTEM;
            options.device.kind = command->bytes[0];
        }
        rc = solaris_tun_create(&options, &test->tun);
        if (rc == SOLARIS_OK)
            CHECK(solaris_tun_name(test->tun) == NULL);
    } else if (command->type == 'P') {
        CHECK(test->tun);
        rc = solaris_tun_input(test->tun, command->bytes, command->length);
    } else if (command->type == 'S') {
        CHECK(test->tun);
        rc = solaris_tun_close(test->tun);
    } else if (command->type == 'G') {
        CHECK(command->length == 4);
        test->mode = read32(command->bytes);
    } else if (command->type == 'M') {
        CHECK(command->length == 4);
        atomic_store(&test->fail_after, (int32_t)read32(command->bytes));
    } else if (command->type == 'Q') {
        solaris_tun_snapshot_t snapshot;
        CHECK(solaris_tun_snapshot(test->tun, &snapshot) == SOLARIS_OK);
        uint8_t bytes[24];
        put32(bytes, (uint32_t)snapshot.active_tcp);
        put32(bytes + 4, (uint32_t)snapshot.malformed);
        put32(bytes + 8, (uint32_t)snapshot.unsupported);
        put32(bytes + 12, (uint32_t)snapshot.congested);
        put32(bytes + 16, (uint32_t)snapshot.packets_in);
        put32(bytes + 20, (uint32_t)snapshot.packets_out);
        event(test, 'Q', bytes, sizeof(bytes));
    } else
        CHECK(0);
done:
    status_event(test, 'A', command->type, rc);
    solaris_test_event_signal(&test->ready);
}
int main(void)
{
    fixture_t test = {0};
    atomic_init(&test.fail_after, -1);
    CHECK(!uv_mutex_init(&test.output) && !solaris_test_event_init(&test.ready, 0));
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = &test;
    services.allocate = allocate;
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.io_workers = 1;
    CHECK(solaris_runtime_create(&options, NULL, &services, &test.engine, NULL) == SOLARIS_OK);
    uint64_t operation;
    CHECK(solaris_engine_start(test.engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(test.engine, 5000, NULL) == SOLARIS_OK);
    test.owner = solaris_runtime_executor(test.engine, 0);
    uint8_t header[5];
    while (fread(header, 1, sizeof(header), stdin) == sizeof(header)) {
        uint32_t n = read32(header + 1);
        CHECK(n <= 65536);
        uint8_t *bytes = malloc(n ? n : 1);
        CHECK(bytes);
        CHECK(fread(bytes, 1, n, stdin) == n);
        if (header[0] == 'T') {
            free(bytes);
            break;
        }
        command_t command = {&test, header[0], bytes, n};
        CHECK(solaris_executor_post(test.owner, execute, &command) == SOLARIS_OK);
        solaris_test_event_wait(&test.ready);
        free(bytes);
    }
    atomic_store(&test.fail_after, -1);
    CHECK(solaris_engine_stop(test.engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(test.engine, 5000, NULL) == SOLARIS_OK);
    CHECK(!test.tun);
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(test.engine, &snapshot, NULL) == SOLARIS_OK &&
          !snapshot.io_buffer_bytes);
    CHECK(solaris_engine_destroy(test.engine, NULL) == SOLARIS_OK);
    event(&test, 'Z', NULL, 0);
    solaris_test_event_destroy(&test.ready);
    uv_mutex_destroy(&test.output);
    return 0;
}
