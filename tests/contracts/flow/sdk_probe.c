#include <solaris/core.h>
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include "observe/probe/http.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x)                                                                                                       \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
typedef struct fixture {
    solaris_engine_t *engine;
    solaris_prepared_config_t *prepared;
    solaris_probe_result_t result;
    atomic_int fail_after;
    atomic_uint typed, generic;
    solaris_test_event_t gate_entered, gate_release, typed_entered, typed_release, generic_entered, generic_release;
    int block_typed, block_generic;
    uint64_t direct, reject, revision;
} fixture_t;
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    int left = atomic_load(&f->fail_after);
    while (left > 0 && !atomic_compare_exchange_weak(&f->fail_after, &left, left - 1)) {
    }
    return left == 1 ? NULL : malloc(size);
}
static void event(void *context, const solaris_event_t *event)
{
    fixture_t *f = context;
    if (event->operation != SOLARIS_OPERATION_PROBE)
        return;
    CHECK(!event->config_revision && atomic_load(&f->typed) == 1 && !atomic_load(&f->generic));
    CHECK(event->status == f->result.status);
    atomic_fetch_add(&f->generic, 1);
    if (f->block_generic) {
        solaris_test_event_signal(&f->generic_entered);
        solaris_test_event_wait(&f->generic_release);
    }
}
static void prepared(void *context, solaris_status_t status, solaris_prepared_config_t *prepared,
                     const solaris_error_t *error)
{
    fixture_t *f = context;
    (void)error;
    CHECK(status == SOLARIS_OK && prepared);
    f->prepared = prepared;
}
static void committed(void *context, solaris_status_t status, uint64_t revision, const solaris_error_t *error)
{
    fixture_t *f = context;
    (void)error;
    CHECK(status == SOLARIS_OK && revision);
    f->revision = revision;
}
static void probed(void *context, const solaris_probe_result_t *result)
{
    fixture_t *f = context;
    CHECK(atomic_fetch_add(&f->typed, 1) == 0 && !atomic_load(&f->generic));
    f->result = *result;
    CHECK(solaris_engine_flush(f->engine, 0, NULL) == SOLARIS_EDEADLOCK);
    CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_EDEADLOCK);
    if (f->block_typed) {
        solaris_test_event_signal(&f->typed_entered);
        solaris_test_event_wait(&f->typed_release);
    }
}
static solaris_status_t gate_start(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    (void)context;
    (void)engine;
    solaris_runtime_operation_complete(operation, SOLARIS_OK, 0);
    return SOLARIS_OK;
}
static void gate_complete(void *context, solaris_status_t status, uint64_t revision)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK && !revision);
    solaris_test_event_signal(&f->gate_entered);
    solaris_test_event_wait(&f->gate_release);
}
static void gate(fixture_t *f)
{
    solaris_runtime_request_t request = {
        .operation = SOLARIS_OPERATION_SET_MODE, .context = f, .start = gate_start, .complete = gate_complete};
    uint64_t id;
    CHECK(solaris_runtime_request_submit(f->engine, &request, &id, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&f->gate_entered);
}
static void reset(fixture_t *f)
{
    memset(&f->result, 0, sizeof(f->result));
    atomic_store(&f->typed, 0);
    atomic_store(&f->generic, 0);
}
static void init(fixture_t *f)
{
    memset(f, 0, sizeof(*f));
    atomic_init(&f->fail_after, 0);
    atomic_init(&f->typed, 0);
    atomic_init(&f->generic, 0);
    solaris_test_event_t *events[] = {&f->gate_entered,  &f->gate_release,    &f->typed_entered,
                                      &f->typed_release, &f->generic_entered, &f->generic_release};
    for (size_t i = 0; i < 6; ++i)
        CHECK(!solaris_test_event_init(events[i], 0));
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = f;
    services.allocate = allocate;
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.io_workers = 2;
    solaris_host_t host = {f, event};
    CHECK(solaris_runtime_create(&options, &host, &services, &f->engine, NULL) == SOLARIS_OK);
    uint64_t id;
    CHECK(solaris_engine_start(f->engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK);
    solaris_config_t *image;
    solaris_diagnostics_t *diagnostics;
    CHECK(solaris_config_compile_bytes("mode: rule\n", 11, NULL, &image, &diagnostics, NULL) == SOLARIS_OK);
    solaris_diagnostics_release(diagnostics);
    solaris_config_node_info_t node;
    CHECK(solaris_config_get_node(image, 0, &node) == SOLARIS_OK);
    f->direct = node.id;
    CHECK(solaris_config_get_node(image, 1, &node) == SOLARIS_OK);
    f->reject = node.id;
    CHECK(solaris_engine_prepare_config(f->engine, image, NULL, prepared, f, &id, NULL) == SOLARIS_OK);
    solaris_config_release(image);
    CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_commit_config(f->engine, f->prepared, committed, f, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK);
    solaris_prepared_config_release(f->prepared);
    f->prepared = NULL;
}
static void destroy(fixture_t *f)
{
    CHECK(solaris_engine_destroy(f->engine, NULL) == SOLARIS_OK);
    solaris_test_event_t *events[] = {&f->gate_entered,  &f->gate_release,    &f->typed_entered,
                                      &f->typed_release, &f->generic_entered, &f->generic_release};
    for (size_t i = 0; i < 6; ++i)
        solaris_test_event_destroy(events[i]);
}
typedef struct parent_fixture {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_scope_t parent;
    solaris_select_control_t *health;
    solaris_outbound_t outbound;
    solaris_test_event_t done;
    size_t baseline;
    unsigned released, opened;
} parent_fixture_t;
static uint32_t parent_caps(void *context)
{
    (void)context;
    return SOLARIS_OUTBOUND_STREAM;
}
static solaris_status_t parent_open(void *context, const solaris_address_t *target,
                                    const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    parent_fixture_t *f = context;
    (void)target;
    (void)callbacks;
    (void)user;
    (void)out;
    ++f->opened;
    return SOLARIS_ENOTSUP;
}
static const solaris_outbound_ops_t parent_ops = {.capabilities = parent_caps, .open_stream = parent_open};
static void parent_release(void *context)
{
    ++((parent_fixture_t *)context)->released;
}
static void parent_probe_done(void *context, solaris_http_probe_t *probe, const solaris_http_probe_result_t *result)
{
    (void)context;
    (void)probe;
    (void)result;
    CHECK(0);
}
static void parent_drained(void *context)
{
    parent_fixture_t *f = context;
    /* Health rejection happens after a deadline was accepted. The old
     * unparented path queued this callback before probe's final destructor. */
    CHECK(solaris_budget_used(f->budget) == f->baseline && f->released == 1 && !f->opened);
    solaris_test_event_signal(&f->done);
}
static void parent_start(void *context, solaris_status_t status)
{
    parent_fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&f->parent, f->owner, NULL, parent_drained, f) == SOLARIS_OK);
    f->baseline = solaris_budget_used(f->budget);
    solaris_dial_plan_t plan = {.outbound = &f->outbound, .context = f, .release = parent_release, .node_id = 1};
    solaris_http_probe_options_t options = {
        .url = "http://127.0.0.1:1/", .timeout_ms = 1000, .health = f->health, .parent_scope = &f->parent};
    solaris_http_probe_t *probe = NULL;
    CHECK(solaris_http_probe_start(f->owner, &plan, &options, parent_probe_done, f, &probe) == SOLARIS_EINVAL);
    CHECK(!probe && plan.outbound == &f->outbound);
    CHECK(solaris_dial_plan_release(&plan) == SOLARIS_OK);
    solaris_scope_cancel(&f->parent);
}
static void rejected_parent_cleanup(void)
{
    parent_fixture_t f = {0};
    CHECK(!solaris_test_event_init(&f.done, 0));
    CHECK(solaris_budget_create(1048576, NULL, &f.budget) == SOLARIS_OK);
    solaris_select_member_t member = {2, "other-node"};
    CHECK(solaris_select_control_create(f.budget, &member, 1, 2, &f.health) == SOLARIS_OK);
    solaris_executor_options_t options = {.queue_capacity = 4, .resource_limit = 64, .budget = f.budget};
    CHECK(solaris_executor_create(&options, &f.owner) == SOLARIS_OK);
    CHECK(solaris_executor_activate(f.owner, 1) == SOLARIS_OK);
    f.outbound = (solaris_outbound_t){&parent_ops, &f, f.owner};
    CHECK(solaris_executor_post(f.owner, parent_start, &f) == SOLARIS_OK);
    solaris_test_event_wait(&f.done);
    CHECK(solaris_executor_quiesce(f.owner) == SOLARIS_OK && solaris_executor_destroy(f.owner) == SOLARIS_OK);
    solaris_select_control_release(f.health);
    CHECK(!solaris_budget_used(f.budget));
    solaris_budget_release(f.budget);
    solaris_test_event_destroy(&f.done);
}
static void unit(void)
{
    rejected_parent_cleanup();
    fixture_t f;
    init(&f);
    uint64_t id;
    solaris_probe_options_t options;
    solaris_probe_options_init(&options);
    options.target_id = f.reject;
    options.url = "http://127.0.0.1:1/health";
    CHECK(solaris_engine_probe(f.engine, &options, probed, &f, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    CHECK(f.result.status == SOLARIS_EACCESS && atomic_load(&f.generic) == 1 && f.result.config_revision == f.revision);
    solaris_engine_snapshot_t baseline;
    CHECK(solaris_engine_get_snapshot(f.engine, &baseline, NULL) == SOLARIS_OK);
    for (int failure = 1; failure <= 32; ++failure) {
        reset(&f);
        gate(&f);
        CHECK(solaris_engine_probe(f.engine, &options, probed, &f, &id, NULL) == SOLARIS_OK);
        atomic_store(&f.fail_after, failure);
        solaris_test_event_signal(&f.gate_release);
        CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
        atomic_store(&f.fail_after, 0);
        CHECK(atomic_load(&f.typed) == 1 && atomic_load(&f.generic) == 1);
        CHECK(f.result.status == SOLARIS_ENOMEM || f.result.status == SOLARIS_EACCESS);
        solaris_engine_snapshot_t after;
        CHECK(solaris_engine_get_snapshot(f.engine, &after, NULL) == SOLARIS_OK);
        CHECK(!after.pending_operations && after.io_buffer_bytes == baseline.io_buffer_bytes);
    }
    reset(&f);
    gate(&f);
    CHECK(solaris_engine_probe(f.engine, &options, probed, &f, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_cancel(f.engine, id, NULL) == SOLARIS_OK);
    solaris_test_event_signal(&f.gate_release);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK && f.result.status == SOLARIS_ECANCELLED);
    for (unsigned i = 0; i < 64; ++i) {
        reset(&f);
        CHECK(solaris_engine_probe(f.engine, &options, probed, &f, &id, NULL) == SOLARIS_OK);
        solaris_status_t cancelled = solaris_engine_cancel(f.engine, id, NULL);
        CHECK(cancelled == SOLARIS_OK || cancelled == SOLARIS_ECLOSED);
        CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
        CHECK(atomic_load(&f.typed) == 1 && atomic_load(&f.generic) == 1);
        CHECK(f.result.status == SOLARIS_ECANCELLED || f.result.status == SOLARIS_EACCESS);
    }
    reset(&f);
    f.block_typed = f.block_generic = 1;
    CHECK(solaris_engine_probe(f.engine, &options, probed, &f, &id, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&f.typed_entered);
    CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT);
    solaris_test_event_signal(&f.typed_release);
    solaris_test_event_wait(&f.generic_entered);
    CHECK(solaris_engine_flush(f.engine, 0, NULL) == SOLARIS_ETIMEDOUT);
    solaris_test_event_signal(&f.generic_release);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    f.block_typed = f.block_generic = 0;
    solaris_log_snapshot_t *logs;
    CHECK(solaris_engine_get_logs(f.engine, 0, 0, &logs, NULL) == SOLARIS_OK);
    solaris_log_info_t info;
    CHECK(solaris_log_snapshot_get_info(logs, &info) == SOLARIS_OK && info.count);
    solaris_log_record_t record;
    CHECK(solaris_log_snapshot_get_record(logs, info.count - 1, &record) == SOLARIS_OK);
    CHECK(record.event == SOLARIS_LOG_PROBE && record.operation_id == id && record.config_revision == f.revision);
    destroy(&f);
    CHECK(solaris_log_snapshot_get_record(logs, 0, &record) == SOLARIS_OK);
    solaris_log_snapshot_release(logs);
    puts("Public probe: failure drain, cancellation race, two callback barriers and owned logs passed");
}
static void endpoint(const char *url, const char *pem_file, int expected)
{
    fixture_t f;
    init(&f);
    char *pem = NULL;
    size_t length = 0;
    if (strcmp(pem_file, "-")) {
        FILE *file = NULL;
#ifdef _MSC_VER
        CHECK(fopen_s(&file, pem_file, "rb") == 0);
#else
        file = fopen(pem_file, "rb");
#endif
        CHECK(file && !fseek(file, 0, SEEK_END));
        long n = ftell(file);
        CHECK(n > 0 && n <= 262144 && !fseek(file, 0, SEEK_SET));
        length = (size_t)n;
        pem = malloc(length);
        CHECK(pem && fread(pem, 1, length, file) == length);
        fclose(file);
    }
    solaris_probe_options_t options;
    solaris_probe_options_init(&options);
    options.target_id = f.direct;
    options.url = url;
    options.trust_pem = pem;
    options.trust_length = length;
    uint64_t id;
    solaris_status_t rc = solaris_engine_probe(f.engine, &options, probed, &f, &id, NULL);
    if (pem) {
        memset(pem, 0, length);
        free(pem);
    }
    if (rc == SOLARIS_OK) {
        CHECK(solaris_engine_flush(f.engine, 7000, NULL) == SOLARIS_OK);
        rc = f.result.status;
        CHECK(atomic_load(&f.generic) == 1);
    } else
        CHECK(!id && !atomic_load(&f.typed));
    CHECK(expected == 999 ? rc != SOLARIS_OK : rc == expected);
    if (rc == SOLARIS_OK)
        CHECK(f.result.http_status == 204 && f.result.node_id == f.direct && f.result.bytes_written &&
              f.result.bytes_read);
    destroy(&f);
    puts("Public HTTP(S) probe endpoint passed");
}
int main(int argc, char **argv)
{
    if (argc == 4)
        endpoint(argv[1], argv[2], atoi(argv[3]));
    else {
        CHECK(argc == 1);
        unit();
    }
    return 0;
}
