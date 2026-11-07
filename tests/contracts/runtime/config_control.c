#include <solaris/core.h>
#include <solaris/control.h>
#include "runtime/config/manager.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
    solaris_test_event_t callback;
    solaris_status_t status;
    solaris_control_result_t result;
    uint64_t committed;
    atomic_uint completed_controls, cancelled_after_publication;
} fixture_t;
static void event(void *context, const solaris_event_t *e)
{
    fixture_t *f = context;
    if ((e->operation == SOLARIS_OPERATION_SET_MODE || e->operation == SOLARIS_OPERATION_SELECT) &&
        e->status == SOLARIS_OK) {
        CHECK(e->config_revision);
        CHECK(solaris_engine_cancel(f->engine, e->operation_id, NULL) == SOLARIS_ECLOSED);
        atomic_fetch_add(&f->cancelled_after_publication, 1);
    }
}
static void prepared(void *context, solaris_status_t status, solaris_prepared_config_t *value,
                     const solaris_error_t *error)
{
    fixture_t *f = context;
    (void)error;
    f->status = status;
    f->prepared = value;
    solaris_test_event_signal(&f->callback);
}
static void committed(void *context, solaris_status_t status, uint64_t revision, const solaris_error_t *error)
{
    fixture_t *f = context;
    (void)error;
    f->status = status;
    f->committed = revision;
    solaris_test_event_signal(&f->callback);
}
static void controlled(void *context, solaris_status_t status, const solaris_control_result_t *result,
                       const solaris_error_t *error)
{
    fixture_t *f = context;
    (void)error;
    f->status = status;
    f->result = *result;
    atomic_fetch_add(&f->completed_controls, 1);
    if (status != SOLARIS_OK)
        CHECK(!result->config_revision && !result->selection_revision && !result->mode && !result->group_id &&
              !result->selected_id);
    solaris_test_event_signal(&f->callback);
}
static void wait_callback(fixture_t *f, solaris_status_t expected)
{
    solaris_test_event_wait(&f->callback);
    CHECK(solaris_engine_flush(f->engine, 5000, NULL) == SOLARIS_OK);
    CHECK(f->status == expected);
}
static solaris_prepared_config_t *prepare(fixture_t *f, const char *yaml)
{
    solaris_config_t *image;
    solaris_diagnostics_t *diagnostics;
    solaris_error_t error;
    CHECK(solaris_config_compile_bytes(yaml, strlen(yaml), NULL, &image, &diagnostics, &error) == SOLARIS_OK);
    solaris_diagnostics_release(diagnostics);
    uint64_t id;
    CHECK(solaris_engine_prepare_config(f->engine, image, NULL, prepared, f, &id, &error) == SOLARIS_OK);
    solaris_config_release(image);
    wait_callback(f, SOLARIS_OK);
    CHECK(f->prepared);
    solaris_prepared_config_t *out = f->prepared;
    f->prepared = NULL;
    return out;
}
static uint64_t commit(fixture_t *f, solaris_prepared_config_t *value)
{
    uint64_t id;
    CHECK(solaris_engine_commit_config(f->engine, value, committed, f, &id, NULL) == SOLARIS_OK);
    wait_callback(f, SOLARIS_OK);
    solaris_prepared_config_release(value);
    CHECK(f->committed);
    return f->committed;
}
static solaris_control_snapshot_t *snapshot(fixture_t *f, solaris_control_info_t *info)
{
    solaris_control_snapshot_t *s;
    CHECK(solaris_engine_get_control_snapshot(f->engine, &s, NULL) == SOLARIS_OK);
    CHECK(solaris_control_snapshot_get_info(s, info) == SOLARIS_OK);
    return s;
}
static uint64_t node(solaris_control_snapshot_t *s, const char *name)
{
    solaris_control_info_t info;
    CHECK(solaris_control_snapshot_get_info(s, &info) == SOLARIS_OK);
    for (size_t i = 0; i < info.node_count; ++i) {
        solaris_config_node_info_t n;
        CHECK(solaris_control_snapshot_get_node(s, i, &n) == SOLARIS_OK);
        if (!strcmp(n.name, name))
            return n.id;
    }
    CHECK(0);
    return 0;
}
static solaris_group_info_t group(solaris_control_snapshot_t *s, const char *name)
{
    solaris_control_info_t info;
    CHECK(solaris_control_snapshot_get_info(s, &info) == SOLARIS_OK);
    for (size_t i = 0; i < info.group_count; ++i) {
        solaris_group_info_t g;
        CHECK(solaris_control_snapshot_get_group(s, i, &g) == SOLARIS_OK);
        if (!strcmp(g.name, name))
            return g;
    }
    CHECK(0);
    return (solaris_group_info_t){0};
}
static uint64_t set_mode(fixture_t *f, uint64_t config, solaris_mode_t mode, solaris_status_t expected)
{
    uint64_t id;
    CHECK(solaris_engine_set_mode(f->engine, config, mode, controlled, f, &id, NULL) == SOLARIS_OK);
    wait_callback(f, expected);
    return f->result.selection_revision;
}
static uint64_t select_node(fixture_t *f, uint64_t config, uint64_t group_id, uint64_t member,
                            solaris_status_t expected)
{
    uint64_t id;
    CHECK(solaris_engine_select(f->engine, config, group_id, member, controlled, f, &id, NULL) == SOLARIS_OK);
    wait_callback(f, expected);
    return f->result.selection_revision;
}
typedef struct gate {
    solaris_test_event_t entered, release;
} gate_t;
static solaris_status_t gated_start(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    gate_t *gate = context;
    (void)engine;
    /* Test-only owner gate: deterministically keep the following public
     * operation queued while cancellation is requested from another thread. */
    solaris_test_event_signal(&gate->entered);
    solaris_test_event_wait(&gate->release);
    solaris_runtime_operation_complete(operation, SOLARIS_OK, 0);
    return SOLARIS_OK;
}
static void queued_cancel(fixture_t *f, uint64_t config, uint64_t before)
{
    gate_t gate;
    CHECK(!solaris_test_event_init(&gate.entered, 0));
    CHECK(!solaris_test_event_init(&gate.release, 0));
    solaris_runtime_request_t request = {
        .operation = SOLARIS_OPERATION_PROBE, .requires_running = 1, .context = &gate, .start = gated_start};
    uint64_t gate_id, id;
    CHECK(solaris_runtime_request_submit(f->engine, &request, &gate_id, NULL) == SOLARIS_OK);
    solaris_test_event_wait(&gate.entered);
    CHECK(solaris_engine_set_mode(f->engine, config, SOLARIS_MODE_DIRECT, controlled, f, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_cancel(f->engine, id, NULL) == SOLARIS_OK);
    solaris_test_event_signal(&gate.release);
    wait_callback(f, SOLARIS_ECANCELLED);
    solaris_control_info_t info;
    solaris_control_snapshot_t *s = snapshot(f, &info);
    CHECK(info.selection_revision == before && info.mode == SOLARIS_MODE_RULE);
    solaris_control_snapshot_release(s);
    solaris_test_event_destroy(&gate.entered);
    solaris_test_event_destroy(&gate.release);
}
typedef struct plan_check {
    solaris_config_admission_t *view;
    solaris_executor_t *owner;
    uint64_t target, expected, revision;
    solaris_test_event_t done;
} plan_check_t;
static void check_plan(void *context, solaris_status_t status)
{
    plan_check_t *check = context;
    CHECK(status == SOLARIS_OK);
    solaris_dial_plan_t plan;
    uint32_t caps;
    CHECK(solaris_config_admission_acquire_plan(check->view, check->owner, check->target, &plan, &caps) == SOLARIS_OK);
    CHECK(plan.node_id == check->expected && plan.selection_revision == check->revision &&
          (caps & SOLARIS_OUTBOUND_STREAM));
    CHECK(solaris_dial_plan_release(&plan) == SOLARIS_OK);
    solaris_test_event_signal(&check->done);
}
static void verify_admission(fixture_t *f, solaris_config_admission_t *view, uint64_t target, uint64_t expected,
                             uint64_t revision)
{
    plan_check_t check = {.view = view,
                          .owner = solaris_runtime_executor(f->engine, 0),
                          .target = target,
                          .expected = expected,
                          .revision = revision};
    CHECK(!solaris_test_event_init(&check.done, 0));
    CHECK(solaris_executor_post(check.owner, check_plan, &check) == SOLARIS_OK);
    solaris_test_event_wait(&check.done);
    solaris_test_event_destroy(&check.done);
}
typedef struct reader {
    fixture_t *f;
    solaris_control_snapshot_t *old;
    uint64_t config;
    atomic_int stop;
    atomic_uint reads;
} reader_t;
static void read_snapshots(void *context)
{
    reader_t *r = context;
    solaris_control_snapshot_retain(r->old);
    while (!atomic_load(&r->stop)) {
        solaris_control_info_t info;
        solaris_control_snapshot_t *s = snapshot(r->f, &info);
        CHECK(info.config_revision == r->config && info.selection_revision);
        for (size_t i = 0; i < info.group_count; ++i) {
            solaris_group_info_t g;
            CHECK(solaris_control_snapshot_get_group(s, i, &g) == SOLARIS_OK);
            CHECK(g.reason_revision <= info.selection_revision);
            int found = 0;
            for (size_t j = 0; j < g.member_count; ++j) {
                uint64_t id;
                CHECK(solaris_control_snapshot_get_group_member(s, i, j, &id) == SOLARIS_OK);
                found |= id == g.selected_id;
            }
            CHECK(found);
        }
        solaris_control_snapshot_release(s);
        CHECK(solaris_control_snapshot_get_info(r->old, &info) == SOLARIS_OK && info.config_revision < r->config &&
              info.mode == SOLARIS_MODE_RULE);
        atomic_fetch_add(&r->reads, 1);
    }
    solaris_control_snapshot_release(r->old);
}
int main(void)
{
    fixture_t f = {0};
    CHECK(!solaris_test_event_init(&f.callback, 0));
    atomic_init(&f.completed_controls, 0);
    atomic_init(&f.cancelled_after_publication, 0);
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.io_workers = 2;
    solaris_host_t host = {.context = &f, .on_event = event};
    CHECK(solaris_engine_create(&options, &host, &f.engine, NULL) == SOLARIS_OK);
    uint64_t id;
    CHECK(solaris_engine_start(f.engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    const char *first = "mode: rule\nproxies: [{name: a, type: direct}, {name: b, type: reject}]\nproxy-groups: "
                        "[{name: Choice, type: select, proxies: [a,b,DIRECT]}]\n";
    uint64_t revision = commit(&f, prepare(&f, first));
    solaris_control_info_t initial;
    solaris_control_snapshot_t *old = snapshot(&f, &initial);
    uint64_t a = node(old, "a"), b = node(old, "b"), direct = node(old, "DIRECT"), choice = group(old, "Choice").id,
             global = group(old, "GLOBAL").id;
    CHECK(initial.config_revision == revision && group(old, "Choice").selection_reason == SOLARIS_SELECTION_INITIAL);
    CHECK(set_mode(&f, revision, SOLARIS_MODE_RULE, SOLARIS_OK) == initial.selection_revision);
    CHECK(select_node(&f, revision, global, direct, SOLARIS_OK) == initial.selection_revision);
    queued_cancel(&f, revision, initial.selection_revision);
    solaris_config_admission_t *old_view;
    CHECK(solaris_config_admission_acquire(f.engine, revision, &old_view) == SOLARIS_OK);
    CHECK(select_node(&f, revision, choice, b, SOLARIS_OK) > initial.selection_revision);
    set_mode(&f, revision, SOLARIS_MODE_GLOBAL, SOLARIS_OK);
    select_node(&f, revision, global, b, SOLARIS_OK);
    verify_admission(&f, old_view, choice, a, initial.selection_revision);
    solaris_config_admission_t *latest;
    CHECK(solaris_config_admission_acquire(f.engine, revision, &latest) == SOLARIS_OK);
    solaris_control_info_t latest_info;
    CHECK(solaris_config_admission_get_state(latest, &latest_info) == SOLARIS_OK &&
          latest_info.mode == SOLARIS_MODE_GLOBAL);
    verify_admission(&f, latest, global, b, latest_info.selection_revision);
    solaris_config_admission_release(latest);
    uint64_t rejected = 99;
    CHECK(solaris_engine_set_mode(f.engine, 0, SOLARIS_MODE_RULE, controlled, &f, &rejected, NULL) == SOLARIS_EINVAL &&
          !rejected);
    select_node(&f, revision, choice, choice, SOLARIS_EINVAL);
    const char *second = "mode: direct\nproxies: [{name: a, type: direct}, {name: b, type: reject}]\nproxy-groups: "
                         "[{name: Choice, type: select, proxies: [b,a,DIRECT]}]\n";
    solaris_prepared_config_t *candidate = prepare(&f, second);
    set_mode(&f, revision, SOLARIS_MODE_RULE, SOLARIS_OK);
    select_node(&f, revision, choice, a, SOLARIS_OK);
    uint64_t first_revision = revision;
    revision = commit(&f, candidate);
    solaris_control_info_t info;
    solaris_control_snapshot_t *s = snapshot(&f, &info);
    solaris_group_info_t selected = group(s, "Choice");
    CHECK(info.mode == SOLARIS_MODE_RULE && selected.selected_id == a &&
          selected.selection_reason == SOLARIS_SELECTION_RELOAD_PRESERVED);
    solaris_control_snapshot_release(s);
    const char *third = "mode: global\nproxies: [{name: b, type: reject}]\nproxy-groups: [{name: Choice, type: select, "
                        "proxies: [b,DIRECT]}, {name: Added, type: select, proxies: [DIRECT]}]\n";
    revision = commit(&f, prepare(&f, third));
    s = snapshot(&f, &info);
    selected = group(s, "Choice");
    CHECK(selected.selected_id == b && selected.previous_selected_id == a &&
          selected.selection_reason == SOLARIS_SELECTION_MEMBER_REMOVED);
    CHECK(group(s, "Added").selection_reason == SOLARIS_SELECTION_GROUP_ADDED && info.mode == SOLARIS_MODE_RULE);
    solaris_control_snapshot_release(s);
    verify_admission(&f, old_view, choice, a, initial.selection_revision);
    solaris_config_admission_release(old_view);
    select_node(&f, first_revision, choice, b, SOLARIS_EAGAIN);
    reader_t readers = {.f = &f, .old = old, .config = revision};
    atomic_init(&readers.stop, 0);
    atomic_init(&readers.reads, 0);
    uv_thread_t threads[3];
    for (size_t i = 0; i < 3; ++i)
        CHECK(!uv_thread_create(&threads[i], read_snapshots, &readers));
    for (unsigned i = 0; i < 160; ++i)
        select_node(&f, revision, choice, i % 2 ? b : direct, SOLARIS_OK);
    atomic_store(&readers.stop, 1);
    for (size_t i = 0; i < 3; ++i)
        CHECK(!uv_thread_join(&threads[i]));
    CHECK(atomic_load(&readers.reads) > 0);
    CHECK(solaris_engine_stop(f.engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(f.engine, 5000, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_destroy(f.engine, NULL) == SOLARIS_OK);
    CHECK(solaris_control_snapshot_get_info(old, &info) == SOLARIS_OK && info.config_revision == first_revision &&
          info.mode == SOLARIS_MODE_RULE && group(old, "Choice").selected_id == a);
    CHECK(atomic_load(&f.cancelled_after_publication) > 160);
    solaris_control_snapshot_release(old);
    solaris_test_event_destroy(&f.callback);
    puts("control: no-op revisions, queued/postpublication cancel, fixed admissions, latest-control reload migration "
         "and concurrent owned snapshots passed");
    return 0;
}
