#include "support/runtime/files.h"
#include "observe/probe/http.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct worker {
    solaris_executor_t *owner;
    solaris_module_config_t *config;
    solaris_module_instance_t *nodes[2];
    solaris_select_control_t *control;
    solaris_select_group_t *group;
    solaris_dial_plan_t first;
    solaris_tracker_t *tracker;
    solaris_replay_store_t *replay;
    solaris_traffic_counter_t *traffic;
    solaris_tls_context_t *trust;
    solaris_http_probe_t *probe;
    solaris_test_event_t ready, done;
    const char *good_url, *bad_url;
    solaris_status_t expected_failure;
    int peer_may_disconnect;
    unsigned int phase;
    size_t bytes_read, bytes_written;
} worker_t;
static void next(worker_t *worker);
static void completed(void *context, solaris_http_probe_t *probe, const solaris_http_probe_result_t *result)
{
    worker_t *worker = context; CHECK(probe == worker->probe && solaris_executor_is_owner(worker->owner));
    CHECK(result->node_id == (worker->phase == 0u ? 1u : 2u) && result->selection_revision == (worker->phase == 0u ? 1u : 2u));
    solaris_status_t expected = worker->expected_failure != SOLARIS_OK ? worker->expected_failure : worker->phase == 2u ? SOLARIS_EIO : SOLARIS_OK;
    if (worker->peer_may_disconnect && result->status == SOLARIS_EIO)
        expected = SOLARIS_EIO;
    if (result->status != expected) fprintf(stderr, "probe phase=%u status=%d http=%u expected=%d\n", worker->phase, result->status, result->http_status, expected);
    CHECK(result->status == expected && result->connection_id != 0u && result->completed_ns >= result->started_ns);
    if (worker->expected_failure == SOLARIS_OK) CHECK(result->http_status == (worker->phase == 2u ? 503u : 204u) && result->bytes_written != 0u && result->bytes_read != 0u);
    worker->bytes_read += result->bytes_read; worker->bytes_written += result->bytes_written;
    solaris_select_snapshot_t selected; CHECK(solaris_select_snapshot(worker->control, &selected) == SOLARIS_OK && selected.selected_id == 2u && selected.revision == 2u);
    worker->phase++;
    if (worker->phase < 3u) { next(worker); return; }
    CHECK(solaris_select_group_retire(worker->group) == SOLARIS_OK);
    for (size_t i = 0u; i < 2u; ++i) CHECK(solaris_module_retire(worker->nodes[i]) == SOLARIS_OK);
    solaris_test_event_signal(&worker->done);
}
static void next(worker_t *worker)
{
    solaris_dial_plan_t source;
    if (worker->phase == 0u) { source = worker->first; memset(&worker->first, 0, sizeof(worker->first)); }
    else CHECK(solaris_select_plan_acquire(worker->group, &source) == SOLARIS_OK);
    solaris_http_probe_options_t options = {.url = worker->phase == 2u ? worker->bad_url : worker->good_url,
        .timeout_ms = 3000u, .trust = worker->trust, .tracker = worker->tracker, .health = worker->control};
    CHECK(solaris_http_probe_start(worker->owner, &source, &options, completed, worker, &worker->probe) == SOLARIS_OK && source.outbound == NULL);
}
static void begin(void *context, solaris_status_t status) { CHECK(status == SOLARIS_OK); next(context); }
static void create(void *context, solaris_status_t status)
{
    worker_t *worker = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = worker->owner, .replay = worker->replay, .dialer = {.traffic = worker->traffic}};
    for (size_t i = 0u; i < 2u; ++i) CHECK(solaris_module_create(worker->config, &services, NULL, NULL, &worker->nodes[i], NULL) == SOLARIS_OK);
    CHECK(solaris_select_group_create(worker->owner, worker->control, worker->nodes, 2u, NULL, NULL, &worker->group) == SOLARIS_OK);
    CHECK(solaris_select_plan_acquire(worker->group, &worker->first) == SOLARIS_OK);
    solaris_test_event_signal(&worker->ready);
}
static solaris_config_field_t field(const char *name, const char *value)
{ solaris_config_field_t f = {.name = name, .value = {.kind = SOLARIS_CONFIG_STRING}}; f.value.value.string.data = value; f.value.value.string.length = strlen(value); return f; }
static solaris_config_field_t number(const char *name, int64_t value)
{ solaris_config_field_t f = {.name = name, .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = value}}; return f; }
static size_t read_file(const char *path, char *out, size_t capacity)
{ FILE *file = solaris_test_fopen(path, "rb"); CHECK(file != NULL); size_t n = fread(out, 1u, capacity - 1u, file); CHECK(feof(file)); fclose(file); out[n] = '\0'; return n; }
int main(int argc, char **argv)
{
    CHECK(argc >= 10 && argc <= 12);
    solaris_budget_t *budget; CHECK(solaris_budget_create(16u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[16]; size_t count = 0u; char pem[16384];
    if (strcmp(argv[1], "block") != 0) {
        fields[count++] = number("pending-bytes", 4096); fields[count++] = number("pending-requests", 1); fields[count++] = number("read-chunk-size", 31);
        if (strcmp(argv[1], "direct") != 0) {
            fields[count++] = field("server", "127.0.0.1"); fields[count++] = number("port", atoi(argv[2]));
            if (strcmp(argv[1], "socks5") == 0) {
                if (strcmp(argv[3], "-") != 0 || strcmp(argv[4], "-") != 0) {
                    fields[count++] = field("username", argv[4]); fields[count++] = field("password", argv[3]);
                }
            } else {
                fields[count++] = field(strcmp(argv[1], "vless") == 0 ? "uuid" : "password", argv[3]);
                if (strcmp(argv[4], "-") != 0) fields[count++] = field("cipher", argv[4]);
            }
            if (strcmp(argv[5], "-") != 0) {
                (void)read_file(argv[5], pem, sizeof(pem));
                fields[count++] = (solaris_config_field_t){.name = "tls", .value = {.kind = SOLARIS_CONFIG_BOOL, .value.boolean = 1}};
                fields[count++] = field("servername", "localhost"); fields[count++] = field("ca-pem", pem);
            }
            if (argc >= 11) fields[count++] = field("encryption", argv[10]);
            if (argc == 12) fields[count++] = field("flow", argv[11]);
        }
    }
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {.fields = fields, .count = count}};
    solaris_module_config_t *config; solaris_error_t error;
    solaris_status_t rc = solaris_registry_compile(registry, argv[1], &view, &config, &error);
    if (rc != SOLARIS_OK) fprintf(stderr, "compile: %s\n", error.message);
    CHECK(rc == SOLARIS_OK); solaris_registry_destroy(registry);
    solaris_select_member_t members[] = {{1u,"first"},{2u,"second"}}; solaris_select_control_t *control;
    CHECK(solaris_select_control_create(budget, members, 2u, 1u, &control) == SOLARIS_OK);
    solaris_tracker_t *tracker; CHECK(solaris_tracker_create(budget, 16u, 16u, &tracker) == SOLARIS_OK);
    solaris_replay_store_t *replay; CHECK(solaris_replay_create(budget, 1024u, 0u, NULL, NULL, &replay) == SOLARIS_OK);
    solaris_tls_context_t *trust = NULL;
    if (strcmp(argv[6], "-") != 0) { size_t n = read_file(argv[6], pem, sizeof(pem)); CHECK(solaris_tls_context_create(budget, pem, n, &trust) == SOLARIS_OK); }
    worker_t workers[2] = {{0}};
    for (size_t i = 0u; i < 2u; ++i) {
        worker_t *worker = &workers[i]; worker->config = config; worker->control = control; worker->tracker = tracker; worker->replay = replay;
        worker->trust = trust; worker->good_url = argv[7]; worker->bad_url = argv[8]; worker->peer_may_disconnect = !strcmp(argv[9], "auth-denial-or-disconnect");
        worker->expected_failure = worker->peer_may_disconnect ? SOLARIS_EACCESS : (solaris_status_t)atoi(argv[9]);
        CHECK(solaris_traffic_counter_create(budget, &worker->traffic) == SOLARIS_OK);
        CHECK(solaris_test_event_init(&worker->ready, 0u) == 0 && solaris_test_event_init(&worker->done, 0u) == 0);
        solaris_executor_options_t options = {.id = (uint32_t)i, .queue_capacity = 8u, .resource_limit = 256u, .budget = budget};
        CHECK(solaris_executor_create(&options, &worker->owner) == SOLARIS_OK && solaris_executor_activate(worker->owner, 1u) == SOLARIS_OK);
        CHECK(solaris_executor_post(worker->owner, create, worker) == SOLARIS_OK);
    }
    for (size_t i = 0u; i < 2u; ++i) solaris_test_event_wait(&workers[i].ready);
    solaris_module_config_release(config); CHECK(solaris_select_set(control, 2u) == SOLARIS_OK);
    for (size_t i = 0u; i < 2u; ++i) CHECK(solaris_executor_post(workers[i].owner, begin, &workers[i]) == SOLARIS_OK);
    for (size_t i = 0u; i < 2u; ++i) {
        worker_t *worker = &workers[i]; solaris_test_event_wait(&worker->done);
        CHECK(solaris_executor_quiesce(worker->owner) == SOLARIS_OK && solaris_executor_destroy(worker->owner) == SOLARIS_OK);
        solaris_traffic_snapshot_t wire; CHECK(solaris_traffic_counter_snapshot(worker->traffic, &wire) == SOLARIS_OK && !wire.saturated);
        CHECK(wire.stream_read >= worker->bytes_read && wire.stream_written >= worker->bytes_written && wire.packets_written == 0u);
        solaris_traffic_counter_release(worker->traffic); solaris_test_event_destroy(&worker->ready); solaris_test_event_destroy(&worker->done);
    }
    solaris_select_member_snapshot_t one, two;
    CHECK(solaris_select_member_snapshot(control, 0u, &one) == SOLARIS_OK && solaris_select_member_snapshot(control, 1u, &two) == SOLARIS_OK);
    CHECK(!one.checking && !two.checking && one.health == (uint32_t)(workers[0].expected_failure == SOLARIS_OK ? SOLARIS_HEALTH_PASS : SOLARIS_HEALTH_FAIL) && two.health == SOLARIS_HEALTH_FAIL);
    solaris_tracker_totals_t users, probes; CHECK(solaris_tracker_totals(tracker, SOLARIS_FLOW_USER, &users) == SOLARIS_OK && users.created == 0u);
    CHECK(solaris_tracker_totals(tracker, SOLARIS_FLOW_PROBE, &probes) == SOLARIS_OK && probes.created == 6u && probes.closed == 6u && probes.active == 0u);
    solaris_connection_snapshot_t entries[16]; size_t needed;
    CHECK(solaris_tracker_list(tracker, 1, entries, 16u, &needed) == SOLARIS_OK && needed == 6u);
    unsigned int first = 0u, second = 0u;
    for (size_t i = 0u; i < needed; ++i) {
        CHECK(entries[i].state == SOLARIS_CONNECTION_CLOSED && entries[i].purpose == SOLARIS_FLOW_PROBE && entries[i].pending_requests == 0u);
        if (entries[i].node_id == 1u) { CHECK(entries[i].selection_revision == 1u); first++; }
        else { CHECK(entries[i].node_id == 2u && entries[i].selection_revision == 2u); second++; }
    }
    CHECK(first == 2u && second == 4u);
    CHECK(solaris_tracker_destroy(tracker) == SOLARIS_OK); solaris_select_control_release(control); solaris_replay_release(replay); solaris_tls_context_release(trust);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
    printf("%s probes: old/new selected plans, two workers, HTTP status, health and isolated traffic passed\n", argv[1]); return 0;
}
