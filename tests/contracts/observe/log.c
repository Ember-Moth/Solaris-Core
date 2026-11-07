#include "observe/log/service.h"
#include "support/runtime/event.h"
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
typedef struct writer {
    solaris_log_service_t *service;
    unsigned index;
} writer_t;
static void write_records(void *context)
{
    writer_t *writer = context;
    for (unsigned i = 0; i < 128; ++i) {
        solaris_log_record_t record = {.level = SOLARIS_LOG_INFO,
                                       .event = SOLARIS_LOG_CONTROL,
                                       .operation_id = writer->index * 128u + i + 1u,
                                       .component = "control"};
        solaris_log_service_emit(writer->service, &record);
    }
}
int main(void)
{
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(1048576, NULL, &budget) == SOLARIS_OK);
    solaris_log_service_t *service;
    CHECK(solaris_log_service_create(budget, &service) == SOLARIS_OK);
    for (unsigned i = 0; i < 300; ++i) {
        solaris_log_record_t record = {
            .level = SOLARIS_LOG_INFO, .event = SOLARIS_LOG_CONTROL, .operation_id = i + 1, .component = "control"};
        solaris_log_service_emit(service, &record);
    }
    solaris_log_snapshot_t *snapshot;
    CHECK(solaris_log_service_snapshot(service, 0, 2, &snapshot) == SOLARIS_OK);
    solaris_log_info_t info;
    CHECK(solaris_log_snapshot_get_info(snapshot, &info) == SOLARIS_OK);
    CHECK(info.count == 2 && info.oldest_sequence == 45 && info.latest_sequence == 300 && info.cursor == 46);
    CHECK(info.overwritten == 44 && info.missed == 44 && !info.dropped);
    solaris_log_record_t record;
    CHECK(solaris_log_snapshot_get_record(snapshot, 0, &record) == SOLARIS_OK && record.sequence == 45);
    solaris_log_snapshot_release(snapshot);
    solaris_diagnostic_sink_t sink = solaris_log_service_diagnostic(service);
    const uint8_t secret[] = "password=SECRET-CREDENTIAL Authorization: private";
    sink.report(sink.context, "anytls", SOLARIS_EACCESS, secret, sizeof(secret) - 1);
    sink.report(sink.context, "SECRET-COMPONENT", SOLARIS_EACCESS, secret, sizeof(secret) - 1);
    record = (solaris_log_record_t){.level = 99, .event = SOLARIS_LOG_CONTROL};
    solaris_log_service_emit(service, &record);
    CHECK(solaris_log_service_snapshot(service, 300, 0, &snapshot) == SOLARIS_OK);
    CHECK(solaris_log_snapshot_get_info(snapshot, &info) == SOLARIS_OK && info.count == 2 && info.dropped == 1);
    CHECK(solaris_log_snapshot_get_record(snapshot, 0, &record) == SOLARIS_OK && !strcmp(record.component, "anytls"));
    CHECK(solaris_log_snapshot_get_record(snapshot, 1, &record) == SOLARIS_OK && !strcmp(record.component, "module"));
    CHECK(!strstr(record.component, "SECRET"));
    solaris_log_snapshot_release(snapshot);
    writer_t writers[8];
    uv_thread_t threads[8];
    for (unsigned i = 0; i < 8; ++i) {
        writers[i] = (writer_t){service, i};
        CHECK(!uv_thread_create(&threads[i], write_records, &writers[i]));
    }
    for (unsigned i = 0; i < 32; ++i) {
        CHECK(solaris_log_service_snapshot(service, 0, 17, &snapshot) == SOLARIS_OK);
        CHECK(solaris_log_snapshot_get_info(snapshot, &info) == SOLARIS_OK && info.count <= 17);
        uint64_t previous = 0;
        for (size_t j = 0; j < info.count; ++j) {
            CHECK(solaris_log_snapshot_get_record(snapshot, j, &record) == SOLARIS_OK);
            CHECK(record.sequence > previous && record.monotonic_time_ns);
            previous = record.sequence;
        }
        CHECK(!info.count || previous == info.cursor);
        solaris_log_snapshot_release(snapshot);
    }
    for (unsigned i = 0; i < 8; ++i)
        CHECK(!uv_thread_join(&threads[i]));
    solaris_log_service_stop(service, 1);
    record = (solaris_log_record_t){.level = SOLARIS_LOG_INFO, .event = SOLARIS_LOG_PROBE, .component = "probe"};
    solaris_log_service_emit(service, &record);
    CHECK(solaris_log_service_drained(service));
    CHECK(solaris_log_service_snapshot(service, 0, SIZE_MAX, &snapshot) == SOLARIS_OK);
    CHECK(solaris_log_snapshot_get_info(snapshot, &info) == SOLARIS_OK && info.count == 256 &&
          info.latest_sequence == 1327);
    solaris_log_snapshot_retain(snapshot);
    solaris_log_service_destroy(service);
    CHECK(!solaris_budget_used(budget));
    solaris_budget_release(budget);
    CHECK(solaris_log_snapshot_get_record(snapshot, info.count - 1, &record) == SOLARIS_OK &&
          !strcmp(record.component, "probe"));
    solaris_log_snapshot_release(snapshot);
    solaris_log_snapshot_release(snapshot);
    CHECK(solaris_log_service_snapshot(NULL, 100, 0, &snapshot) == SOLARIS_OK);
    CHECK(solaris_log_snapshot_get_info(snapshot, &info) == SOLARIS_OK && !info.count && info.cursor == 100);
    solaris_log_snapshot_release(snapshot);
    puts("Bounded logs: ordered cursor/eviction, concurrent writers, secret suppression and independent snapshots "
         "passed");
    return 0;
}
