#include "observe/log/service.h"
#include "runtime/config/manager.h"
#include "runtime/executor/executor.h"
#include "api/common/error.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
enum { LOG_CAPACITY = 256 };
struct solaris_log_service {
    uv_mutex_t mutex;
    uint64_t sequence, overwritten, dropped;
    size_t head, count;
    solaris_log_record_t records[LOG_CAPACITY];
};
struct solaris_log_snapshot {
    atomic_size_t references;
    solaris_log_info_t info;
    solaris_log_record_t records[];
};
static const char *safe_component(const char *component)
{
    static const char *const names[] = {"runtime", "config", "control", "probe",       "proxy",
                                        "route",   "tls",    "anytls",  "shadowsocks", "vless",
                                        "socks5",  "direct", "block",   "transport",   "module"};
    if (component)
        for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i) {
            size_t n = strlen(names[i]), j = 0;
            while (j < n && component[j] == names[i][j])
                ++j;
            if (j == n && component[j] == 0)
                return names[i];
        }
    return "module";
}
solaris_status_t solaris_log_service_create(solaris_budget_t *budget, solaris_log_service_t **out)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!budget)
        return SOLARIS_EINVAL;
    solaris_log_service_t *service = solaris_memory_allocate(budget, sizeof(*service));
    if (!service)
        return SOLARIS_ENOMEM;
    memset(service, 0, sizeof(*service));
    if (uv_mutex_init(&service->mutex)) {
        solaris_memory_free(service);
        return SOLARIS_EIO;
    }
    *out = service;
    return SOLARIS_OK;
}
void solaris_log_service_stop(solaris_log_service_t *service, int destroy)
{
    /* Synchronous writers own no queued work. Keep recording terminal events
     * while the manager drains producers; only destroy ends ring lifetime. */
    (void)service;
    (void)destroy;
}
int solaris_log_service_drained(solaris_log_service_t *service)
{
    if (service) {
        uv_mutex_lock(&service->mutex);
        uv_mutex_unlock(&service->mutex);
    }
    return 1;
}
void solaris_log_service_destroy(solaris_log_service_t *service)
{
    if (service) {
        uv_mutex_destroy(&service->mutex);
        solaris_memory_free(service);
    }
}
void solaris_log_service_emit(solaris_log_service_t *service, const solaris_log_record_t *input)
{
    if (!service || !input)
        return;
    uv_mutex_lock(&service->mutex);
    if (service->sequence == UINT64_MAX || input->event < SOLARIS_LOG_DIAGNOSTIC || input->event > SOLARIS_LOG_PROBE ||
        input->level < SOLARIS_LOG_INFO || input->level > SOLARIS_LOG_ERROR) {
        if (service->dropped != UINT64_MAX)
            ++service->dropped;
        uv_mutex_unlock(&service->mutex);
        return;
    }
    size_t index;
    if (service->count == LOG_CAPACITY) {
        index = service->head;
        service->head = (service->head + 1) % LOG_CAPACITY;
        if (service->overwritten != UINT64_MAX)
            ++service->overwritten;
    } else {
        index = (service->head + service->count) % LOG_CAPACITY;
        ++service->count;
    }
    solaris_log_record_t *record = &service->records[index];
    memset(record, 0, sizeof(*record));
    record->sequence = ++service->sequence;
    record->monotonic_time_ns = uv_hrtime();
    record->runtime_generation = input->runtime_generation;
    record->config_revision = input->config_revision;
    record->operation_id = input->operation_id;
    record->node_id = input->node_id;
    record->event = input->event;
    record->level = input->level;
    record->status = input->status;
    const char *component = safe_component(input->component);
    memcpy(record->component, component, strlen(component) + 1);
    uv_mutex_unlock(&service->mutex);
}
static void diagnostic(void *context, const char *component, solaris_status_t status, const uint8_t *message,
                       size_t length)
{
    (void)message;
    (void)length; /* Peer content may contain credentials: never inspect or copy it. */
    solaris_log_record_t record = {.level = SOLARIS_LOG_WARNING, .event = SOLARIS_LOG_DIAGNOSTIC, .status = status};
    solaris_executor_t *owner = solaris_executor_current();
    if (owner)
        record.runtime_generation = solaris_executor_generation(owner);
    const char *safe = safe_component(component);
    memcpy(record.component, safe, strlen(safe) + 1);
    solaris_log_service_emit(context, &record);
}
solaris_diagnostic_sink_t solaris_log_service_diagnostic(solaris_log_service_t *service)
{
    return (solaris_diagnostic_sink_t){.context = service, .report = service ? diagnostic : NULL};
}
solaris_status_t solaris_log_service_snapshot(solaris_log_service_t *service, uint64_t after, size_t maximum,
                                              solaris_log_snapshot_t **out)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    size_t capacity = !maximum || maximum > LOG_CAPACITY ? LOG_CAPACITY : maximum;
    if (!service)
        capacity = 0;
    /* Owned public copies cannot retain an engine's injected allocator context
     * after engine_destroy has released that context. */
    solaris_log_snapshot_t *snapshot = calloc(1, sizeof(*snapshot) + capacity * sizeof(*snapshot->records));
    if (!snapshot)
        return SOLARIS_ENOMEM;
    atomic_init(&snapshot->references, 1);
    snapshot->info.cursor = after;
    if (service) {
        uv_mutex_lock(&service->mutex);
        snapshot->info.latest_sequence = service->sequence;
        snapshot->info.oldest_sequence = service->count ? service->records[service->head].sequence : 0;
        snapshot->info.overwritten = service->overwritten;
        snapshot->info.dropped = service->dropped;
        if (snapshot->info.oldest_sequence && after < snapshot->info.oldest_sequence - 1)
            snapshot->info.missed = snapshot->info.oldest_sequence - 1 - after;
        for (size_t i = 0; i < service->count && snapshot->info.count < capacity; ++i) {
            const solaris_log_record_t *record = &service->records[(service->head + i) % LOG_CAPACITY];
            if (record->sequence <= after)
                continue;
            snapshot->records[snapshot->info.count++] = *record;
            snapshot->info.cursor = record->sequence;
        }
        uv_mutex_unlock(&service->mutex);
    }
    *out = snapshot;
    return SOLARIS_OK;
}
solaris_status_t solaris_engine_get_logs(solaris_engine_t *engine, uint64_t after, size_t maximum,
                                         solaris_log_snapshot_t **out, solaris_error_t *error)
{
    if (out)
        *out = NULL;
    if (!engine || !out)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, NULL);
    solaris_config_manager_t *manager = solaris_config_manager_find(engine);
    solaris_status_t status =
        solaris_log_service_snapshot(manager ? solaris_config_manager_log(manager) : NULL, after, maximum, out);
    return solaris_error_set(error, status, 0, NULL);
}
void solaris_log_snapshot_retain(solaris_log_snapshot_t *snapshot)
{
    if (snapshot)
        atomic_fetch_add_explicit(&snapshot->references, 1, memory_order_relaxed);
}
void solaris_log_snapshot_release(solaris_log_snapshot_t *snapshot)
{
    if (snapshot && atomic_fetch_sub_explicit(&snapshot->references, 1, memory_order_acq_rel) == 1)
        free(snapshot);
}
solaris_status_t solaris_log_snapshot_get_info(const solaris_log_snapshot_t *snapshot, solaris_log_info_t *out)
{
    if (!snapshot || !out)
        return SOLARIS_EINVAL;
    *out = snapshot->info;
    return SOLARIS_OK;
}
solaris_status_t solaris_log_snapshot_get_record(const solaris_log_snapshot_t *snapshot, size_t index,
                                                 solaris_log_record_t *out)
{
    if (!snapshot || !out || index >= snapshot->info.count)
        return SOLARIS_EINVAL;
    *out = snapshot->records[index];
    return SOLARIS_OK;
}
