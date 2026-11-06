#include <solaris/core.h>
#include <stdio.h>
#include <string.h>

static unsigned int completed;
static int invalid_event;

static void event_cb(void *context, const solaris_event_t *event)
{
    (void)context;
    completed++;
    if (event->operation_id != completed || event->status != SOLARIS_OK) {
        invalid_event = 1;
    }
}

int main(void)
{
    solaris_engine_t *engine = NULL;
    solaris_error_t error;
    solaris_host_t host = {NULL, event_cb};
    solaris_engine_snapshot_t snapshot;
    uint64_t id;
    if (strlen(solaris_version_string()) == 0u ||
        solaris_engine_create(NULL, &host, &engine, &error) != SOLARIS_OK) return 1;
    int failed =
        solaris_engine_get_snapshot(engine, &snapshot, &error) != SOLARIS_OK ||
        snapshot.state != SOLARIS_ENGINE_IDLE || snapshot.io_workers != 1u ||
        solaris_engine_start(engine, &id, &error) != SOLARIS_OK || id != 1u ||
        solaris_engine_flush(engine, 5000u, &error) != SOLARIS_OK ||
        solaris_engine_get_snapshot(engine, &snapshot, &error) != SOLARIS_OK ||
        snapshot.state != SOLARIS_ENGINE_RUNNING ||
        solaris_engine_stop(engine, &id, &error) != SOLARIS_OK || id != 2u ||
        solaris_engine_flush(engine, 5000u, &error) != SOLARIS_OK ||
        solaris_engine_get_snapshot(engine, &snapshot, &error) != SOLARIS_OK ||
        snapshot.state != SOLARIS_ENGINE_STOPPED || snapshot.pending_operations != 0u ||
        completed != 2u || invalid_event;
    if (solaris_engine_destroy(engine, &error) != SOLARIS_OK) failed = 1;
    if (failed) fprintf(stderr, "Solaris SDK lifecycle smoke failed\n");
    return failed;
}
