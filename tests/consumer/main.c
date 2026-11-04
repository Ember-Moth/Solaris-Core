#include <solaris/core.h>

int main(void)
{
    solaris_engine_t *engine = 0;
    solaris_engine_snapshot_t snapshot;
    uint64_t id;
    if (solaris_engine_create(0, 0, &engine, 0) != SOLARIS_OK) return 1;
    int bad = solaris_engine_start(engine, &id, 0) != SOLARIS_OK ||
              solaris_engine_flush(engine, 5000u, 0) != SOLARIS_OK ||
              solaris_engine_stop(engine, &id, 0) != SOLARIS_OK ||
              solaris_engine_flush(engine, 5000u, 0) != SOLARIS_OK ||
              solaris_engine_get_snapshot(engine, &snapshot, 0) != SOLARIS_OK ||
              snapshot.state != SOLARIS_ENGINE_STOPPED ||
              snapshot.completed_operations != 2u;
    if (solaris_engine_destroy(engine, 0) != SOLARIS_OK) bad = 1;
    return bad;
}
