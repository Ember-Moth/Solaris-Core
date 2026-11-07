#include <solaris/core.h>

static int configuration_api(void)
{
    solaris_config_options_t options;
    solaris_config_options_init(&options);
    solaris_config_t *config = 0;
    solaris_diagnostics_t *diagnostics = 0;
    solaris_config_diagnostic_t diagnostic;
    solaris_error_t error;
    /* Malformed input exercises the installed compiler and copy-out ownership
     * contract even in builds that deliberately remove every outbound. */
    solaris_status_t status = solaris_config_compile_bytes("[", 1, &options,
        &config, &diagnostics, &error);
    int bad = status == SOLARIS_OK || config != 0 || error.code != status ||
        solaris_diagnostics_count(diagnostics) == 0 ||
        solaris_diagnostics_get(diagnostics, 0, &diagnostic) != SOLARIS_OK ||
        diagnostic.severity != SOLARIS_DIAGNOSTIC_ERROR;
    solaris_diagnostics_retain(diagnostics);
    solaris_diagnostics_release(diagnostics);
    solaris_diagnostics_release(diagnostics);
    solaris_config_release(config);
    return bad;
}

int main(void)
{
    if (configuration_api()) return 1;
    solaris_engine_t *engine = 0;
    solaris_engine_snapshot_t snapshot;
    uint64_t id;
    if (solaris_engine_create(0, 0, &engine, 0) != SOLARIS_OK) return 1;
    solaris_connection_list_t *connections = 0;
    solaris_log_snapshot_t *logs = 0;
    solaris_traffic_info_t traffic;
    solaris_log_info_t log_info;
    /* These APIs also work before any configuration or optional module exists.
     * Keep their owned results through destruction of the installed engine. */
    if (solaris_engine_get_connections(engine, 1, &connections, 0) != SOLARIS_OK ||
        solaris_connection_list_count(connections) != 0 ||
        solaris_engine_get_traffic(engine, &traffic, 0) != SOLARIS_OK ||
        traffic.logical[SOLARIS_FLOW_USER].active != 0 ||
        solaris_engine_get_logs(engine, 0, 1, &logs, 0) != SOLARIS_OK) return 1;
    int bad = solaris_engine_start(engine, &id, 0) != SOLARIS_OK ||
              solaris_engine_flush(engine, 5000u, 0) != SOLARIS_OK ||
              solaris_engine_stop(engine, &id, 0) != SOLARIS_OK ||
              solaris_engine_flush(engine, 5000u, 0) != SOLARIS_OK ||
              solaris_engine_get_snapshot(engine, &snapshot, 0) != SOLARIS_OK ||
              snapshot.state != SOLARIS_ENGINE_STOPPED ||
              snapshot.completed_operations != 2u;
    if (solaris_engine_cancel(engine, 0, 0) != SOLARIS_EINVAL) bad = 1;
    if (solaris_engine_destroy(engine, 0) != SOLARIS_OK) bad = 1;
    if (solaris_connection_list_count(connections) != 0 ||
        solaris_log_snapshot_get_info(logs, &log_info) != SOLARIS_OK || log_info.count != 0) bad = 1;
    solaris_connection_list_retain(connections);
    solaris_connection_list_release(connections);
    solaris_connection_list_release(connections);
    solaris_log_snapshot_retain(logs);
    solaris_log_snapshot_release(logs);
    solaris_log_snapshot_release(logs);
    return bad;
}
