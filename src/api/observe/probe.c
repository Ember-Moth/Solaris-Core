#include <solaris/probe.h>
#include "runtime/engine/internal.h"
#include "runtime/config/manager.h"
#include "observe/probe/http.h"
#include "observe/probe/http_codec.h"
#include "observe/log/service.h"
#include "api/common/error.h"
#include "solaris_builtin_modules.h"
#include <assert.h>
#include <string.h>
#include <uv.h>

typedef struct sdk_probe {
    solaris_engine_t *engine;
    solaris_runtime_operation_t *operation;
    solaris_config_admission_t *admission;
    solaris_tracker_t *tracker;
    solaris_log_service_t *log;
    solaris_executor_t *owner;
    solaris_probe_options_t options;
    solaris_probe_result_t result;
    solaris_probe_callback_t callback;
    void *context, *pem;
    char url[2049];
    uint64_t deadline_ns, operation_id;
    uv_mutex_t mutex;
    uv_work_t trust_work;
    solaris_tls_context_t *trust;
    solaris_status_t setup_status;
    solaris_scope_t scope;
    solaris_http_probe_t *probe;
    solaris_deferred_t cancel_node;
    solaris_control_completion_t ack_node;
    size_t owner_posts;
    int tls, cancelled, work_active, dispatched, scope_initialized, owner_done, cancel_queued, ack_posted;
} sdk_probe_t;

static void finish_control(void *context);
static void post_ack(sdk_probe_t *probe)
{
    solaris_status_t rc = solaris_runtime_control_post(probe->engine, &probe->ack_node);
    assert(rc == SOLARIS_OK);
    (void)rc;
}
static int ack_ready_locked(sdk_probe_t *probe)
{
    if (!probe->owner_done || probe->owner_posts || probe->ack_posted)
        return 0;
    probe->ack_posted = 1;
    return 1;
}
static void owner_finished(void *context)
{
    sdk_probe_t *probe = context;
    uv_mutex_lock(&probe->mutex);
    probe->owner_done = 1;
    int ack = ack_ready_locked(probe);
    uv_mutex_unlock(&probe->mutex);
    if (ack)
        post_ack(probe); /* last context access: control may dispose it */
}
static void owner_cancelled(void *context)
{
    sdk_probe_t *probe = context;
    if (probe->probe)
        (void)solaris_http_probe_cancel(probe->probe);
}
static void probe_done(void *context, solaris_http_probe_t *handle, const solaris_http_probe_result_t *result)
{
    sdk_probe_t *probe = context;
    (void)handle;
    probe->probe = NULL;
    probe->result.status = result->status;
    probe->result.http_status = result->http_status;
    probe->result.node_id = result->node_id;
    probe->result.connection_id = result->connection_id;
    probe->result.completed_ns = result->completed_ns;
    probe->result.bytes_written = result->bytes_written;
    probe->result.bytes_read = result->bytes_read;
    solaris_scope_cancel(&probe->scope);
}
static void cancel_on_owner(void *context)
{
    sdk_probe_t *probe = context;
    if (probe->scope_initialized && !probe->scope.finishing)
        solaris_scope_cancel(&probe->scope);
    uv_mutex_lock(&probe->mutex);
    assert(probe->owner_posts);
    --probe->owner_posts;
    int ack = ack_ready_locked(probe);
    uv_mutex_unlock(&probe->mutex);
    if (ack)
        post_ack(probe); /* no access after publishing the final ACK */
}
static void start_on_owner(void *context, solaris_status_t status)
{
    sdk_probe_t *probe = context;
    uv_mutex_lock(&probe->mutex);
    int cancelled = probe->cancelled;
    uv_mutex_unlock(&probe->mutex);
    if (cancelled || solaris_runtime_operation_cancelled(probe->operation))
        status = SOLARIS_ECANCELLED;
    if (status == SOLARIS_OK && solaris_executor_now_ns(probe->owner) >= probe->deadline_ns)
        status = SOLARIS_ETIMEDOUT;
    if (status != SOLARIS_OK) {
        probe->result.status = status;
        owner_finished(probe);
        return;
    }
    status = solaris_scope_init(&probe->scope, probe->owner, owner_cancelled, owner_finished, probe);
    if (status != SOLARIS_OK) {
        probe->result.status = status;
        owner_finished(probe);
        return;
    }
    probe->scope_initialized = 1;
    solaris_dial_plan_t plan = {0};
    uint32_t capabilities;
    status = solaris_config_admission_acquire_plan(probe->admission, probe->owner, probe->options.target_id, &plan,
                                                   &capabilities);
    if (status == SOLARIS_OK && !(capabilities & SOLARIS_OUTBOUND_STREAM))
        status = SOLARIS_ENOTSUP;
    if (status == SOLARIS_OK && solaris_runtime_operation_cancelled(probe->operation))
        status = SOLARIS_ECANCELLED;
    if (status == SOLARIS_OK) {
        probe->result.node_id = plan.node_id;
        solaris_http_probe_options_t options = {.url = probe->url,
                                                .timeout_ms = probe->options.timeout_ms,
                                                .trust = probe->trust,
                                                .tracker = probe->tracker,
                                                .parent_scope = &probe->scope,
                                                .deadline_ns = probe->deadline_ns,
                                                .config_revision = probe->result.config_revision};
        status = solaris_http_probe_start(probe->owner, &plan, &options, probe_done, probe, &probe->probe);
    }
    if (status != SOLARIS_OK) {
        (void)solaris_dial_plan_release(&plan);
        probe->result.status = status;
        solaris_scope_cancel(&probe->scope);
    }
}
static void dispatch_owner(sdk_probe_t *probe)
{
    uv_mutex_lock(&probe->mutex);
    int cancelled = probe->cancelled;
    probe->dispatched = 1;
    uv_mutex_unlock(&probe->mutex);
    solaris_status_t rc = cancelled ? SOLARIS_ECANCELLED : solaris_executor_post(probe->owner, start_on_owner, probe);
    if (rc != SOLARIS_OK) {
        probe->result.status = rc;
        owner_finished(probe);
    }
}
#if SOLARIS_HAS_TLS
static void prepare_trust(uv_work_t *work)
{
    sdk_probe_t *probe = work->data;
    probe->setup_status = solaris_tls_context_create(solaris_runtime_budget(probe->engine), probe->pem,
                                                     probe->options.trust_length, &probe->trust);
}
static void prepared_trust(uv_work_t *work, int status)
{
    sdk_probe_t *probe = work->data;
    probe->work_active = 0;
    uv_mutex_lock(&probe->mutex);
    int cancelled = probe->cancelled;
    uv_mutex_unlock(&probe->mutex);
    if (status == UV_ECANCELED || cancelled)
        probe->setup_status = SOLARIS_ECANCELLED;
    else if (solaris_executor_now_ns(probe->owner) >= probe->deadline_ns)
        probe->setup_status = SOLARIS_ETIMEDOUT;
    if (probe->setup_status == SOLARIS_OK)
        dispatch_owner(probe);
    else {
        probe->result.status = probe->setup_status;
        owner_finished(probe);
    }
}
#endif
static solaris_status_t start(void *context, solaris_engine_t *engine, solaris_runtime_operation_t *operation)
{
    sdk_probe_t *probe = context;
    probe->operation = operation;
    probe->operation_id = solaris_runtime_operation_id(operation);
    solaris_status_t rc = solaris_config_admission_acquire(engine, probe->options.config_revision, &probe->admission);
    if (rc != SOLARIS_OK)
        return rc;
    solaris_control_info_t info;
    rc = solaris_config_admission_get_state(probe->admission, &info);
    if (rc != SOLARIS_OK)
        return rc;
    probe->result.config_revision = info.config_revision;
    probe->result.selection_revision = info.selection_revision;
    probe->result.runtime_generation = info.runtime_generation;
    probe->owner = solaris_runtime_executor(engine, probe->options.target_id);
    if (!probe->owner)
        return SOLARIS_ECLOSED;
    probe->result.started_ns = solaris_executor_now_ns(probe->owner);
    uint64_t duration = probe->options.timeout_ms * UINT64_C(1000000);
    if (probe->result.started_ns > UINT64_MAX - duration)
        return SOLARIS_EOVERFLOW;
    probe->deadline_ns = probe->result.started_ns + duration;
    solaris_config_manager_t *manager = solaris_config_manager_find(engine);
    probe->tracker = solaris_config_manager_tracker(manager);
    probe->log = solaris_config_manager_log(manager);
#if SOLARIS_HAS_TLS
    if (probe->tls) {
        probe->trust_work.data = probe;
        int queued =
            uv_queue_work(solaris_runtime_control_loop(engine), &probe->trust_work, prepare_trust, prepared_trust);
        if (queued)
            return queued == UV_ENOMEM ? SOLARIS_ENOMEM : SOLARIS_EIO;
        probe->work_active = 1;
        return SOLARIS_OK;
    }
#endif
    dispatch_owner(probe);
    return SOLARIS_OK;
}
static void cancel(void *context)
{
    sdk_probe_t *probe = context;
    uv_mutex_lock(&probe->mutex);
    probe->cancelled = 1;
    int post = probe->dispatched && !probe->owner_done && !probe->cancel_queued;
    if (post) {
        probe->cancel_queued = 1;
        ++probe->owner_posts;
    }
    uv_mutex_unlock(&probe->mutex);
#if SOLARIS_HAS_TLS
    if (probe->work_active)
        (void)uv_cancel((uv_req_t *)&probe->trust_work);
#endif
    if (post) {
        solaris_status_t rc = solaris_executor_defer(probe->owner, &probe->cancel_node);
        assert(rc == SOLARIS_OK);
        (void)rc;
    }
}
static void finish_control(void *context)
{
    sdk_probe_t *probe = context;
    uv_mutex_lock(&probe->mutex);
    assert(probe->owner_done && !probe->owner_posts);
    uv_mutex_unlock(&probe->mutex);
#if SOLARIS_HAS_TLS
    solaris_tls_context_release(probe->trust);
    probe->trust = NULL;
#endif
    solaris_config_admission_release(probe->admission);
    probe->admission = NULL;
    solaris_runtime_operation_t *operation = probe->operation;
    probe->operation = NULL;
    solaris_runtime_operation_complete(operation, probe->result.status, 0);
}
static void complete(void *context, solaris_status_t status, uint64_t revision)
{
    sdk_probe_t *probe = context;
    assert(!revision);
    probe->result.status = status;
    if (!probe->result.completed_ns) {
        uint64_t now = probe->owner ? solaris_executor_now_ns(probe->owner) : uv_hrtime();
        if (!probe->result.started_ns)
            probe->result.started_ns = now;
        probe->result.completed_ns = status == SOLARIS_ETIMEDOUT && probe->deadline_ns ? probe->deadline_ns : now;
    }
    probe->result.duration_ns = probe->result.completed_ns >= probe->result.started_ns
                                    ? probe->result.completed_ns - probe->result.started_ns
                                    : 0;
    if (probe->log) {
        solaris_log_record_t record = {.level = status == SOLARIS_OK ? SOLARIS_LOG_INFO : SOLARIS_LOG_WARNING,
                                       .event = SOLARIS_LOG_PROBE,
                                       .status = status,
                                       .runtime_generation = probe->result.runtime_generation,
                                       .config_revision = probe->result.config_revision,
                                       .operation_id = probe->operation_id,
                                       .node_id = probe->result.node_id,
                                       .component = "probe"};
        solaris_log_service_emit(probe->log, &record);
    }
    probe->callback(probe->context, &probe->result);
}
static void dispose(void *context)
{
    sdk_probe_t *probe = context;
    assert(!probe->work_active);
#if SOLARIS_HAS_TLS
    solaris_tls_context_release(probe->trust);
#endif
    solaris_config_admission_release(probe->admission);
    if (probe->pem)
        for (size_t i = 0; i < probe->options.trust_length; ++i)
            ((volatile uint8_t *)probe->pem)[i] = 0;
    for (size_t i = 0; i < sizeof(probe->url); ++i)
        ((volatile uint8_t *)probe->url)[i] = 0;
    solaris_memory_free(probe->pem);
    uv_mutex_destroy(&probe->mutex);
    solaris_memory_free(probe);
}
void solaris_probe_options_init(solaris_probe_options_t *options)
{
    if (options) {
        memset(options, 0, sizeof(*options));
        options->timeout_ms = 5000;
    }
}
solaris_status_t solaris_engine_probe(solaris_engine_t *engine, const solaris_probe_options_t *options,
                                      solaris_probe_callback_t callback, void *context, uint64_t *operation_id,
                                      solaris_error_t *error)
{
    if (operation_id)
        *operation_id = 0;
    if (!engine || !options || !options->url || !options->target_id || !callback || !operation_id ||
        options->timeout_ms > UINT64_MAX / UINT64_C(1000000) || options->trust_length > 262144 ||
        (options->trust_length && !options->trust_pem))
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "invalid probe inputs");
    size_t length = 0;
    while (length <= 2048 && options->url[length])
        ++length;
    if (!length || length > 2048)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "probe URL is empty or oversized");
    solaris_budget_t *budget = solaris_runtime_budget(engine);
    solaris_http_probe_target_t target;
    solaris_buffer_t *validation = NULL;
    solaris_status_t rc = solaris_http_probe_request(budget, options->url, &target, &validation);
    solaris_buffer_release(validation);
    if (rc != SOLARIS_OK)
        return solaris_error_set(error, rc, 0, "invalid probe URL");
    if (target.tls && !options->trust_length)
        return solaris_error_set(error, SOLARIS_EINVAL, 0, "HTTPS probe requires explicit trust");
#if !SOLARIS_HAS_TLS
    if (target.tls)
        return solaris_error_set(error, SOLARIS_ENOTSUP, 0, "TLS is disabled in this build");
#endif
    sdk_probe_t *probe = solaris_memory_allocate(budget, sizeof(*probe));
    if (!probe)
        return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
    memset(probe, 0, sizeof(*probe));
    if (uv_mutex_init(&probe->mutex)) {
        solaris_memory_free(probe);
        return solaris_error_set(error, SOLARIS_EIO, 0, NULL);
    }
    probe->engine = engine;
    probe->options = *options;
    probe->tls = target.tls;
    probe->callback = callback;
    probe->context = context;
    probe->result.target_id = options->target_id;
    if (!probe->options.timeout_ms)
        probe->options.timeout_ms = 5000;
    memcpy(probe->url, options->url, length + 1);
    probe->options.url = probe->url;
    probe->ack_node = (solaris_control_completion_t){.run = finish_control, .context = probe};
    probe->cancel_node = (solaris_deferred_t){.run = cancel_on_owner, .context = probe};
    if (options->trust_length) {
        probe->pem = solaris_memory_allocate(budget, options->trust_length);
        if (!probe->pem) {
            dispose(probe);
            return solaris_error_set(error, SOLARIS_ENOMEM, 0, NULL);
        }
        memcpy(probe->pem, options->trust_pem, options->trust_length);
        probe->options.trust_pem = probe->pem;
    }
    solaris_runtime_request_t request = {.operation = SOLARIS_OPERATION_PROBE,
                                         .requires_running = 1,
                                         .context = probe,
                                         .start = start,
                                         .cancel = cancel,
                                         .complete = complete,
                                         .dispose = dispose};
    rc = solaris_runtime_request_submit(engine, &request, operation_id, error);
    if (rc != SOLARIS_OK)
        dispose(probe);
    return rc;
}
