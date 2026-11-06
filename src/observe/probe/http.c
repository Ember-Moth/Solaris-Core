#include "observe/probe/http.h"
#include "observe/probe/http_codec.h"
#include "solaris_builtin_modules.h"
#include <assert.h>
#include <string.h>

struct solaris_http_probe {
    solaris_scope_t scope;
    solaris_stream_t *stream;
    solaris_deadline_t *deadline;
    solaris_dial_plan_t plan;
    solaris_buffer_t *request;
    solaris_tls_context_t *trust;
    solaris_select_control_t *health;
    solaris_http_probe_target_t target;
    solaris_http_probe_result_t result;
    solaris_http_probe_fn done;
    void *context;
    uint64_t deadline_ns, token;
    uint8_t header[SOLARIS_HTTP_PROBE_HEADER_LIMIT];
    size_t header_length;
    unsigned int informational;
    int accepted, settled, write_pending, write_done, response_ready;
};
static void decide(solaris_http_probe_t *probe, solaris_status_t status)
{
    if (probe->settled) return;
    uint64_t now = solaris_executor_now_ns(probe->scope.owner);
    if (status != SOLARIS_ECANCELLED && now >= probe->deadline_ns) status = SOLARIS_ETIMEDOUT;
    probe->settled = 1; probe->result.status = status; probe->result.completed_ns = now;
    probe->result.duration_ns = now >= probe->result.started_ns ? now - probe->result.started_ns : 0u;
}
static void cancelled(void *context)
{
    solaris_http_probe_t *probe = context;
    decide(probe, SOLARIS_ECANCELLED);
    if (probe->stream != NULL) (void)solaris_stream_close(probe->stream);
    if (probe->deadline != NULL) solaris_deadline_cancel(probe->deadline);
}
static void settle(solaris_http_probe_t *probe, solaris_status_t status)
{ decide(probe, status); solaris_scope_cancel(&probe->scope); }
static void destroyed(void *context)
{
    solaris_http_probe_t *probe = context; assert(probe->stream == NULL && probe->deadline == NULL && !probe->write_pending);
    if (probe->plan.outbound != NULL) { solaris_status_t rc = solaris_dial_plan_release(&probe->plan); assert(rc == SOLARIS_OK); (void)rc; }
    if (probe->token != 0u) {
        solaris_status_t health = probe->result.status;
        if (!probe->accepted || health == SOLARIS_ECLOSED || health == SOLARIS_ENOMEM || health == SOLARIS_EAGAIN) health = SOLARIS_ECANCELLED;
        (void)solaris_select_probe_finish(probe->health, probe->result.node_id, probe->token, health,
            probe->result.completed_ns, probe->result.duration_ns);
    }
    solaris_select_control_release(probe->health);
#if SOLARIS_HAS_TLS
    solaris_tls_context_release(probe->trust);
#endif
    solaris_buffer_release(probe->request);
    if (probe->accepted) probe->done(probe->context, probe, &probe->result);
    solaris_memory_free(probe);
}
static void deadline(void *context, solaris_status_t status)
{
    solaris_http_probe_t *probe = context; probe->deadline = NULL;
    if (status == SOLARIS_OK) settle(probe, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&probe->scope);
}
static void maybe_complete(solaris_http_probe_t *probe)
{
    if (probe->write_done && probe->response_ready && !probe->settled)
        settle(probe, probe->result.http_status >= 200u && probe->result.http_status < 400u ? SOLARIS_OK : SOLARIS_EIO);
}
static void written(void *context, solaris_status_t status)
{
    solaris_http_probe_t *probe = context; probe->write_pending = 0;
    if (status == SOLARIS_OK) { probe->write_done = 1; probe->result.bytes_written = solaris_buffer_length(probe->request); }
    if (!probe->settled) {
        if (status != SOLARIS_OK) settle(probe, status); else maybe_complete(probe);
    }
    solaris_scope_release(&probe->scope);
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    solaris_http_probe_t *probe = context; if (probe->settled) return;
    if (solaris_executor_now_ns(probe->scope.owner) >= probe->deadline_ns) { settle(probe, SOLARIS_ETIMEDOUT); return; }
    if (status != SOLARIS_OK) { settle(probe, status); return; }
    solaris_slice_t slice = {probe->request, 0u, solaris_buffer_length(probe->request)};
    solaris_status_t rc = solaris_stream_write(stream, &slice, written, probe);
    if (rc == SOLARIS_OK) { probe->write_pending = 1; solaris_scope_retain(&probe->scope); }
    else settle(probe, rc);
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    solaris_http_probe_t *probe = context; if (probe->settled || probe->response_ready) return;
    if (solaris_executor_now_ns(probe->scope.owner) >= probe->deadline_ns) { settle(probe, SOLARIS_ETIMEDOUT); return; }
    size_t length = solaris_buffer_length(buffer); probe->result.bytes_read += length;
    const uint8_t *bytes = solaris_buffer_data(buffer);
    for (size_t i = 0u; i < length; ++i) {
        if (probe->header_length == sizeof(probe->header)) { settle(probe, SOLARIS_EMSGSIZE); return; }
        probe->header[probe->header_length++] = bytes[i];
        if (probe->header_length < 4u || memcmp(probe->header + probe->header_length - 4u, "\r\n\r\n", 4u) != 0) continue;
        uint16_t code; solaris_status_t rc = solaris_http_probe_response(probe->header, probe->header_length, &code);
        if (rc != SOLARIS_OK) { settle(probe, rc); return; }
        if (code < 200u && code != 101u) {
            if (++probe->informational > 4u) { settle(probe, SOLARIS_EIO); return; }
            probe->header_length = 0u; continue;
        }
        probe->result.http_status = code; probe->response_ready = 1;
        (void)solaris_stream_set_reading(stream, 0); maybe_complete(probe); return;
    }
}
static void eof(void *context, solaris_stream_t *stream)
{ (void)stream; solaris_http_probe_t *probe = context; if (!probe->settled && !probe->response_ready) settle(probe, SOLARIS_EIO); }
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    (void)stream; solaris_http_probe_t *probe = context; probe->stream = NULL;
    if (!probe->settled) {
        if (probe->response_ready && probe->write_done) maybe_complete(probe);
        else settle(probe, status == SOLARIS_OK ? SOLARIS_EIO : status);
    }
    solaris_scope_release(&probe->scope);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, eof, NULL, closed};
#if SOLARIS_HAS_TLS
static solaris_status_t carrier_open(void *context, solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_callbacks_t *cb, void *user, solaris_stream_t **out)
{
    (void)options; solaris_http_probe_t *probe = context; assert(owner == probe->scope.owner);
    return solaris_outbound_open_stream(probe->plan.outbound, peer, cb, user, out);
}
#endif
solaris_status_t solaris_http_probe_start(solaris_executor_t *owner, solaris_dial_plan_t *source,
    const solaris_http_probe_options_t *options, solaris_http_probe_fn done, void *context, solaris_http_probe_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || source == NULL || source->outbound == NULL || source->release == NULL || source->node_id == 0u ||
        options == NULL || done == NULL || options->timeout_ms == 0u || options->timeout_ms > UINT64_MAX / UINT64_C(1000000)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner) || source->outbound->owner != owner) return SOLARIS_ETHREAD;
    uint32_t caps; solaris_status_t rc = solaris_outbound_capabilities(source->outbound, &caps);
    if (rc != SOLARIS_OK || !(caps & SOLARIS_OUTBOUND_STREAM)) return SOLARIS_ENOTSUP;
    solaris_http_probe_t *probe = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*probe));
    if (probe == NULL) return SOLARIS_ENOMEM;
    memset(probe, 0, sizeof(*probe)); probe->done = done; probe->context = context;
    rc = solaris_http_probe_request(solaris_executor_budget(owner), options->url, &probe->target, &probe->request);
    if (rc == SOLARIS_OK && probe->target.address.family == SOLARIS_ADDRESS_DOMAIN && !(caps & SOLARIS_OUTBOUND_STREAM_DOMAIN)) rc = SOLARIS_ENOTSUP;
    if (rc == SOLARIS_OK && probe->target.tls) {
#if SOLARIS_HAS_TLS
        if (options->trust == NULL) rc = SOLARIS_EINVAL;
#else
        rc = SOLARIS_ENOTSUP;
#endif
    }
    uint64_t now = solaris_executor_now_ns(owner), duration = options->timeout_ms * UINT64_C(1000000);
    if (rc == SOLARIS_OK && now > UINT64_MAX - duration) rc = SOLARIS_EOVERFLOW;
    if (rc != SOLARIS_OK) { solaris_buffer_release(probe->request); solaris_memory_free(probe); return rc; }
    probe->result = (solaris_http_probe_result_t){.node_id = source->node_id, .selection_revision = source->selection_revision, .started_ns = now};
    probe->deadline_ns = now + duration; probe->health = options->health; solaris_select_control_retain(probe->health);
#if SOLARIS_HAS_TLS
    if (probe->target.tls) { probe->trust = options->trust; solaris_tls_context_retain(probe->trust); }
#endif
    rc = solaris_scope_init(&probe->scope, owner, cancelled, destroyed, probe);
    if (rc != SOLARIS_OK) { destroyed(probe); return rc; }
    solaris_scope_retain(&probe->scope);
    rc = solaris_deadline_start(owner, options->timeout_ms, deadline, probe, &probe->deadline);
    if (rc != SOLARIS_OK) { solaris_scope_release(&probe->scope); settle(probe, rc); return rc; }
    if (probe->health != NULL) {
        rc = solaris_select_probe_begin(probe->health, source->node_id, &probe->token);
        if (rc != SOLARIS_OK) { settle(probe, rc); return rc; }
    }
    if (options->tracker != NULL) {
        solaris_observe_options_t observe = {.kind = SOLARIS_FLOW_STREAM, .purpose = SOLARIS_FLOW_PROBE, .target = probe->target.address};
        solaris_dial_plan_t candidate = *source;
        rc = solaris_observe_plan(options->tracker, &candidate, &observe, &probe->plan, &probe->result.connection_id);
        if (rc != SOLARIS_OK) { settle(probe, rc); return rc; }
    } else probe->plan = *source;
    memset(source, 0, sizeof(*source)); probe->accepted = 1; *out = probe;
#if SOLARIS_HAS_TLS
    if (probe->target.tls) {
        solaris_stream_factory_t carrier = {.context = probe, .open = carrier_open};
        solaris_dialer_options_t dialer = {.pending_byte_limit = 4096u, .pending_request_limit = 1u, .read_chunk_size = 4096u, .open_timeout_ms = options->timeout_ms};
        rc = solaris_tls_open(owner, probe->trust, probe->target.identity, SOLARIS_TLS_1_2, &carrier, &dialer,
            &probe->target.address, &callbacks, probe, &probe->stream);
    } else
#endif
        rc = solaris_outbound_open_stream(probe->plan.outbound, &probe->target.address, &callbacks, probe, &probe->stream);
    if (rc == SOLARIS_OK) solaris_scope_retain(&probe->scope);
    else settle(probe, rc);
    return SOLARIS_OK;
}
solaris_status_t solaris_http_probe_cancel(solaris_http_probe_t *probe)
{
    if (probe == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(probe->scope.owner)) return SOLARIS_ETHREAD;
    settle(probe, SOLARIS_ECANCELLED); return SOLARIS_OK;
}
