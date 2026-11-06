#include "adapters/inbound/proxy/internal.h"
#include <assert.h>

static void finish(proxy_connection_t *c, solaris_status_t status)
{
    solaris_io_done_fn done = c->upgrade_done;
    void *context = c->upgrade_context;
    c->upgrade_done = NULL;
    c->upgrade_context = NULL;
    solaris_buffer_release(c->upgrade_output);
    c->upgrade_output = NULL;
    c->upgrade_offset = 0;
    int close_after = 0;
    if (status == SOLARIS_OK && !c->scope.cancelled) {
        int state = solaris_http_upgrade_response_state(c->upgrade);
        if (state != SOLARIS_HTTP_UPGRADE_PENDING) {
            c->upgrade_settled = 1;
            c->activity_ns = solaris_executor_now_ns(c->scope.owner);
            if (state == SOLARIS_HTTP_UPGRADE_ACCEPTED)
                c->http_upgraded = 1;
            else {
                c->input_length = 0;
                close_after = solaris_http_upgrade_response_complete(c->upgrade);
            }
        }
    }
    done(context, status);
    if (status != SOLARIS_OK || close_after)
        solaris_proxy_cancel(c, status);
    solaris_proxy_schedule(c);
    solaris_scope_release(&c->scope);
}
static void wrote(void *context, solaris_status_t status)
{
    proxy_connection_t *c = context;
    c->upgrade_writing = 0;
    if (status != SOLARIS_OK)
        finish(c, status);
    else
        solaris_proxy_upgrade_pump(c);
}
void solaris_proxy_upgrade_pump(proxy_connection_t *c)
{
    if (!c->upgrade_done || c->upgrade_writing)
        return;
    if (c->scope.cancelled || !c->native) {
        finish(c, SOLARIS_ECANCELLED);
        return;
    }
    if (!c->upgrade_output || c->upgrade_offset == solaris_buffer_length(c->upgrade_output)) {
        finish(c, SOLARIS_OK);
        return;
    }
    solaris_io_snapshot_t stats;
    solaris_status_t rc = solaris_stream_get_snapshot(c->native, &stats);
    if (rc != SOLARIS_OK) {
        finish(c, rc);
        return;
    }
    size_t length = solaris_buffer_length(c->upgrade_output) - c->upgrade_offset;
    if (stats.max_message_bytes && length > stats.max_message_bytes)
        length = stats.max_message_bytes;
    solaris_slice_t slice = {c->upgrade_output, c->upgrade_offset, length};
    rc = solaris_stream_write(c->native, &slice, wrote, c);
    if (rc == SOLARIS_OK) {
        c->upgrade_writing = 1;
        c->upgrade_offset += length;
    } else if (rc != SOLARIS_EAGAIN)
        finish(c, rc);
}
solaris_status_t solaris_proxy_upgrade_write(proxy_connection_t *c, const solaris_slice_t *data,
                                             solaris_io_done_fn done, void *context)
{
    if (c->upgrade_done)
        return SOLARIS_EAGAIN;
    assert(!c->upgrade_output);
    int pending = solaris_http_upgrade_response_state(c->upgrade) == SOLARIS_HTTP_UPGRADE_PENDING;
    solaris_status_t rc = solaris_http_upgrade_response_feed(
        c->upgrade, solaris_buffer_data(data->buffer) + data->offset, data->length, &c->upgrade_output);
    if (rc != SOLARIS_OK) {
        c->inbound->stats.protocol_failed++;
        if (pending)
            solaris_proxy_http_error(c, 502);
        return rc;
    }
    c->upgrade_done = done;
    c->upgrade_context = context;
    solaris_scope_retain(&c->scope);
    solaris_proxy_schedule(c);
    return SOLARIS_OK;
}
