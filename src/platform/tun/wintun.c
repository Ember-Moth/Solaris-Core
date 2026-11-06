#include "platform/tun/internal.h"
#include <assert.h>
#include <string.h>

typedef struct wintun_device {
    solaris_tun_device_t device;
    solaris_wintun_api_t api;
    uv_async_t async;
    uv_timer_t retry;
    uv_thread_t thread;
    uv_mutex_t mutex;
    uv_cond_t resume;
    solaris_status_t wait_status;
    int async_initialized, retry_initialized, thread_started;
    int stopping, awaiting, exited;
} wintun_device_t;
static void worker(void *context)
{
    wintun_device_t *w = context;
    for (;;) {
        solaris_status_t status = w->api.wait(w->api.context);
        uv_mutex_lock(&w->mutex);
        if (w->stopping) { w->exited = 1; (void)uv_async_send(&w->async); uv_mutex_unlock(&w->mutex); return; }
        w->wait_status = status; w->awaiting = 1;
        (void)uv_async_send(&w->async);
        while (w->awaiting && !w->stopping) uv_cond_wait(&w->resume, &w->mutex);
        if (w->stopping) { w->exited = 1; (void)uv_async_send(&w->async); uv_mutex_unlock(&w->mutex); return; }
        uv_mutex_unlock(&w->mutex);
    }
}
static void handle_closed(uv_handle_t *handle)
{ wintun_device_t *w = handle->data; solaris_scope_release(&w->device.scope); }
static void close_handles(wintun_device_t *w)
{
    if (w->retry_initialized && !uv_is_closing((uv_handle_t *)&w->retry)) {
        (void)uv_timer_stop(&w->retry); uv_close((uv_handle_t *)&w->retry, handle_closed);
    }
    uv_mutex_lock(&w->mutex); int exited = w->exited; uv_mutex_unlock(&w->mutex);
    if ((!w->thread_started || exited) && w->async_initialized && !uv_is_closing((uv_handle_t *)&w->async))
        uv_close((uv_handle_t *)&w->async, handle_closed);
}
static void schedule(solaris_tun_device_t *d)
{ wintun_device_t *w = (wintun_device_t *)d; if (!d->closing) (void)uv_async_send(&w->async); }
static void retry(uv_timer_t *timer) { wintun_device_t *w = timer->data; schedule(&w->device); }
static void flush(wintun_device_t *w)
{
    solaris_tun_device_t *d = &w->device;
    for (unsigned int count = 0u; count < 32u && !d->closing && d->head != NULL; ++count) {
        solaris_status_t status = SOLARIS_OK;
        uint8_t *packet = w->api.allocate(w->api.context, d->head->length, &status);
        if (packet == NULL) {
            if (status == SOLARIS_EAGAIN) {
                if (uv_timer_start(&w->retry, retry, 1u, 0u) != 0) solaris_tun_device_fail(d, SOLARIS_EIO);
                return;
            }
            solaris_tun_device_fail(d, status == SOLARIS_OK ? SOLARIS_EIO : status); return;
        }
        memcpy(packet, d->head->data, d->head->length); w->api.send(w->api.context, packet); solaris_tun_device_pop(d);
    }
    solaris_tun_device_writable(d);
    if (!d->closing && d->head != NULL) schedule(d);
}
static void ready(uv_async_t *handle)
{
    wintun_device_t *w = handle->data; solaris_tun_device_t *d = &w->device;
    if (d->closing) { close_handles(w); return; }
    uv_mutex_lock(&w->mutex); solaris_status_t status = w->wait_status; uv_mutex_unlock(&w->mutex);
    if (status != SOLARIS_OK) { solaris_tun_device_fail(d, status); return; }
    int drained = 0;
    for (unsigned int count = 0u; count < 32u && !d->closing; ++count) {
        size_t length = 0u; status = SOLARIS_OK;
        uint8_t *packet = w->api.receive(w->api.context, &length, &status);
        if (packet == NULL) {
            if (status == SOLARIS_EAGAIN) drained = 1;
            else solaris_tun_device_fail(d, status == SOLARIS_OK ? SOLARIS_EIO : status);
            break;
        }
        if (length > d->options.mtu) { w->api.release(w->api.context, packet); solaris_tun_device_fail(d, SOLARIS_EMSGSIZE); break; }
        if (solaris_tun_device_packet(packet, length)) d->options.on_packet(d->options.context, packet, length);
        w->api.release(w->api.context, packet);
    }
    if (drained) {
        uv_mutex_lock(&w->mutex); w->awaiting = 0; uv_cond_signal(&w->resume); uv_mutex_unlock(&w->mutex);
    } else if (!d->closing) schedule(d);
    if (!d->closing) flush(w);
}
static void cancel(solaris_tun_device_t *d)
{
    wintun_device_t *w = (wintun_device_t *)d;
    uv_mutex_lock(&w->mutex); w->stopping = 1; w->awaiting = 0; uv_cond_signal(&w->resume); uv_mutex_unlock(&w->mutex);
    w->api.interrupt(w->api.context); close_handles(w);
}
static void dispose(solaris_tun_device_t *d)
{
    wintun_device_t *w = (wintun_device_t *)d;
    if (w->thread_started) { int rc = uv_thread_join(&w->thread); assert(rc == 0); (void)rc; }
    w->api.close(w->api.context); uv_cond_destroy(&w->resume); uv_mutex_destroy(&w->mutex);
}
static const solaris_tun_device_ops_t operations = {schedule, cancel, dispose};
solaris_status_t solaris_tun_wintun_open_api(const solaris_tun_device_options_t *options,
    const solaris_wintun_api_t *api, solaris_tun_device_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL; solaris_tun_device_options_t selected;
    solaris_status_t rc = solaris_tun_device_normalize(options, &selected);
    if (rc != SOLARIS_OK) return rc;
    if (api == NULL || api->receive == NULL || api->release == NULL || api->allocate == NULL || api->send == NULL ||
        api->wait == NULL || api->interrupt == NULL || api->close == NULL || selected.kind != SOLARIS_TUN_DEVICE_WINTUN) return SOLARIS_EINVAL;
    wintun_device_t *w = solaris_memory_allocate(solaris_executor_budget(options->owner), sizeof(*w));
    if (w == NULL) { api->close(api->context); return SOLARIS_ENOMEM; }
    memset(w, 0, sizeof(*w)); w->api = *api;
    if (uv_mutex_init(&w->mutex) != 0) { api->close(api->context); solaris_memory_free(w); return SOLARIS_ENOMEM; }
    if (uv_cond_init(&w->resume) != 0) { uv_mutex_destroy(&w->mutex); api->close(api->context); solaris_memory_free(w); return SOLARIS_ENOMEM; }
    selected.framing = SOLARIS_TUN_FRAMING_IP;
    rc = solaris_tun_device_init(&w->device, &selected, &operations, selected.name == NULL || selected.name[0] == '\0' ? "Solaris" : selected.name);
    if (rc != SOLARIS_OK) { dispose(&w->device); solaris_memory_free(w); return rc; }
    uv_loop_t *loop = solaris_executor_loop(options->owner);
    if (uv_async_init(loop, &w->async, ready) != 0) { solaris_tun_device_fail(&w->device, SOLARIS_EIO); return SOLARIS_EIO; }
    w->async_initialized = 1; w->async.data = w; solaris_scope_retain(&w->device.scope);
    if (uv_timer_init(loop, &w->retry) != 0) { solaris_tun_device_fail(&w->device, SOLARIS_EIO); return SOLARIS_EIO; }
    w->retry_initialized = 1; w->retry.data = w; solaris_scope_retain(&w->device.scope);
    if (uv_thread_create(&w->thread, worker, w) != 0) { solaris_tun_device_fail(&w->device, SOLARIS_EIO); return SOLARIS_EIO; }
    w->thread_started = 1; w->device.accepted = 1; *out = &w->device; return SOLARIS_OK;
}
