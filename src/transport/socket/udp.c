#include "transport/socket/internal.h"
#include <assert.h>
#include <string.h>

typedef struct solaris_udp {
    solaris_datagram_t datagram;
    solaris_scope_t scope;
    solaris_scope_t *parent;
    solaris_deferred_t opened;
    solaris_socket_token_t *preparation;
    solaris_dialer_options_t options;
    solaris_datagram_callbacks_t callbacks;
    void *context;
    uv_udp_t native;
    solaris_buffer_t *receive_buffer;
    solaris_address_t local;
    solaris_io_snapshot_t stats;
    solaris_status_t close_status, open_status;
    uint32_t family;
    int initialized, accepted, open_delivered, open_scheduled, native_closing;
    int close_requested, read_desired, reading, writable_requested;
    int policy_retained;
} solaris_udp_t;

typedef struct solaris_udp_send {
    uv_udp_send_t native;
    solaris_udp_t *udp;
    struct sockaddr_storage destination;
    const solaris_buffer_t *buffer;
    size_t length;
    solaris_io_done_fn callback;
    void *context;
} solaris_udp_send_t;

static solaris_status_t set_reading(void *state, int enabled);
static void schedule_open(solaris_udp_t *udp, solaris_status_t status);

static void on_native_close(uv_handle_t *native)
{
    solaris_udp_t *udp = native->data;
    udp->initialized = 0;
    solaris_scope_release(&udp->scope);
}

static void on_cancel(void *context)
{
    solaris_udp_t *udp = context;
    if (!udp->close_requested) { udp->close_requested = 1; udp->close_status = SOLARIS_ECANCELLED; }
    schedule_open(udp, udp->close_status == SOLARIS_OK ? SOLARIS_ECANCELLED : udp->close_status);
    if (udp->preparation) (void)solaris_socket_preparation_cancel(udp->preparation);
    if (udp->initialized && !udp->native_closing) {
        udp->native_closing = 1;
        (void)uv_udp_recv_stop(&udp->native);
        uv_close((uv_handle_t *)&udp->native, on_native_close);
    }
}

static void on_done(void *context)
{
    solaris_udp_t *udp = context;
    if (udp->accepted) udp->callbacks.on_close(udp->context, &udp->datagram, udp->close_status);
    solaris_buffer_release(udp->receive_buffer);
    solaris_traffic_counter_release(udp->options.traffic);
    solaris_scope_t *parent = udp->parent;
    if (udp->policy_retained) udp->options.async_policy.release(udp->options.async_policy.context);
    solaris_memory_free(udp);
    if (parent) solaris_scope_release(parent);
}

static void close_with_status(solaris_udp_t *udp, solaris_status_t status)
{
    if (udp->close_requested) return;
    udp->close_requested = 1; udp->close_status = status;
    solaris_scope_cancel(&udp->scope);
}

static void deliver_open(void *context)
{
    solaris_udp_t *udp = context;
    const solaris_status_t status = udp->scope.cancelled && udp->open_status == SOLARIS_OK ? SOLARIS_ECANCELLED : udp->open_status;
    udp->open_delivered = 1;
    udp->callbacks.on_open(udp->context, &udp->datagram, status);
    if (status == SOLARIS_OK && !udp->scope.cancelled && udp->read_desired) {
        const solaris_status_t rc = set_reading(udp, 1);
        if (rc != SOLARIS_OK) close_with_status(udp, rc);
    }
    solaris_scope_release(&udp->scope);
}

static void schedule_open(solaris_udp_t *udp, solaris_status_t status)
{
    if (!udp->accepted || udp->open_scheduled || udp->open_delivered) return;
    udp->open_scheduled = 1; udp->open_status = status;
    solaris_scope_retain(&udp->scope);
    solaris_status_t rc = solaris_executor_defer(udp->scope.owner, &udp->opened);
    assert(rc == SOLARIS_OK); (void)rc;
}
static void preparation_done(void *context, solaris_status_t status)
{
    solaris_udp_t *udp = context; udp->preparation = NULL;
    if (udp->scope.cancelled) return;
    schedule_open(udp, status);
    if (status != SOLARIS_OK) close_with_status(udp, status);
}

static void alloc_read(uv_handle_t *native, size_t suggested, uv_buf_t *buffer)
{
    (void)suggested;
    solaris_udp_t *udp = native->data;
    assert(udp->receive_buffer == NULL);
    if (solaris_buffer_allocate(solaris_executor_budget(udp->scope.owner), 65536u,
                                 &udp->receive_buffer) != SOLARIS_OK) {
        buffer->base = NULL; buffer->len = 0u;
        return;
    }
    *buffer = uv_buf_init((char *)solaris_buffer_mutable_data(udp->receive_buffer),
                         (unsigned int)solaris_buffer_capacity(udp->receive_buffer));
}

static void on_read(uv_udp_t *native, ssize_t count, const uv_buf_t *buffer,
                     const struct sockaddr *source, unsigned int flags)
{
    (void)buffer;
    solaris_udp_t *udp = native->data;
    solaris_buffer_t *received = udp->receive_buffer;
    udp->receive_buffer = NULL;
    if (count >= 0 && source != NULL) solaris_traffic_record_read(udp->options.traffic, SOLARIS_TRAFFIC_DATAGRAM, (uint64_t)count);
    if (!udp->scope.cancelled && (flags & UV_UDP_PARTIAL) != 0u) {
        udp->stats.dropped_packets++;
    } else if (!udp->scope.cancelled && count >= 0 && source != NULL) {
        solaris_address_t address;
        if (solaris_address_from_sockaddr(source, &address) == SOLARIS_OK && received != NULL) {
            const solaris_status_t rc = solaris_buffer_set_length(received, (size_t)count);
            assert(rc == SOLARIS_OK); (void)rc;
            solaris_buffer_publish(received);
            udp->stats.bytes_read += (uint64_t)count;
            udp->stats.packets_read++;
            udp->callbacks.on_packet(udp->context, &udp->datagram, &address, received);
        } else udp->stats.dropped_packets++;
    } else if (!udp->scope.cancelled && count < 0) {
        udp->stats.last_system_error = (int32_t)count;
        close_with_status(udp, solaris_socket_status((int)count));
    }
    solaris_buffer_release(received);
}

static solaris_status_t set_reading(void *state, int enabled)
{
    solaris_udp_t *udp = state;
    if (udp->scope.cancelled) return SOLARIS_ECLOSED;
    udp->read_desired = enabled;
    if (!udp->open_delivered) return SOLARIS_OK;
    if (enabled == udp->reading) return SOLARIS_OK;
    const int rc = enabled ? uv_udp_recv_start(&udp->native, alloc_read, on_read)
                           : uv_udp_recv_stop(&udp->native);
    if (rc == 0) udp->reading = enabled;
    else udp->stats.last_system_error = rc;
    return solaris_socket_status(rc);
}

static void on_send(uv_udp_send_t *native, int status)
{
    solaris_udp_send_t *request = native->data;
    solaris_udp_t *udp = request->udp;
    udp->stats.pending_bytes -= request->length;
    udp->stats.pending_requests--;
    if (status == 0) {
        udp->stats.bytes_written += request->length;
        udp->stats.packets_written++;
        solaris_traffic_record_write(udp->options.traffic, SOLARIS_TRAFFIC_DATAGRAM, request->length);
    } else udp->stats.last_system_error = status;
    request->callback(request->context, solaris_socket_status(status));
    if (udp->writable_requested && !udp->scope.cancelled) {
        udp->writable_requested = 0;
        if (udp->callbacks.on_writable != NULL) udp->callbacks.on_writable(udp->context, &udp->datagram);
    }
    solaris_buffer_release(request->buffer);
    solaris_memory_free(request);
    solaris_scope_release(&udp->scope);
}

static solaris_status_t send_packet(void *state, const solaris_address_t *destination,
                                    const solaris_slice_t *data, solaris_io_done_fn callback, void *context)
{
    solaris_udp_t *udp = state;
    if (udp->scope.cancelled || !solaris_executor_accepting(udp->scope.owner)) return SOLARIS_ECLOSED;
    if (!udp->open_delivered) return SOLARIS_EBUSY;
    if (destination->family != udp->family) return SOLARIS_ENOTSUP;
    if (destination->port == 0u) return SOLARIS_EINVAL;
    if (data->length > udp->stats.max_message_bytes || data->length > udp->options.pending_byte_limit) return SOLARIS_EMSGSIZE;
    if (udp->stats.pending_requests >= udp->options.pending_request_limit ||
        udp->stats.pending_bytes > udp->options.pending_byte_limit - data->length) {
        udp->writable_requested = 1;
        return SOLARIS_EAGAIN;
    }
    solaris_udp_send_t *request = solaris_memory_allocate(solaris_executor_budget(udp->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request));
    solaris_status_t rc = solaris_address_to_sockaddr(destination, &request->destination);
    if (rc != SOLARIS_OK) { solaris_memory_free(request); return rc; }
    request->udp = udp; request->buffer = data->buffer; request->length = data->length;
    request->callback = callback; request->context = context; request->native.data = request;
    solaris_buffer_retain(request->buffer);
    solaris_scope_retain(&udp->scope);
    uv_buf_t buffer = uv_buf_init((char *)solaris_buffer_data(data->buffer) + data->offset, (unsigned int)data->length);
    const int native_rc = uv_udp_send(&request->native, &udp->native, &buffer, 1u,
                                       (const struct sockaddr *)&request->destination, on_send);
    if (native_rc != 0) {
        solaris_buffer_release(request->buffer); solaris_memory_free(request);
        solaris_scope_release(&udp->scope);
        udp->stats.last_system_error = native_rc;
        return solaris_socket_status(native_rc);
    }
    udp->stats.pending_bytes += data->length; udp->stats.pending_requests++;
    return SOLARIS_OK;
}

static solaris_status_t close_datagram(void *state)
{ close_with_status(state, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out)
{ *out = ((solaris_udp_t *)state)->stats; return SOLARIS_OK; }
static solaris_status_t local_address(void *state, solaris_address_t *out)
{ *out = ((solaris_udp_t *)state)->local; return SOLARIS_OK; }

static const solaris_datagram_ops_t datagram_ops = {
    send_packet, set_reading, close_datagram, snapshot, local_address
};

solaris_status_t solaris_dialer_open_datagram(solaris_executor_t *executor,
                                              const solaris_dialer_options_t *options,
                                              uint32_t family,
                                              const solaris_datagram_callbacks_t *callbacks,
                                              void *context, solaris_datagram_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (executor == NULL || callbacks == NULL || callbacks->on_open == NULL ||
        callbacks->on_packet == NULL || callbacks->on_close == NULL ||
        (family != SOLARIS_ADDRESS_IPV4 && family != SOLARIS_ADDRESS_IPV6)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(executor)) return SOLARIS_ETHREAD;
    solaris_dialer_options_t selected;
    solaris_status_t rc = solaris_socket_options(options, &selected);
    if (rc != SOLARIS_OK) return rc;
    if (selected.parent_scope && selected.parent_scope->owner != executor) return SOLARIS_ETHREAD;
    if (selected.parent_scope && (selected.parent_scope->cancelled || selected.parent_scope->finishing)) return SOLARIS_ECLOSED;
    if (selected.local_bind.family != 0u && selected.local_bind.family != family) return SOLARIS_EINVAL;
    if (selected.network_view_present && !(selected.allowed_families & (family == SOLARIS_ADDRESS_IPV4 ? 1u : 2u)))
        return SOLARIS_ENOTSUP;
    uint64_t deadline_ns = 0;
    if (selected.async_policy.start) {
        uint64_t now = solaris_executor_now_ns(executor), duration = selected.open_timeout_ms * UINT64_C(1000000);
        if (now > UINT64_MAX - duration) return SOLARIS_EOVERFLOW;
        deadline_ns = now + duration;
    }
    solaris_udp_t *udp = solaris_memory_allocate(solaris_executor_budget(executor), sizeof(*udp));
    if (udp == NULL) return SOLARIS_ENOMEM;
    memset(udp, 0, sizeof(*udp));
    udp->options = selected; udp->callbacks = *callbacks; udp->context = context; udp->family = family;
    udp->datagram.ops = &datagram_ops; udp->datagram.state = udp; udp->datagram.owner = executor;
    udp->opened.run = deliver_open; udp->opened.context = udp;
    udp->read_desired = 1;
    udp->stats.max_message_bytes = family == SOLARIS_ADDRESS_IPV6 ? 65527u : 65507u;
    rc = solaris_scope_init(&udp->scope, executor, on_cancel, on_done, udp);
    if (rc != SOLARIS_OK) { solaris_memory_free(udp); return rc; }
    udp->parent = selected.parent_scope;
    if (udp->parent) solaris_scope_retain(udp->parent);
    if (selected.async_policy.start && selected.async_policy.retain) {
        selected.async_policy.retain(selected.async_policy.context); udp->policy_retained = 1;
    }
    solaris_traffic_counter_retain(udp->options.traffic);
    int native_rc = uv_udp_init_ex(solaris_executor_loop(executor), &udp->native,
                                   (unsigned int)(family == SOLARIS_ADDRESS_IPV6 ? AF_INET6 : AF_INET));
    if (native_rc == 0) {
        udp->initialized = 1; udp->native.data = udp;
        solaris_scope_retain(&udp->scope);
        solaris_address_t bind_address = selected.local_bind;
        if (bind_address.family == 0u) { memset(&bind_address, 0, sizeof(bind_address)); bind_address.family = family; }
        struct sockaddr_storage local;
        rc = solaris_address_to_sockaddr(&bind_address, &local);
        if (rc == SOLARIS_OK) native_rc = uv_udp_bind(&udp->native, (const struct sockaddr *)&local,
                                                    family == SOLARIS_ADDRESS_IPV6 ? UV_UDP_IPV6ONLY : 0u);
        if (native_rc == 0 && rc == SOLARIS_OK) rc = solaris_socket_prepare(&selected,
            (uv_handle_t *)&udp->native, family, SOLARIS_SOCKET_UDP);
        if (native_rc == 0 && rc == SOLARIS_OK) {
            int length = sizeof(local);
            native_rc = uv_udp_getsockname(&udp->native, (struct sockaddr *)&local, &length);
            if (native_rc == 0) rc = solaris_address_from_sockaddr((const struct sockaddr *)&local, &udp->local);
        }
    }
    if (native_rc != 0) rc = solaris_socket_status(native_rc);
    if (rc == SOLARIS_OK && selected.async_policy.start)
        rc = solaris_socket_prepare_async(&selected, executor, (uv_handle_t *)&udp->native,
            family, SOLARIS_SOCKET_UDP, deadline_ns, &udp->scope, preparation_done, udp, &udp->preparation);
    if (rc != SOLARIS_OK) { close_with_status(udp, rc); return rc; }
    udp->accepted = 1;
    if (!udp->preparation) schedule_open(udp, SOLARIS_OK);
    *out = &udp->datagram;
    return SOLARIS_OK;
}
