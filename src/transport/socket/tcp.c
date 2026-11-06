#include "transport/socket/internal.h"
#include "dns/system/resolver.h"
#include <assert.h>
#include <limits.h>
#include <string.h>

typedef struct solaris_tcp {
    solaris_stream_t stream;
    solaris_scope_t scope;
    solaris_deferred_t opened;
    solaris_dialer_options_t options;
    solaris_stream_callbacks_t callbacks;
    void *context;
    uv_tcp_t native;
    uv_connect_t connect;
    solaris_resolve_t *resolve;
    solaris_deadline_t *deadline;
    solaris_buffer_t *receive_buffer;
    solaris_address_t candidates[SOLARIS_RESOLVER_MAX_ADDRESSES];
    size_t candidate_count, next_candidate;
    uint64_t open_deadline_ns;
    solaris_io_snapshot_t stats;
    solaris_status_t open_status, close_status;
    int accepted, open_settled, initialized, native_closing, retrying;
    int connected, reading, read_desired, shutdown_requested, shutdown_done;
    int close_requested, writable_requested;
} solaris_tcp_t;

typedef struct solaris_tcp_write {
    uv_write_t native;
    solaris_tcp_t *tcp;
    const solaris_buffer_t *buffer;
    size_t length;
    solaris_io_done_fn callback;
    void *context;
} solaris_tcp_write_t;

typedef struct solaris_tcp_shutdown {
    uv_shutdown_t native;
    solaris_tcp_t *tcp;
    solaris_io_done_fn callback;
    void *context;
} solaris_tcp_shutdown_t;

static solaris_status_t set_reading(void *state, int enabled);
static void close_with_status(solaris_tcp_t *tcp, solaris_status_t status);
static void schedule_open(solaris_tcp_t *tcp, solaris_status_t status);
static solaris_status_t start_attempt(solaris_tcp_t *tcp);

static void on_native_close(uv_handle_t *native)
{
    solaris_tcp_t *tcp = native->data;
    tcp->initialized = 0;
    tcp->native_closing = 0;
    if (tcp->retrying && !tcp->scope.cancelled) {
        tcp->retrying = 0;
        const solaris_status_t rc = start_attempt(tcp);
        if (rc != SOLARIS_OK) {
            schedule_open(tcp, rc);
            close_with_status(tcp, rc);
        }
    }
    solaris_scope_release(&tcp->scope);
}

static void on_cancel(void *context)
{
    solaris_tcp_t *tcp = context;
    if (!tcp->close_requested) {
        tcp->close_requested = 1;
        tcp->close_status = SOLARIS_ECANCELLED;
    }
    if (tcp->accepted && !tcp->open_settled) {
        schedule_open(tcp, tcp->close_status == SOLARIS_OK ? SOLARIS_ECANCELLED : tcp->close_status);
    }
    if (tcp->resolve != NULL) solaris_resolve_cancel(tcp->resolve);
    if (tcp->deadline != NULL) solaris_deadline_cancel(tcp->deadline);
    if (tcp->initialized && !tcp->native_closing) {
        tcp->native_closing = 1;
        (void)uv_read_stop((uv_stream_t *)&tcp->native);
        uv_close((uv_handle_t *)&tcp->native, on_native_close);
    }
}

static void on_done(void *context)
{
    solaris_tcp_t *tcp = context;
    if (tcp->accepted) tcp->callbacks.on_close(tcp->context, &tcp->stream, tcp->close_status);
    solaris_buffer_release(tcp->receive_buffer);
    solaris_traffic_counter_release(tcp->options.traffic);
    solaris_memory_free(tcp);
}

static void close_with_status(solaris_tcp_t *tcp, solaris_status_t status)
{
    if (tcp->close_requested) return;
    tcp->close_requested = 1;
    tcp->close_status = status;
    solaris_scope_cancel(&tcp->scope);
}

static void deliver_open(void *context)
{
    solaris_tcp_t *tcp = context;
    tcp->callbacks.on_open(tcp->context, &tcp->stream, tcp->open_status);
    if (tcp->open_status == SOLARIS_OK && !tcp->scope.cancelled && tcp->read_desired) {
        const solaris_status_t rc = set_reading(tcp, 1);
        if (rc != SOLARIS_OK) close_with_status(tcp, rc);
    }
    solaris_scope_release(&tcp->scope);
}

static void schedule_open(solaris_tcp_t *tcp, solaris_status_t status)
{
    if (tcp->open_settled || !tcp->accepted) return;
    tcp->open_settled = 1;
    tcp->open_status = status;
    if (tcp->deadline != NULL) solaris_deadline_cancel(tcp->deadline);
    solaris_scope_retain(&tcp->scope);
    const solaris_status_t rc = solaris_executor_defer(tcp->scope.owner, &tcp->opened);
    assert(rc == SOLARIS_OK); (void)rc;
}

static void on_timeout(void *context, solaris_status_t status)
{
    solaris_tcp_t *tcp = context;
    tcp->deadline = NULL;
    if (status == SOLARIS_OK && !tcp->open_settled) {
        schedule_open(tcp, SOLARIS_ETIMEDOUT);
        close_with_status(tcp, SOLARIS_ETIMEDOUT);
    }
    solaris_scope_release(&tcp->scope);
}

static void alloc_read(uv_handle_t *native, size_t suggested, uv_buf_t *buffer)
{
    (void)suggested;
    solaris_tcp_t *tcp = native->data;
    assert(tcp->receive_buffer == NULL);
    if (solaris_buffer_allocate(solaris_executor_budget(tcp->scope.owner),
                                 tcp->options.read_chunk_size, &tcp->receive_buffer) != SOLARIS_OK) {
        buffer->base = NULL; buffer->len = 0u;
        return;
    }
    buffer->base = (char *)solaris_buffer_mutable_data(tcp->receive_buffer);
    buffer->len = solaris_buffer_capacity(tcp->receive_buffer);
}

static void on_read(uv_stream_t *native, ssize_t count, const uv_buf_t *buffer)
{
    (void)buffer;
    solaris_tcp_t *tcp = native->data;
    solaris_buffer_t *received = tcp->receive_buffer;
    tcp->receive_buffer = NULL;
    if (count > 0) solaris_traffic_record_read(tcp->options.traffic, SOLARIS_TRAFFIC_STREAM, (uint64_t)count);
    if (!tcp->scope.cancelled && count > 0) {
        const solaris_status_t rc = solaris_buffer_set_length(received, (size_t)count);
        assert(rc == SOLARIS_OK); (void)rc;
        solaris_buffer_publish(received);
        tcp->stats.bytes_read += (uint64_t)count;
        tcp->callbacks.on_data(tcp->context, &tcp->stream, received);
    } else if (!tcp->scope.cancelled && count == UV_EOF) {
        tcp->reading = 0;
        tcp->stats.read_eof = 1u;
        (void)uv_read_stop(native);
        if (tcp->callbacks.on_eof != NULL) tcp->callbacks.on_eof(tcp->context, &tcp->stream);
        if (tcp->shutdown_done && !tcp->scope.cancelled) close_with_status(tcp, SOLARIS_OK);
    } else if (!tcp->scope.cancelled && count < 0) {
        tcp->stats.last_system_error = (int32_t)count;
        close_with_status(tcp, solaris_socket_status((int)count));
    }
    solaris_buffer_release(received);
}

static solaris_status_t set_reading(void *state, int enabled)
{
    solaris_tcp_t *tcp = state;
    if (tcp->scope.cancelled) return SOLARIS_ECLOSED;
    tcp->read_desired = enabled;
    if (!tcp->connected) return SOLARIS_OK;
    if (enabled && tcp->stats.read_eof) return SOLARIS_ECLOSED;
    if (enabled == tcp->reading) return SOLARIS_OK;
    const int rc = enabled ? uv_read_start((uv_stream_t *)&tcp->native, alloc_read, on_read)
                           : uv_read_stop((uv_stream_t *)&tcp->native);
    if (rc == 0) tcp->reading = enabled;
    else tcp->stats.last_system_error = rc;
    return solaris_socket_status(rc);
}

static void on_connect(uv_connect_t *native, int status)
{
    solaris_tcp_t *tcp = native->data;
    if (!tcp->scope.cancelled) {
        if (solaris_executor_now_ns(tcp->scope.owner) >= tcp->open_deadline_ns) {
            schedule_open(tcp, SOLARIS_ETIMEDOUT);
            close_with_status(tcp, SOLARIS_ETIMEDOUT);
        } else if (status == 0) {
            tcp->connected = 1;
            schedule_open(tcp, SOLARIS_OK);
        } else if (tcp->next_candidate < tcp->candidate_count) {
            tcp->stats.last_system_error = status;
            tcp->retrying = 1;
            tcp->native_closing = 1;
            uv_close((uv_handle_t *)&tcp->native, on_native_close);
        } else {
            tcp->stats.last_system_error = status;
            schedule_open(tcp, solaris_socket_status(status));
            close_with_status(tcp, solaris_socket_status(status));
        }
    }
    solaris_scope_release(&tcp->scope);
}

static solaris_status_t start_attempt(solaris_tcp_t *tcp)
{
    if (!solaris_executor_accepting(tcp->scope.owner)) return SOLARIS_ECANCELLED;
    if (solaris_executor_now_ns(tcp->scope.owner) >= tcp->open_deadline_ns) return SOLARIS_ETIMEDOUT;
    const solaris_address_t *destination = NULL;
    while (tcp->next_candidate < tcp->candidate_count) {
        const solaris_address_t *candidate = &tcp->candidates[tcp->next_candidate++];
        if (tcp->options.local_bind.family == 0u || tcp->options.local_bind.family == candidate->family) {
            destination = candidate; break;
        }
    }
    if (destination == NULL) return SOLARIS_ENOTSUP;
    const unsigned int family = destination->family == SOLARIS_ADDRESS_IPV6 ? AF_INET6 : AF_INET;
    int rc = uv_tcp_init_ex(solaris_executor_loop(tcp->scope.owner), &tcp->native, family);
    if (rc != 0) { tcp->stats.last_system_error = rc; return solaris_socket_status(rc); }
    tcp->initialized = 1;
    tcp->native.data = tcp;
    solaris_scope_retain(&tcp->scope);
    if (tcp->options.local_bind.family != 0u) {
        struct sockaddr_storage local;
        solaris_status_t status = solaris_address_to_sockaddr(&tcp->options.local_bind, &local);
        if (status != SOLARIS_OK) return status;
        rc = uv_tcp_bind(&tcp->native, (const struct sockaddr *)&local, 0u);
        if (rc != 0) { tcp->stats.last_system_error = rc; return solaris_socket_status(rc); }
    }
    solaris_status_t status = solaris_socket_prepare(&tcp->options, (uv_handle_t *)&tcp->native,
                                                    destination->family, SOLARIS_SOCKET_TCP);
    if (status != SOLARIS_OK) return status;
    if (!solaris_executor_accepting(tcp->scope.owner)) return SOLARIS_ECANCELLED;
    struct sockaddr_storage remote;
    status = solaris_address_to_sockaddr(destination, &remote);
    if (status != SOLARIS_OK) return status;
    tcp->connect.data = tcp;
    solaris_scope_retain(&tcp->scope);
    rc = uv_tcp_connect(&tcp->connect, &tcp->native, (const struct sockaddr *)&remote, on_connect);
    if (rc != 0) {
        solaris_scope_release(&tcp->scope);
        tcp->stats.last_system_error = rc;
    }
    return solaris_socket_status(rc);
}

static void on_resolve(void *context, solaris_status_t status,
                        const solaris_address_t *addresses, size_t count)
{
    solaris_tcp_t *tcp = context;
    tcp->resolve = NULL;
    if (!tcp->scope.cancelled) {
        if (status == SOLARIS_OK) {
            tcp->candidate_count = count;
            memcpy(tcp->candidates, addresses, count * sizeof(*addresses));
            status = start_attempt(tcp);
        }
        if (status != SOLARIS_OK) {
            schedule_open(tcp, status);
            close_with_status(tcp, status);
        }
    }
    solaris_scope_release(&tcp->scope);
}

static void on_write(uv_write_t *native, int status)
{
    solaris_tcp_write_t *request = native->data;
    solaris_tcp_t *tcp = request->tcp;
    tcp->stats.pending_bytes -= request->length;
    tcp->stats.pending_requests--;
    if (status == 0) {
        tcp->stats.bytes_written += request->length;
        solaris_traffic_record_write(tcp->options.traffic, SOLARIS_TRAFFIC_STREAM, request->length);
    }
    else tcp->stats.last_system_error = status;
    request->callback(request->context, solaris_socket_status(status));
    if (status != 0 && !tcp->scope.cancelled) close_with_status(tcp, solaris_socket_status(status));
    if (tcp->writable_requested && !tcp->scope.cancelled && !tcp->shutdown_requested) {
        tcp->writable_requested = 0;
        if (tcp->callbacks.on_writable != NULL) tcp->callbacks.on_writable(tcp->context, &tcp->stream);
    }
    solaris_buffer_release(request->buffer);
    solaris_memory_free(request);
    solaris_scope_release(&tcp->scope);
}

static solaris_status_t write_stream(void *state, const solaris_slice_t *data,
                                      solaris_io_done_fn callback, void *context)
{
    solaris_tcp_t *tcp = state;
    if (tcp->scope.cancelled || tcp->shutdown_requested ||
        !solaris_executor_accepting(tcp->scope.owner)) return SOLARIS_ECLOSED;
    if (!tcp->connected) return SOLARIS_EBUSY;
    if (data->length > tcp->options.pending_byte_limit || data->length > UINT_MAX) return SOLARIS_EMSGSIZE;
    if (tcp->stats.pending_requests >= tcp->options.pending_request_limit ||
        tcp->stats.pending_bytes > tcp->options.pending_byte_limit - data->length) {
        tcp->writable_requested = 1;
        return SOLARIS_EAGAIN;
    }
    solaris_tcp_write_t *request = solaris_memory_allocate(solaris_executor_budget(tcp->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request));
    request->tcp = tcp; request->buffer = data->buffer; request->length = data->length;
    request->callback = callback; request->context = context; request->native.data = request;
    solaris_buffer_retain(request->buffer);
    solaris_scope_retain(&tcp->scope);
    uv_buf_t buffer = uv_buf_init((char *)solaris_buffer_data(data->buffer) + data->offset, (unsigned int)data->length);
    int rc = uv_write(&request->native, (uv_stream_t *)&tcp->native, &buffer, 1u, on_write);
    if (rc != 0) {
        solaris_buffer_release(request->buffer); solaris_memory_free(request);
        solaris_scope_release(&tcp->scope);
        tcp->stats.last_system_error = rc;
        close_with_status(tcp, solaris_socket_status(rc));
        return solaris_socket_status(rc);
    }
    tcp->stats.pending_bytes += data->length; tcp->stats.pending_requests++;
    return SOLARIS_OK;
}

static void on_shutdown(uv_shutdown_t *native, int status)
{
    solaris_tcp_shutdown_t *request = native->data;
    solaris_tcp_t *tcp = request->tcp;
    if (status == 0) { tcp->shutdown_done = 1; tcp->stats.write_shutdown = 1u; }
    else tcp->stats.last_system_error = status;
    request->callback(request->context, solaris_socket_status(status));
    if (!tcp->scope.cancelled && (status != 0 || tcp->stats.read_eof)) close_with_status(tcp, solaris_socket_status(status));
    solaris_memory_free(request);
    solaris_scope_release(&tcp->scope);
}

static solaris_status_t shutdown_write(void *state, solaris_io_done_fn callback, void *context)
{
    solaris_tcp_t *tcp = state;
    if (tcp->scope.cancelled || tcp->shutdown_requested) return SOLARIS_ECLOSED;
    if (!tcp->connected) return SOLARIS_EBUSY;
    solaris_tcp_shutdown_t *request = solaris_memory_allocate(solaris_executor_budget(tcp->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request));
    request->tcp = tcp; request->callback = callback; request->context = context; request->native.data = request;
    solaris_scope_retain(&tcp->scope);
    int rc = uv_shutdown(&request->native, (uv_stream_t *)&tcp->native, on_shutdown);
    if (rc != 0) {
        solaris_scope_release(&tcp->scope); solaris_memory_free(request);
        tcp->stats.last_system_error = rc; return solaris_socket_status(rc);
    }
    tcp->shutdown_requested = 1;
    return SOLARIS_OK;
}

static solaris_status_t close_stream(void *state)
{ close_with_status(state, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out)
{ *out = ((solaris_tcp_t *)state)->stats; return SOLARIS_OK; }

static const solaris_stream_ops_t stream_ops = {
    write_stream, shutdown_write, set_reading, close_stream, snapshot, NULL
};

solaris_status_t solaris_dialer_open_stream(solaris_executor_t *executor,
                                            const solaris_dialer_options_t *options,
                                            const solaris_address_t *destination,
                                            const solaris_stream_callbacks_t *callbacks,
                                            void *context, solaris_stream_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (executor == NULL || destination == NULL || destination->port == 0u || callbacks == NULL ||
        callbacks->on_open == NULL || callbacks->on_data == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(executor)) return SOLARIS_ETHREAD;
    if (destination->family != SOLARIS_ADDRESS_DOMAIN && destination->family != SOLARIS_ADDRESS_IPV4 &&
        destination->family != SOLARIS_ADDRESS_IPV6) return SOLARIS_EINVAL;
    solaris_dialer_options_t selected;
    solaris_status_t rc = solaris_socket_options(options, &selected);
    if (rc != SOLARIS_OK) return rc;
    solaris_tcp_t *tcp = solaris_memory_allocate(solaris_executor_budget(executor), sizeof(*tcp));
    if (tcp == NULL) return SOLARIS_ENOMEM;
    memset(tcp, 0, sizeof(*tcp));
    tcp->options = selected; tcp->callbacks = *callbacks; tcp->context = context;
    tcp->stream.ops = &stream_ops; tcp->stream.state = tcp; tcp->stream.owner = executor;
    tcp->opened.run = deliver_open; tcp->opened.context = tcp;
    tcp->read_desired = 1;
    tcp->stats.max_message_bytes = selected.pending_byte_limit;
    rc = solaris_scope_init(&tcp->scope, executor, on_cancel, on_done, tcp);
    if (rc != SOLARIS_OK) { solaris_memory_free(tcp); return rc; }
    solaris_traffic_counter_retain(tcp->options.traffic);
    const uint64_t now = solaris_executor_now_ns(executor);
    const uint64_t duration = selected.open_timeout_ms * UINT64_C(1000000);
    if (duration > UINT64_MAX - now) { close_with_status(tcp, SOLARIS_EOVERFLOW); return SOLARIS_EOVERFLOW; }
    tcp->open_deadline_ns = now + duration;
    solaris_scope_retain(&tcp->scope);
    rc = solaris_deadline_start(executor, selected.open_timeout_ms, on_timeout, tcp, &tcp->deadline);
    if (rc != SOLARIS_OK) {
        solaris_scope_release(&tcp->scope); close_with_status(tcp, rc); return rc;
    }
    if (destination->family == SOLARIS_ADDRESS_DOMAIN) {
        solaris_scope_retain(&tcp->scope);
        rc = solaris_resolve_start(executor, destination, 0u, on_resolve, tcp, &tcp->resolve);
        if (rc != SOLARIS_OK) solaris_scope_release(&tcp->scope);
    } else {
        tcp->candidates[0] = *destination; tcp->candidate_count = 1u;
        rc = start_attempt(tcp);
    }
    if (rc != SOLARIS_OK) { close_with_status(tcp, rc); return rc; }
    tcp->accepted = 1;
    *out = &tcp->stream;
    return SOLARIS_OK;
}
