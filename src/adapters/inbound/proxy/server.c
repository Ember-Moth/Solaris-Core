#include "adapters/inbound/proxy/internal.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static void pump(void *context);
static void inbound_cancel(void *context);
static void connection_timeout(proxy_connection_t *c);
static void maybe_retired(solaris_proxy_inbound_t *in);
static void inbound_fail(solaris_proxy_inbound_t *inbound, solaris_status_t status)
{
    if (!inbound->scope.cancelled) {
        inbound->status = status;
        solaris_scope_cancel(&inbound->scope);
    }
}
void solaris_proxy_cancel(proxy_connection_t *c, solaris_status_t status)
{
    if (!c->scope.cancelled) {
        c->status = status;
        solaris_scope_cancel(&c->scope);
    }
}
static void connection_cancel(void *context)
{
    proxy_connection_t *c = context;
    if (c->native)
        (void)solaris_stream_close(c->native);
    if (c->route_job)
        solaris_route_cancel(c->route_job);
    if (c->relay)
        solaris_tcp_relay_close(c->relay);
    solaris_proxy_udp_cancel(c);
    solaris_proxy_schedule(c);
}
static void connection_done(void *context)
{
    proxy_connection_t *c = context;
    solaris_proxy_inbound_t *in = c->inbound;
    assert(!c->native && !c->relay && !c->datagram && !c->upgrade_done && !c->route_job);
    proxy_connection_t **cursor = &in->connections;
    while (*cursor != c) {
        assert(*cursor);
        cursor = &(*cursor)->next;
    }
    *cursor = c->next;
    in->stats.connections--;
    solaris_http_request_destroy(c->http);
    solaris_http_upgrade_response_destroy(c->upgrade);
    for (size_t i = 0; i < c->input_capacity; ++i)
        ((volatile uint8_t *)c->input)[i] = 0;
    solaris_memory_free(c->input);
    solaris_buffer_release(c->header);
    solaris_buffer_release(c->reply);
    int context_retained = c->context_retained;
    solaris_proxy_context_t capture = c->capture;
    solaris_tracker_finish(c->flow, c->status);
    solaris_memory_free(c);
    maybe_retired(in);
    if (context_retained)
        capture.release(capture.context);
    solaris_scope_release(&in->scope);
}
void solaris_proxy_schedule(proxy_connection_t *c)
{
    if (c->deferred.queued)
        return;
    solaris_scope_retain(&c->scope);
    solaris_status_t rc = solaris_executor_defer(c->scope.owner, &c->deferred);
    assert(rc == SOLARIS_OK);
    (void)rc;
}
void solaris_proxy_consume(proxy_connection_t *c, size_t n)
{
    assert(n <= c->input_length);
    c->input_length -= n;
    memmove(c->input, c->input + n, c->input_length);
}
static int expired(proxy_connection_t *c)
{
    /* RFC 1928 control lifetime is TCP EOF/explicit close. UDP idle belongs to
     * its association, so a still-authenticated control can create a new one. */
    if (c->state == PROXY_UDP)
        return 0;
    uint64_t now = solaris_executor_now_ns(c->scope.owner);
    int active = (c->state == PROXY_STREAM || c->state == PROXY_UDP) && (!c->upgrade || c->upgrade_settled);
    uint64_t start = active ? c->activity_ns : c->created_ns;
    uint64_t timeout = active ? c->inbound->options.idle_timeout_ms : c->inbound->options.handshake_timeout_ms;
    return now - start >= timeout * UINT64_C(1000000);
}
static void reply_done(void *context, solaris_status_t status)
{
    proxy_connection_t *c = context;
    c->replying = 0;
    solaris_buffer_release(c->reply);
    c->reply = NULL;
    if (status != SOLARIS_OK)
        solaris_proxy_cancel(c, status);
    else if (!c->scope.cancelled) {
        c->state = c->after_reply;
        if (c->state == PROXY_UDP)
            solaris_tracker_flow_open(c->flow);
        if (c->state == PROXY_ERROR)
            solaris_proxy_cancel(c, SOLARIS_EIO);
        else {
            c->activity_ns = solaris_executor_now_ns(c->scope.owner);
            solaris_proxy_schedule(c);
        }
    }
    solaris_scope_release(&c->scope);
}
static void write_reply(proxy_connection_t *c)
{
    if (!c->reply || c->replying || c->scope.cancelled || !c->native_open)
        return;
    solaris_slice_t slice = {c->reply, 0, solaris_buffer_length(c->reply)};
    solaris_status_t rc = solaris_stream_write(c->native, &slice, reply_done, c);
    if (rc == SOLARIS_OK) {
        c->replying = 1;
        solaris_scope_retain(&c->scope);
    } else if (rc != SOLARIS_EAGAIN)
        solaris_proxy_cancel(c, rc);
}
void solaris_proxy_reply(proxy_connection_t *c, const void *data, size_t length, proxy_state_t next)
{
    if (c->scope.cancelled)
        return;
    assert(!c->reply);
    solaris_status_t rc = solaris_buffer_copy(solaris_executor_budget(c->scope.owner), data, length, &c->reply);
    if (rc != SOLARIS_OK) {
        solaris_proxy_cancel(c, rc);
        return;
    }
    c->after_reply = next;
    c->draining = next == PROXY_ERROR;
    if (c->draining)
        c->state = PROXY_ERROR;
    write_reply(c);
}
void solaris_proxy_http_error(proxy_connection_t *c, unsigned code)
{
    const char *reason = code == 407   ? "Proxy Authentication Required"
                         : code == 502 ? "Bad Gateway"
                         : code == 504 ? "Gateway Timeout"
                         : code == 431 ? "Request Header Fields Too Large"
                                       : "Bad Request";
    char response[256];
    int n = snprintf(response, sizeof(response), "HTTP/1.1 %u %s\r\nConnection: close\r\nContent-Length: 0\r\n%s\r\n",
                     code, reason, code == 407 ? "Proxy-Authenticate: Basic realm=\"Solaris\"\r\n" : "");
    solaris_proxy_reply(c, response, (size_t)n, PROXY_ERROR);
}
static void connection_timeout(proxy_connection_t *c)
{
    int upgrading = c->upgrade && c->state == PROXY_STREAM &&
                    solaris_http_upgrade_response_state(c->upgrade) == SOLARIS_HTTP_UPGRADE_PENDING;
    if (!c->draining && !c->reply && (c->state == PROXY_CONNECTING || c->state == PROXY_UDP_OPEN || upgrading)) {
        /* Give the failure reply one bounded handshake interval to drain. */
        c->created_ns = solaris_executor_now_ns(c->scope.owner);
        if (c->protocol == SOLARIS_INBOUND_HTTP)
            solaris_proxy_http_error(c, 504);
        else
            solaris_proxy_socks_reply(c, 6, NULL, PROXY_ERROR);
        if (c->route_job)
            solaris_route_cancel(c->route_job);
        if (c->relay)
            solaris_tcp_relay_close(c->relay);
    } else
        solaris_proxy_cancel(c, SOLARIS_ETIMEDOUT);
}
static solaris_status_t wrapper_write(void *context, const solaris_slice_t *data, solaris_io_done_fn done, void *user)
{
    proxy_connection_t *c = context;
    if (c->scope.cancelled || !c->native || solaris_tracker_flow_closing(c->flow))
        return SOLARIS_ECLOSED;
    if (c->state != PROXY_STREAM || c->reply)
        return SOLARIS_EAGAIN;
    c->activity_ns = solaris_executor_now_ns(c->scope.owner);
    if (c->upgrade && !c->http_upgraded)
        return solaris_proxy_upgrade_write(c, data, done, user);
    return solaris_stream_write(c->native, data, done, user);
}
static void wrapper_shutdown_done(void *context, solaris_status_t status)
{
    proxy_connection_t *c = context;
    solaris_io_done_fn done = c->shutdown_done;
    void *user = c->shutdown_context;
    c->shutdown_done = NULL;
    done(user, status);
    if (c->http && !c->http_connect && !c->http_upgraded)
        solaris_proxy_cancel(c, status);
    solaris_scope_release(&c->scope);
}
static solaris_status_t wrapper_shutdown(void *context, solaris_io_done_fn done, void *user)
{
    proxy_connection_t *c = context;
    if (c->scope.cancelled || !c->native || solaris_tracker_flow_closing(c->flow))
        return SOLARIS_ECLOSED;
    if (c->state != PROXY_STREAM || c->reply)
        return SOLARIS_EAGAIN;
    if (c->shutdown_done)
        return SOLARIS_ECLOSED;
    if (c->upgrade && !c->http_upgraded && solaris_http_upgrade_response_eof(c->upgrade) != SOLARIS_OK) {
        if (solaris_http_upgrade_response_state(c->upgrade) == SOLARIS_HTTP_UPGRADE_PENDING)
            solaris_proxy_http_error(c, 502);
        return SOLARIS_EIO;
    }
    solaris_status_t rc = solaris_stream_shutdown_write(c->native, wrapper_shutdown_done, c);
    if (rc == SOLARIS_OK) {
        c->shutdown_done = done;
        c->shutdown_context = user;
        solaris_scope_retain(&c->scope);
    }
    return rc;
}
static solaris_status_t wrapper_reading(void *context, int reading)
{
    proxy_connection_t *c = context;
    if (c->scope.cancelled || solaris_tracker_flow_closing(c->flow))
        return SOLARIS_ECLOSED;
    c->reading = reading;
    if (!reading && c->native)
        (void)solaris_stream_set_reading(c->native, 0);
    if (reading)
        solaris_proxy_schedule(c);
    return SOLARIS_OK;
}
static solaris_status_t wrapper_close(void *context)
{
    proxy_connection_t *c = context;
    if (!c->draining)
        solaris_proxy_cancel(c, SOLARIS_OK);
    return SOLARIS_OK;
}
static solaris_status_t wrapper_snapshot(void *context, solaris_io_snapshot_t *out)
{
    proxy_connection_t *c = context;
    if (!c->native)
        return SOLARIS_ECLOSED;
    solaris_status_t rc = solaris_stream_get_snapshot(c->native, out);
    /* Leave room for the buffered response header when the final block arrives. */
    if (rc == SOLARIS_OK && c->upgrade && !c->http_upgraded &&
        (!out->max_message_bytes || out->max_message_bytes > 4096))
        out->max_message_bytes = 4096;
    return rc;
}
static const solaris_stream_ops_t wrapper_ops = {wrapper_write, wrapper_shutdown, wrapper_reading,
                                                 wrapper_close, wrapper_snapshot, NULL};
static void relay_closed(void *context, solaris_status_t status)
{
    proxy_connection_t *c = context;
    c->relay = NULL;
    if (!c->draining)
        solaris_proxy_cancel(c, status);
    solaris_scope_release(&c->scope);
}
static void relay_connected(void *context, solaris_status_t status)
{
    proxy_connection_t *c = context;
    if (c->scope.cancelled || c->draining)
        return;
    if (expired(c)) {
        connection_timeout(c);
        return;
    }
    if (status != SOLARIS_OK) {
        if (c->protocol == SOLARIS_INBOUND_HTTP)
            solaris_proxy_http_error(c, status == SOLARIS_ETIMEDOUT ? 504 : 502);
        else
            solaris_proxy_socks_reply(c,
                                      status == SOLARIS_ETIMEDOUT ? 6
                                      : status == SOLARIS_EACCESS ? 2
                                                                  : 5,
                                      NULL, PROXY_ERROR);
    } else if (c->protocol == SOLARIS_INBOUND_SOCKS5)
        solaris_proxy_socks_reply(c, 0, NULL, PROXY_STREAM);
    else if (c->http_connect) {
        static const char response[] = "HTTP/1.1 200 Connection Established\r\n\r\n";
        solaris_proxy_reply(c, response, sizeof(response) - 1, PROXY_STREAM);
    } else {
        c->state = PROXY_STREAM;
        solaris_proxy_schedule(c);
    }
}
solaris_status_t solaris_proxy_select(proxy_connection_t *c, uint32_t network, const solaris_address_t *destination,
                                      solaris_dial_plan_t *out)
{
    if (c->scope.cancelled)
        return SOLARIS_ECLOSED;
    solaris_inbound_request_t request = {.protocol = c->protocol,
                                         .network = network,
                                         .inbound_id = c->inbound->options.inbound_id,
                                         .connection_id = c->id,
                                         .source = network == SOLARIS_INBOUND_UDP ? c->udp_peer : c->peer,
                                         .destination = *destination,
                                         .username = c->username,
                                         .username_length = c->username_length};
    if (!c->inbound->options.select)
        return SOLARIS_ENOTSUP;
    solaris_status_t rc = c->inbound->options.select(c->capture.context, c->scope.owner, &request, out);
    if (rc == SOLARIS_OK && c->scope.cancelled)
        rc = SOLARIS_ECLOSED;
    return rc;
}
void solaris_proxy_route_options_release(solaris_route_options_t *options)
{
    if (options->release)
        options->release(options->context);
    memset(options, 0, sizeof(*options));
}
solaris_status_t solaris_proxy_route_options(proxy_connection_t *c, uint32_t network,
                                             const solaris_address_t *destination, solaris_route_options_t *out)
{
    memset(out, 0, sizeof(*out));
    if (c->scope.cancelled || !c->inbound->options.route)
        return SOLARIS_ECLOSED;
    solaris_inbound_request_t request = {.protocol = c->protocol,
                                         .network = network,
                                         .inbound_id = c->inbound->options.inbound_id,
                                         .connection_id = c->id,
                                         .source = network == SOLARIS_INBOUND_UDP ? c->udp_peer : c->peer,
                                         .destination = *destination,
                                         .username = c->username,
                                         .username_length = c->username_length};
    solaris_status_t rc = c->inbound->options.route(c->capture.context, c->scope.owner, &request, out);
    if (rc != SOLARIS_OK)
        return rc;
    if (c->scope.cancelled) {
        solaris_proxy_route_options_release(out);
        return SOLARIS_ECLOSED;
    }
    if ((out->retain == NULL) != (out->release == NULL)) {
        solaris_proxy_route_options_release(out);
        return SOLARIS_EINVAL;
    }
    out->owner = c->scope.owner;
    out->metadata.source = request.source;
    out->metadata.destination = *destination;
    memset(&out->metadata.resolved, 0, sizeof(out->metadata.resolved));
    out->metadata.resolved_valid = 0;
    out->metadata.network = network;
    out->metadata.inbound_id = request.inbound_id;
    out->metadata.connection_id = c->id;
    uint64_t timeout = c->inbound->options.handshake_timeout_ms;
    if (network == SOLARIS_INBOUND_TCP) {
        uint64_t elapsed = solaris_executor_now_ns(c->scope.owner) - c->created_ns;
        uint64_t duration = timeout * UINT64_C(1000000);
        if (elapsed >= duration) {
            solaris_proxy_route_options_release(out);
            return SOLARIS_ETIMEDOUT;
        }
        timeout = (duration - elapsed - 1) / UINT64_C(1000000) + 1;
    }
    if (!out->timeout_ms || out->timeout_ms > timeout)
        out->timeout_ms = timeout;
    return SOLARIS_OK;
}
static solaris_status_t start_relay(proxy_connection_t *c, solaris_dial_plan_t *plan, const solaris_address_t *target,
                                    const solaris_route_result_t *selected)
{
    if (c->flow) {
        solaris_route_result_t fallback = {.metadata = {.source = c->peer,
                                                        .destination = c->destination,
                                                        .network = SOLARIS_NETWORK_TCP,
                                                        .inbound_id = c->inbound->options.inbound_id,
                                                        .config_revision = c->capture.config_revision,
                                                        .selection_revision = c->capture.selection_revision},
                                           .dial_target = *target,
                                           .rule_index = UINT64_MAX};
        solaris_dial_plan_t observed;
        solaris_status_t rc = solaris_tracker_attach_plan(c->flow, plan, selected ? selected : &fallback, &observed);
        if (rc != SOLARIS_OK)
            return rc;
        *plan = observed;
    }
    solaris_tcp_relay_options_t options = {.owner = c->scope.owner,
                                           .destination = *target,
                                           .pending_byte_limit = c->inbound->options.pending_byte_limit,
                                           .context = c,
                                           .on_close = relay_closed,
                                           .on_connect = relay_connected};
    solaris_status_t rc = solaris_tcp_relay_prepare(&options, plan, &c->callbacks, &c->callback_context, &c->relay);
    if (rc != SOLARIS_OK)
        return rc;
    c->wrapper = 1;
    solaris_scope_retain(&c->scope);
    solaris_proxy_schedule(c);
    return SOLARIS_OK;
}
static void routed(void *context, solaris_status_t status, solaris_route_result_t *result)
{
    proxy_connection_t *c = context;
    c->route_job = NULL;
    if (!c->scope.cancelled && !c->draining) {
        if (solaris_tracker_flow_closing(c->flow))
            solaris_proxy_cancel(c, SOLARIS_ECANCELLED);
        else if (expired(c))
            connection_timeout(c);
        else {
            solaris_dial_plan_t plan = {0};
            if (status == SOLARIS_OK)
                status = solaris_route_result_take_plan(result, &plan);
            if (status == SOLARIS_OK)
                status = start_relay(c, &plan, &result->dial_target, result);
            (void)solaris_dial_plan_release(&plan);
            if (status != SOLARIS_OK)
                relay_connected(c, status);
        }
    }
    solaris_scope_release(&c->scope);
}
void solaris_proxy_connect(proxy_connection_t *c)
{
    if (solaris_tracker_flow_closing(c->flow)) {
        solaris_proxy_cancel(c, SOLARIS_ECANCELLED);
        return;
    }
    solaris_tracker_flow_target(c->flow, &c->destination);
    c->state = PROXY_CONNECTING;
    if (c->inbound->options.route) {
        solaris_route_options_t options;
        solaris_status_t rc = solaris_proxy_route_options(c, SOLARIS_INBOUND_TCP, &c->destination, &options);
        if (rc == SOLARIS_OK) {
            options.done = routed;
            options.user = c;
            solaris_scope_retain(&c->scope);
            rc = solaris_route_start(&options, &c->route_job);
            if (rc != SOLARIS_OK)
                solaris_scope_release(&c->scope);
            solaris_proxy_route_options_release(&options);
        }
        if (rc != SOLARIS_OK)
            relay_connected(c, rc);
        return;
    }
    solaris_dial_plan_t plan = {0};
    solaris_status_t rc = solaris_proxy_select(c, SOLARIS_INBOUND_TCP, &c->destination, &plan);
    if (rc == SOLARIS_OK)
        rc = start_relay(c, &plan, &c->destination, NULL);
    (void)solaris_dial_plan_release(&plan);
    if (rc != SOLARIS_OK)
        relay_connected(c, rc);
}
static void http_parse(proxy_connection_t *c)
{
    size_t n = 0;
    for (size_t i = 3; i < c->input_length; ++i)
        if (!memcmp(c->input + i - 3, "\r\n\r\n", 4)) {
            n = i + 1;
            break;
        }
    if (!n) {
        if (c->input_length >= c->inbound->options.header_limit)
            solaris_proxy_http_error(c, 431);
        return;
    }
    solaris_http_metadata_t metadata;
    solaris_status_t rc =
        solaris_http_request_create(solaris_executor_budget(c->scope.owner), c->input, n,
                                    c->inbound->options.header_limit, &metadata, &c->header, &c->http);
    if (rc != SOLARIS_OK) {
        c->inbound->stats.protocol_failed++;
        solaris_proxy_http_error(c, 400);
        return;
    }
    if (c->inbound->options.authenticate) {
        rc = metadata.credentials ? c->inbound->options.authenticate(c->inbound->options.context, metadata.username,
                                                                     metadata.username_length, metadata.password,
                                                                     metadata.password_length)
                                  : SOLARIS_EINVAL;
        if (rc == SOLARIS_OK) {
            memcpy(c->username, metadata.username, metadata.username_length);
            c->username_length = metadata.username_length;
        }
    }
    solaris_http_credentials_clear(&metadata);
    /* Credential-bearing input is not retained after authentication. */
    for (size_t i = 0; i < n; ++i)
        ((volatile uint8_t *)c->input)[i] = 0;
    solaris_proxy_consume(c, n);
    if (c->scope.cancelled)
        return;
    if (rc != SOLARIS_OK) {
        c->inbound->stats.authentication_failed++;
        solaris_proxy_http_error(c, 407);
        return;
    }
    c->http_connect = metadata.connect;
    if (metadata.websocket) {
        rc = solaris_http_upgrade_response_create(solaris_executor_budget(c->scope.owner),
                                                  c->inbound->options.header_limit, &c->upgrade);
        if (rc != SOLARIS_OK) {
            solaris_proxy_http_error(c, 502);
            return;
        }
    }
    c->destination = metadata.destination;
    solaris_proxy_connect(c);
}
static void stream_input(proxy_connection_t *c)
{
    if (!c->reading || c->scope.cancelled)
        return;
    solaris_buffer_t *data = NULL;
    if (c->header) {
        data = c->header;
        c->header = NULL;
    } else if (c->upgrade && !c->http_upgraded) {
        /* Client early frames stay bounded and paused until 101 is written. */
        return;
    } else if (c->http && !c->http_connect && !c->http_upgraded) {
        size_t used;
        solaris_status_t rc = solaris_http_request_body(c->http, c->input, c->input_length, &used, &data);
        if (rc != SOLARIS_OK) {
            c->inbound->stats.protocol_failed++;
            solaris_proxy_cancel(c, rc);
            return;
        }
        solaris_proxy_consume(c, used);
        if (solaris_http_request_complete(c->http))
            c->input_length = 0; /* never forward another request */
    } else if (c->input_length) {
        solaris_status_t rc =
            solaris_buffer_copy(solaris_executor_budget(c->scope.owner), c->input, c->input_length, &data);
        if (rc != SOLARIS_OK) {
            solaris_proxy_cancel(c, rc);
            return;
        }
        c->input_length = 0;
    }
    if (data) {
        c->callbacks.on_data(c->callback_context, &c->stream, data);
        solaris_buffer_release(data);
        if (c->reading)
            solaris_proxy_schedule(c);
        return;
    }
    if (c->native_eof && !c->eof_delivered) {
        c->eof_delivered = 1;
        if (c->http && !c->http_connect && !c->http_upgraded) {
            if (solaris_http_request_eof(c->http) != SOLARIS_OK)
                solaris_proxy_cancel(c, SOLARIS_EIO);
        } else if (c->callbacks.on_eof)
            c->callbacks.on_eof(c->callback_context, &c->stream);
    }
    if (!c->scope.cancelled && c->native && !c->native_eof &&
        !(c->http && !c->http_connect && !c->http_upgraded && solaris_http_request_complete(c->http)))
        (void)solaris_stream_set_reading(c->native, 1);
}
static void pump(void *context)
{
    proxy_connection_t *c = context;
    if (!c->scope.cancelled && solaris_tracker_flow_closing(c->flow))
        solaris_proxy_cancel(c, SOLARIS_ECANCELLED);
    if (c->wrapper && !c->virtual_open) {
        c->virtual_open = 1;
        c->callbacks.on_open(c->callback_context, &c->stream, c->scope.cancelled ? SOLARIS_ECANCELLED : SOLARIS_OK);
    }
    solaris_proxy_upgrade_pump(c);
    if (c->wrapper && !c->native && !c->virtual_close && !c->upgrade_done) {
        c->virtual_close = 1;
        c->callbacks.on_close(c->callback_context, &c->stream, c->status);
    }
    if (c->scope.cancelled || !c->native_open)
        goto done;
    if (expired(c)) {
        connection_timeout(c);
        goto done;
    }
    if (c->reply) {
        write_reply(c);
        goto done;
    }
    if (c->state == PROXY_DETECT && c->input_length) {
        c->protocol = c->input[0] == 5 ? SOLARIS_INBOUND_SOCKS5 : SOLARIS_INBOUND_HTTP;
        c->state = c->protocol == SOLARIS_INBOUND_SOCKS5 ? PROXY_METHOD : PROXY_HTTP;
    }
    if (c->state == PROXY_HTTP)
        http_parse(c);
    else if (c->state == PROXY_METHOD || c->state == PROXY_AUTH || c->state == PROXY_REQUEST)
        solaris_proxy_socks_parse(c);
    if (c->scope.cancelled || c->reply)
        goto done;
    if (c->state == PROXY_STREAM) {
        if (c->callbacks.on_writable)
            c->callbacks.on_writable(c->callback_context, &c->stream);
        stream_input(c);
    } else if (c->state == PROXY_UDP) {
        if (c->input_length || c->native_eof)
            solaris_proxy_cancel(c, SOLARIS_ECLOSED);
        else
            (void)solaris_stream_set_reading(c->native, 1);
    } else if (c->state != PROXY_CONNECTING && c->state != PROXY_UDP_OPEN && c->state != PROXY_ERROR) {
        if (c->native_eof)
            solaris_proxy_cancel(c, SOLARIS_EIO);
        else
            (void)solaris_stream_set_reading(c->native, 1);
    }
done:
    solaris_scope_release(&c->scope);
}
static void native_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    proxy_connection_t *c = context;
    (void)stream;
    c->native_open = status == SOLARIS_OK;
    if (status != SOLARIS_OK)
        solaris_proxy_cancel(c, status);
    else
        solaris_proxy_schedule(c);
}
static void native_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    proxy_connection_t *c = context;
    if (!c->scope.cancelled && solaris_tracker_flow_closing(c->flow))
        solaris_proxy_cancel(c, SOLARIS_ECANCELLED);
    if (c->scope.cancelled)
        return;
    (void)solaris_stream_set_reading(stream, 0);
    size_t n = solaris_buffer_length(buffer);
    if (n > c->input_capacity - c->input_length) {
        solaris_proxy_cancel(c, SOLARIS_EOVERFLOW);
        return;
    }
    memcpy(c->input + c->input_length, solaris_buffer_data(buffer), n);
    c->input_length += n;
    c->activity_ns = solaris_executor_now_ns(c->scope.owner);
    solaris_proxy_schedule(c);
}
static void native_eof(void *context, solaris_stream_t *stream)
{
    proxy_connection_t *c = context;
    (void)stream;
    c->native_eof = 1;
    solaris_proxy_schedule(c);
}
static void native_writable(void *context, solaris_stream_t *stream)
{
    (void)stream;
    solaris_proxy_schedule(context);
}
static void native_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    proxy_connection_t *c = context;
    (void)stream;
    c->native = NULL;
    solaris_proxy_cancel(c, status);
    solaris_proxy_schedule(c);
    solaris_scope_release(&c->scope);
}
static const solaris_stream_callbacks_t native_callbacks = {native_opened, native_data, native_eof, native_writable,
                                                            native_closed};
static void observed_close(void *context)
{
    solaris_proxy_cancel(context, SOLARIS_ECANCELLED);
}
solaris_status_t solaris_proxy_inbound_accept_with_context(solaris_proxy_inbound_t *in, const solaris_address_t *peer,
                                                           const solaris_address_t *local, solaris_stream_t *stream,
                                                           solaris_stream_callbacks_t *callbacks, void **stream_context,
                                                           const solaris_proxy_context_t *capture)
{
    if (!in || !peer || !local || !stream || !callbacks || !stream_context ||
        (capture && ((capture->retain == NULL) != (capture->release == NULL))))
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(in->scope.owner) || stream->owner != in->scope.owner)
        return SOLARIS_ETHREAD;
    if (in->scope.cancelled || in->stats.retired || !solaris_executor_accepting(in->scope.owner))
        return SOLARIS_ECLOSED;
    if (in->stats.connections >= in->options.connection_limit || in->serial == UINT64_MAX) {
        in->stats.rejected++;
        return SOLARIS_EAGAIN;
    }
    proxy_connection_t *c = solaris_memory_allocate(solaris_executor_budget(in->scope.owner), sizeof(*c));
    if (!c) {
        in->stats.rejected++;
        return SOLARIS_ENOMEM;
    }
    memset(c, 0, sizeof(*c));
    c->inbound = in;
    c->capture = capture ? *capture
                         : (solaris_proxy_context_t){.context = in->options.context,
                                                     .retain = in->options.retain,
                                                     .release = in->options.release};
    c->input_capacity = in->options.header_limit + 8192;
    c->input = solaris_memory_allocate(solaris_executor_budget(in->scope.owner), c->input_capacity);
    if (!c->input) {
        solaris_memory_free(c);
        in->stats.rejected++;
        return SOLARIS_ENOMEM;
    }
    solaris_status_t rc = solaris_scope_init(&c->scope, in->scope.owner, connection_cancel, connection_done, c);
    if (rc != SOLARIS_OK) {
        solaris_memory_free(c->input);
        solaris_memory_free(c);
        return rc;
    }
    c->peer = *peer;
    c->local = *local;
    c->protocol = in->options.protocol;
    c->stream = (solaris_stream_t){&wrapper_ops, c, in->scope.owner};
    c->state = c->protocol == SOLARIS_INBOUND_MIXED  ? PROXY_DETECT
               : c->protocol == SOLARIS_INBOUND_HTTP ? PROXY_HTTP
                                                     : PROXY_METHOD;
    c->id = ++in->serial;
    c->created_ns = c->activity_ns = solaris_executor_now_ns(in->scope.owner);
    c->deferred = (solaris_deferred_t){.run = pump, .context = c};
    c->next = in->connections;
    in->connections = c;
    in->stats.connections++;
    solaris_scope_retain(&in->scope);
    if (in->options.tracker) {
        solaris_observe_options_t observe = {.kind = SOLARIS_FLOW_STREAM,
                                             .purpose = SOLARIS_FLOW_USER,
                                             .source = *peer,
                                             .config_revision = c->capture.config_revision,
                                             .selection_revision = c->capture.selection_revision,
                                             .inbound_id = in->options.inbound_id,
                                             .rule_index = UINT64_MAX,
                                             .network = SOLARIS_NETWORK_TCP};
        rc = solaris_tracker_admit(in->options.tracker, in->scope.owner, &observe, observed_close, c, &c->flow, &c->id);
        if (rc != SOLARIS_OK) {
            in->stats.rejected++;
            solaris_proxy_cancel(c, rc);
            return rc;
        }
    }
    c->native = stream;
    solaris_scope_retain(&c->scope);
    if (c->capture.retain) {
        c->capture.retain(c->capture.context);
        c->context_retained = 1;
    }
    in->stats.accepted++;
    *callbacks = native_callbacks;
    *stream_context = c;
    return SOLARIS_OK;
}
solaris_status_t solaris_proxy_inbound_accept(solaris_proxy_inbound_t *in, const solaris_address_t *peer,
                                              const solaris_address_t *local, solaris_stream_t *stream,
                                              solaris_stream_callbacks_t *callbacks, void **stream_context)
{
    return solaris_proxy_inbound_accept_with_context(in, peer, local, stream, callbacks, stream_context, NULL);
}
static solaris_status_t accepted(void *context, const solaris_address_t *peer, const solaris_address_t *local,
                                 solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks, void **stream_context)
{
    return solaris_proxy_inbound_accept(context, peer, local, stream, callbacks, stream_context);
}
static void maybe_retired(solaris_proxy_inbound_t *in)
{
    if (in->stats.retired && !in->connections && !in->listener && !in->scope.cancelled)
        inbound_fail(in, SOLARIS_OK);
}
static void listener_closed(void *context, solaris_status_t status)
{
    solaris_proxy_inbound_t *in = context;
    in->listener = NULL;
    if (in->stats.retired && status == SOLARIS_OK)
        maybe_retired(in);
    else
        inbound_fail(in, status);
}
static solaris_status_t start_timer(solaris_proxy_inbound_t *in);
static void timer_fired(void *context, solaris_status_t status)
{
    solaris_proxy_inbound_t *in = context;
    in->timer = NULL;
    if (status == SOLARIS_OK && !in->scope.cancelled) {
        for (proxy_connection_t *c = in->connections; c; c = c->next)
            if (!c->scope.cancelled && expired(c))
                connection_timeout(c);
        solaris_status_t rc = start_timer(in);
        if (rc != SOLARIS_OK)
            inbound_fail(in, rc);
    }
    solaris_scope_release(&in->scope);
}
static solaris_status_t start_timer(solaris_proxy_inbound_t *in)
{
    uint64_t interval = 1000;
    if (in->options.handshake_timeout_ms < interval)
        interval = in->options.handshake_timeout_ms;
    if (in->options.idle_timeout_ms < interval)
        interval = in->options.idle_timeout_ms;
    solaris_status_t rc = solaris_deadline_start(in->scope.owner, interval, timer_fired, in, &in->timer);
    if (rc == SOLARIS_OK)
        solaris_scope_retain(&in->scope);
    return rc;
}
static void inbound_cancel(void *context)
{
    solaris_proxy_inbound_t *in = context;
    in->stats.closing = 1;
    if (in->listener)
        solaris_tcp_listener_close(in->listener);
    if (in->timer)
        solaris_deadline_cancel(in->timer);
    if (in->udp)
        (void)solaris_udp_dispatcher_close(in->udp);
    for (proxy_connection_t *c = in->connections; c; c = c->next)
        solaris_proxy_cancel(c, SOLARIS_ECANCELLED);
}
static void inbound_done(void *context)
{
    solaris_proxy_inbound_t *in = context;
    assert(!in->listener && !in->timer && !in->connections);
    if (in->udp) {
        solaris_status_t rc = solaris_udp_dispatcher_destroy(in->udp);
        assert(rc == SOLARIS_OK);
        (void)rc;
    }
    if (in->accepted)
        in->options.on_close(in->options.context, &in->stats, in->status);
    solaris_scope_t *parent = in->parent_retained ? in->options.parent_scope : NULL;
    solaris_memory_free(in);
    if (parent)
        solaris_scope_release(parent);
}
void solaris_proxy_inbound_options_init(solaris_proxy_inbound_options_t *o)
{
    memset(o, 0, sizeof(*o));
    o->protocol = SOLARIS_INBOUND_MIXED;
    (void)solaris_address_parse("127.0.0.1", 0, &o->listen);
    o->connection_limit = 1024;
    o->header_limit = 32768;
    o->pending_byte_limit = 262144;
    o->pending_packet_limit = 64;
    o->udp_mapping_limit = 64;
    o->handshake_timeout_ms = 10000;
    o->idle_timeout_ms = 300000;
    o->udp = 1;
}
static solaris_status_t create(const solaris_proxy_inbound_options_t *o, solaris_proxy_inbound_t **out, int detached)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!o || !o->owner || (!o->select && !o->route) || !o->on_close || ((o->retain == NULL) != (o->release == NULL)) ||
        o->protocol < SOLARIS_INBOUND_HTTP || o->protocol > SOLARIS_INBOUND_MIXED || !o->connection_limit ||
        o->header_limit < 1024 || o->header_limit > 1048576 || o->pending_byte_limit < o->header_limit + 8192 ||
        !o->pending_packet_limit || !o->udp_mapping_limit || !o->handshake_timeout_ms || !o->idle_timeout_ms ||
        o->handshake_timeout_ms > UINT64_MAX / 1000000 || o->idle_timeout_ms > UINT64_MAX / 1000000 ||
        (o->udp != 0 && o->udp != 1))
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(o->owner) || (o->parent_scope && o->parent_scope->owner != o->owner))
        return SOLARIS_ETHREAD;
    if (o->parent_scope && (o->parent_scope->cancelled || o->parent_scope->finishing))
        return SOLARIS_ECLOSED;
    solaris_proxy_inbound_t *in = solaris_memory_allocate(solaris_executor_budget(o->owner), sizeof(*in));
    if (!in)
        return SOLARIS_ENOMEM;
    memset(in, 0, sizeof(*in));
    in->options = *o;
    in->status = SOLARIS_ECANCELLED;
    solaris_status_t rc = solaris_scope_init(&in->scope, o->owner, inbound_cancel, inbound_done, in);
    if (rc != SOLARIS_OK) {
        solaris_memory_free(in);
        return rc;
    }
    if (o->parent_scope) {
        solaris_scope_retain(o->parent_scope);
        in->parent_retained = 1;
    }
    if (o->udp && o->protocol != SOLARIS_INBOUND_HTTP)
        rc = solaris_proxy_udp_create(in);
    if (rc == SOLARIS_OK)
        rc = start_timer(in);
    if (rc == SOLARIS_OK && !detached) {
        solaris_dialer_options_t stream;
        solaris_dialer_options_init(&stream);
        stream.pending_byte_limit = o->pending_byte_limit;
        stream.read_chunk_size = 8192;
        rc = solaris_tcp_listener_open_scoped(o->owner, &in->scope, &o->listen, &stream, accepted, listener_closed, in,
                                              &in->listener, &in->stats.bound);
    }
    if (rc != SOLARIS_OK) {
        inbound_fail(in, rc);
        return rc;
    }
    if (detached)
        in->stats.bound = o->listen;
    in->accepted = 1;
    *out = in;
    return SOLARIS_OK;
}
solaris_status_t solaris_proxy_inbound_create(const solaris_proxy_inbound_options_t *options,
                                              solaris_proxy_inbound_t **out)
{
    return create(options, out, 0);
}
solaris_status_t solaris_proxy_inbound_detached_create(const solaris_proxy_inbound_options_t *options,
                                                       solaris_proxy_inbound_t **out)
{
    return create(options, out, 1);
}
solaris_status_t solaris_proxy_inbound_retire(solaris_proxy_inbound_t *in)
{
    if (!in)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(in->scope.owner))
        return SOLARIS_ETHREAD;
    if (in->scope.cancelled)
        return SOLARIS_ECLOSED;
    in->stats.retired = 1;
    if (in->listener)
        solaris_tcp_listener_close(in->listener);
    maybe_retired(in);
    return SOLARIS_OK;
}
solaris_status_t solaris_proxy_inbound_snapshot(solaris_proxy_inbound_t *in, solaris_proxy_inbound_snapshot_t *out)
{
    if (!in || !out)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(in->scope.owner))
        return SOLARIS_ETHREAD;
    *out = in->stats;
    return SOLARIS_OK;
}
solaris_status_t solaris_proxy_inbound_close(solaris_proxy_inbound_t *in)
{
    if (!in)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(in->scope.owner))
        return SOLARIS_ETHREAD;
    inbound_fail(in, SOLARIS_OK);
    return SOLARIS_OK;
}
