#include "contracts/dns/exchange.h"
#include "solaris_builtin_modules.h"
#include <assert.h>
#include <string.h>

struct solaris_dns_exchange {
    solaris_scope_t scope;
    solaris_scope_t *parent;
    solaris_deferred_t begin;
    solaris_deadline_t *deadline;
    solaris_dns_exchange_options_t options;
    solaris_dns_exchange_result_t result;
    solaris_dns_exchange_fn done;
    void *context;
    const solaris_dns_wire_t *query;
    solaris_dns_wire_t *response;
    solaris_buffer_t *frame;
    uint8_t *receive;
    size_t received, frame_size;
    solaris_datagram_t *udp;
    solaris_stream_t *tcp;
    solaris_tls_context_t *trust;
    char identity[254];
    int accepted, settled, delivering, write_pending, write_done, fallback_pending, switching;
};
static void settle(solaris_dns_exchange_t *exchange, solaris_status_t status);
static void progress(solaris_dns_exchange_t *exchange);
static void start_tcp(solaris_dns_exchange_t *exchange);

void solaris_dns_exchange_options_init(solaris_dns_exchange_options_t *options)
{
    if (!options) return;
    memset(options, 0, sizeof(*options));
    options->transport = SOLARIS_DNS_TRANSPORT_UDP;
    options->view.role = SOLARIS_DNS_CLIENT_QUERY;
    solaris_dialer_options_init(&options->dialer);
    solaris_dns_wire_limits_init(&options->wire_limits);
}
static int live(solaris_dns_exchange_t *exchange)
{
    if (exchange->settled) return 0;
    if (!solaris_executor_accepting(exchange->scope.owner) ||
        solaris_executor_generation(exchange->scope.owner) != exchange->scope.generation) {
        settle(exchange, SOLARIS_ECANCELLED); return 0;
    }
    if (solaris_executor_now_ns(exchange->scope.owner) >= exchange->options.deadline_ns) {
        settle(exchange, SOLARIS_ETIMEDOUT); return 0;
    }
    return 1;
}
static void decide(solaris_dns_exchange_t *exchange, solaris_status_t status)
{
    if (exchange->settled) return;
    uint64_t now = solaris_executor_now_ns(exchange->scope.owner);
    /* A deadline must not soften a policy/network invalidation into an ordinary
     * lookup failure that a caller could interpret as permission to continue. */
    if (!solaris_dns_lookup_terminal(status) && now >= exchange->options.deadline_ns) status = SOLARIS_ETIMEDOUT;
    exchange->settled = 1; exchange->result.status = status; exchange->result.completed_ns = now;
    exchange->result.duration_ns = now >= exchange->result.started_ns ? now - exchange->result.started_ns : 0;
}
static void cancelled(void *context)
{
    solaris_dns_exchange_t *exchange = context; decide(exchange, SOLARIS_ECANCELLED);
    if (exchange->udp) (void)solaris_datagram_close(exchange->udp);
    if (exchange->tcp) (void)solaris_stream_close(exchange->tcp);
    if (exchange->deadline) solaris_deadline_cancel(exchange->deadline);
}
static void settle(solaris_dns_exchange_t *exchange, solaris_status_t status)
{ decide(exchange, status); solaris_scope_cancel(&exchange->scope); }
static void destroyed(void *context)
{
    solaris_dns_exchange_t *exchange = context;
    assert(!exchange->udp && !exchange->tcp && !exchange->deadline && !exchange->write_pending && !exchange->begin.queued);
    if (exchange->result.status == SOLARIS_OK &&
        (!solaris_executor_accepting(exchange->scope.owner) ||
         solaris_executor_generation(exchange->scope.owner) != exchange->scope.generation))
        exchange->result.status = SOLARIS_ECANCELLED;
    exchange->result.response = exchange->result.status == SOLARIS_OK ? exchange->response : NULL;
    exchange->delivering = 1;
    if (exchange->accepted) exchange->done(exchange->context, exchange, &exchange->result);
    solaris_scope_t *parent = exchange->parent;
    solaris_dns_wire_release(exchange->query); solaris_dns_wire_release(exchange->response);
    solaris_buffer_release(exchange->frame); solaris_memory_free(exchange->receive);
#if SOLARIS_HAS_TLS
    solaris_tls_context_release(exchange->trust);
#endif
    solaris_memory_free(exchange);
    if (parent) solaris_scope_release(parent);
}
static void deadline(void *context, solaris_status_t status)
{
    solaris_dns_exchange_t *exchange = context; exchange->deadline = NULL;
    if (status == SOLARIS_OK) settle(exchange, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&exchange->scope);
}
static solaris_status_t prepare(void *context, uintptr_t handle, uint32_t family, uint32_t kind)
{
    solaris_dns_exchange_t *exchange = context;
    solaris_status_t rc = SOLARIS_OK;
    if (exchange->options.dialer.prepare_socket)
        rc = exchange->options.dialer.prepare_socket(exchange->options.dialer.policy_context, handle, family, kind);
    /* A host preparation callback may cancel/reenter this exchange. Check again
     * before the physical dialer is allowed to connect or send anything. */
    if (rc == SOLARIS_OK && !live(exchange)) rc = exchange->result.status;
    return rc;
}
static solaris_dialer_options_t dialer(solaris_dns_exchange_t *exchange)
{
    solaris_dialer_options_t options = exchange->options.dialer;
    options.parent_scope = &exchange->scope;
    options.prepare_socket = prepare; options.policy_context = exchange;
    options.lookup_view = exchange->options.view; options.require_lookup = 1;
    uint64_t now = solaris_executor_now_ns(exchange->scope.owner);
    uint64_t remaining = exchange->options.deadline_ns > now ? exchange->options.deadline_ns - now : 1;
    options.open_timeout_ms = (remaining - 1) / UINT64_C(1000000) + 1;
    return options;
}
static void sent(void *context, solaris_status_t status)
{
    solaris_dns_exchange_t *exchange = context; exchange->write_pending = 0;
    if (status == SOLARIS_OK) {
        exchange->write_done = 1;
        exchange->result.bytes_written += exchange->result.transport != SOLARIS_DNS_TRANSPORT_UDP ?
            solaris_buffer_length(exchange->frame) : solaris_buffer_length(solaris_dns_wire_buffer(exchange->query));
    }
    if (!exchange->settled) { if (status == SOLARIS_OK) progress(exchange); else settle(exchange, status); }
    solaris_scope_release(&exchange->scope);
}
static void send_query(solaris_dns_exchange_t *exchange)
{
    if (!live(exchange) || exchange->write_pending || exchange->write_done) return;
    const solaris_buffer_t *buffer = exchange->tcp ? exchange->frame : solaris_dns_wire_buffer(exchange->query);
    solaris_slice_t slice = {buffer, 0, solaris_buffer_length(buffer)};
    solaris_status_t rc = exchange->tcp ? solaris_stream_write(exchange->tcp, &slice, sent, exchange) :
        solaris_datagram_send(exchange->udp, &exchange->options.upstream, &slice, sent, exchange);
    if (rc == SOLARIS_OK) { exchange->write_pending = 1; solaris_scope_retain(&exchange->scope); }
    else if (rc != SOLARIS_EAGAIN) settle(exchange, rc);
}
static void progress(solaris_dns_exchange_t *exchange)
{
    if (!live(exchange) || !exchange->write_done) return;
    if (exchange->fallback_pending && !exchange->switching) {
        exchange->switching = 1;
        if (exchange->udp) (void)solaris_datagram_close(exchange->udp);
    } else if (exchange->response) settle(exchange, SOLARIS_OK);
}
static int consider(solaris_dns_exchange_t *exchange, const uint8_t *bytes, size_t length, int tcp)
{
    if (!live(exchange)) return 0;
    const solaris_dns_header_t *query_header = solaris_dns_wire_header(exchange->query);
    if (length < 12 || (((uint16_t)bytes[0] << 8) | bytes[1]) != query_header->id || !(bytes[2] & 0x80u)) return 0;
    solaris_dns_wire_t *message = NULL;
    solaris_status_t rc = solaris_dns_wire_parse(solaris_executor_budget(exchange->scope.owner), bytes, length,
        &exchange->options.wire_limits, &message, NULL);
    if (rc != SOLARIS_OK) { if (rc == SOLARIS_ENOMEM) settle(exchange, rc); return 0; }
    if (solaris_dns_wire_validate_reply(exchange->query, message) != SOLARIS_OK) {
        solaris_dns_wire_release(message); return 0;
    }
    if (!live(exchange)) { solaris_dns_wire_release(message); return 1; }
    if (solaris_dns_wire_header(message)->flags & SOLARIS_DNS_TC) {
        solaris_dns_wire_release(message);
        if (tcp) settle(exchange, SOLARIS_EIO);
        else {
            exchange->fallback_pending = 1; exchange->result.tcp_fallback = 1;
            (void)solaris_datagram_set_reading(exchange->udp, 0); progress(exchange);
        }
    } else {
        exchange->response = message;
        if (tcp) (void)solaris_stream_set_reading(exchange->tcp, 0);
        else (void)solaris_datagram_set_reading(exchange->udp, 0);
        progress(exchange);
    }
    return 1;
}
static void udp_opened(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{
    (void)datagram; solaris_dns_exchange_t *exchange = context;
    if (!live(exchange)) return;
    if (status != SOLARIS_OK) settle(exchange, status); else send_query(exchange);
}
static void udp_packet(void *context, solaris_datagram_t *datagram, const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    (void)datagram; solaris_dns_exchange_t *exchange = context;
    if (!live(exchange) || exchange->response || exchange->fallback_pending) return;
    size_t length = solaris_buffer_length(buffer); exchange->result.bytes_read += length;
    if (!solaris_address_equal(source, &exchange->options.upstream) ||
        !consider(exchange, solaris_buffer_data(buffer), length, 0)) ++exchange->result.discarded_packets;
}
static void udp_writable(void *context, solaris_datagram_t *datagram)
{ (void)datagram; send_query(context); }
static void udp_closed(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{
    (void)datagram; solaris_dns_exchange_t *exchange = context; exchange->udp = NULL;
    if (!live(exchange)) return;
    if (exchange->switching) { assert(!exchange->write_pending); start_tcp(exchange); }
    else settle(exchange, status == SOLARIS_OK ? SOLARIS_EIO : status);
}
static const solaris_datagram_callbacks_t udp_callbacks = {udp_opened, udp_packet, udp_writable, udp_closed};
static void tcp_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    (void)stream; solaris_dns_exchange_t *exchange = context;
    if (!live(exchange)) return;
    if (status != SOLARIS_OK) { settle(exchange, status); return; }
#if SOLARIS_HAS_TLS
    if (exchange->result.transport == SOLARIS_DNS_TRANSPORT_TLS) {
        size_t length = 0;
        status = solaris_tls_selected_alpn(stream, exchange->result.selected_alpn,
            sizeof(exchange->result.selected_alpn), &length);
        if (status != SOLARIS_OK || (length && (length != 3 || memcmp(exchange->result.selected_alpn, "dot", 3)))) {
            settle(exchange, status == SOLARIS_OK ? SOLARIS_ENOTSUP : status); return;
        }
        exchange->result.selected_alpn_length = length;
    }
#endif
    send_query(exchange);
}
static void tcp_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    (void)stream; solaris_dns_exchange_t *exchange = context;
    if (!live(exchange) || exchange->response) return;
    const uint8_t *bytes = solaris_buffer_data(buffer); size_t length = solaris_buffer_length(buffer);
    exchange->result.bytes_read += length;
    while (length && live(exchange) && !exchange->response) {
        size_t needed = exchange->received < 2 ? 2 - exchange->received : exchange->frame_size + 2 - exchange->received;
        size_t copy = needed < length ? needed : length;
        memcpy(exchange->receive + exchange->received, bytes, copy);
        exchange->received += copy; bytes += copy; length -= copy;
        if (exchange->received == 2) {
            exchange->frame_size = ((size_t)exchange->receive[0] << 8) | exchange->receive[1];
            if (exchange->frame_size < 12) { settle(exchange, SOLARIS_EINVAL); return; }
            if (exchange->frame_size > exchange->options.wire_limits.message_bytes) { settle(exchange, SOLARIS_EMSGSIZE); return; }
        }
        if (exchange->received >= 2 && exchange->received == exchange->frame_size + 2) {
            if (!consider(exchange, exchange->receive + 2, exchange->frame_size, 1)) ++exchange->result.discarded_frames;
            exchange->received = 0; exchange->frame_size = 0;
        }
    }
}
static void tcp_eof(void *context, solaris_stream_t *stream)
{
    (void)stream; solaris_dns_exchange_t *exchange = context;
    if (!exchange->settled) { if (exchange->response) progress(exchange); else settle(exchange, SOLARIS_EIO); }
}
static void tcp_writable(void *context, solaris_stream_t *stream)
{ (void)stream; send_query(context); }
static void tcp_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    (void)stream; solaris_dns_exchange_t *exchange = context; exchange->tcp = NULL;
    if (!exchange->settled) {
        if (exchange->response && exchange->write_done) progress(exchange);
        else settle(exchange, status == SOLARIS_OK ? SOLARIS_EIO : status);
    }
}
static const solaris_stream_callbacks_t tcp_callbacks = {tcp_opened, tcp_data, tcp_eof, tcp_writable, tcp_closed};
static void start_tcp(solaris_dns_exchange_t *exchange)
{
    if (!live(exchange)) return;
    exchange->result.transport = exchange->options.transport == SOLARIS_DNS_TRANSPORT_TLS ?
        SOLARIS_DNS_TRANSPORT_TLS : SOLARIS_DNS_TRANSPORT_TCP;
    exchange->write_done = 0;
    exchange->fallback_pending = 0; exchange->switching = 0;
    solaris_status_t rc = solaris_dns_wire_frame(exchange->query, solaris_executor_budget(exchange->scope.owner), &exchange->frame);
    if (rc == SOLARIS_OK) {
        exchange->receive = solaris_memory_allocate(solaris_executor_budget(exchange->scope.owner), exchange->options.wire_limits.message_bytes + 2);
        if (!exchange->receive) rc = SOLARIS_ENOMEM;
    }
    if (rc == SOLARIS_OK && live(exchange)) {
        solaris_dialer_options_t options = dialer(exchange);
#if SOLARIS_HAS_TLS
        if (exchange->result.transport == SOLARIS_DNS_TRANSPORT_TLS) {
            const uint8_t offer[] = {3, 'd', 'o', 't'};
            solaris_tls_open_options_t tls_options = {.alpn = offer, .alpn_length = sizeof(offer),
                .require_alpn = exchange->options.tls_require_alpn, .deadline_ns = exchange->options.deadline_ns};
            rc = solaris_tls_open_ex(exchange->scope.owner, exchange->trust, exchange->identity, SOLARIS_TLS_1_2,
                &tls_options, NULL, &options, &exchange->options.upstream, &tcp_callbacks, exchange, &exchange->tcp);
        } else
#endif
            rc = solaris_dialer_open_stream(exchange->scope.owner, &options, &exchange->options.upstream, &tcp_callbacks, exchange, &exchange->tcp);
        if (rc == SOLARIS_OK && exchange->settled) (void)solaris_stream_close(exchange->tcp);
    }
    if (rc != SOLARIS_OK) settle(exchange, rc);
}
static void begin(void *context)
{
    solaris_dns_exchange_t *exchange = context;
    if (live(exchange)) {
        if (exchange->options.transport != SOLARIS_DNS_TRANSPORT_UDP) start_tcp(exchange);
        else {
            solaris_dialer_options_t options = dialer(exchange);
            solaris_status_t rc = solaris_dialer_open_datagram(exchange->scope.owner, &options,
                exchange->options.upstream.family, &udp_callbacks, exchange, &exchange->udp);
            if (rc != SOLARIS_OK) settle(exchange, rc);
            else if (exchange->settled) (void)solaris_datagram_close(exchange->udp);
        }
    }
    solaris_scope_release(&exchange->scope);
}
solaris_status_t solaris_dns_exchange_start(solaris_executor_t *owner, const solaris_dns_wire_t *query,
    const solaris_dns_exchange_options_t *options, solaris_dns_exchange_fn done, void *context, solaris_dns_exchange_t **out)
{
    if (out) *out = NULL;
    if (!out || !owner || !query || !options || !done || !options->upstream.port ||
        (options->upstream.family != SOLARIS_ADDRESS_IPV4 && options->upstream.family != SOLARIS_ADDRESS_IPV6) ||
        (options->transport != SOLARIS_DNS_TRANSPORT_UDP && options->transport != SOLARIS_DNS_TRANSPORT_TCP &&
         options->transport != SOLARIS_DNS_TRANSPORT_TLS) ||
        (solaris_dns_wire_header(query)->flags & SOLARIS_DNS_QR) ||
        options->view.role < SOLARIS_DNS_ROUTE_TARGET || options->view.role > SOLARIS_DNS_CLIENT_QUERY) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner) || (options->parent_scope && options->parent_scope->owner != owner)) return SOLARIS_ETHREAD;
    if (options->parent_scope && (options->parent_scope->cancelled || options->parent_scope->finishing)) return SOLARIS_ECLOSED;
    size_t identity_length = 0;
    if (options->transport == SOLARIS_DNS_TRANSPORT_TLS) {
#if !SOLARIS_HAS_TLS
        return SOLARIS_ENOTSUP;
#else
        if (!options->tls_trust || !options->tls_identity ||
            (options->tls_require_alpn != 0 && options->tls_require_alpn != 1)) return SOLARIS_EINVAL;
        while (identity_length < 254 && options->tls_identity[identity_length]) ++identity_length;
        solaris_address_t identity;
        if (!identity_length || identity_length > 253 ||
            solaris_address_parse(options->tls_identity, 853, &identity) != SOLARIS_OK) return SOLARIS_EINVAL;
#endif
    } else if (options->tls_trust || options->tls_identity || options->tls_require_alpn) return SOLARIS_EINVAL;
    uint64_t now = solaris_executor_now_ns(owner);
    if (!options->deadline_ns || options->deadline_ns <= now) return SOLARIS_ETIMEDOUT;
    uint64_t delay = (options->deadline_ns - now - 1) / UINT64_C(1000000) + 1;
    if (delay > UINT64_MAX / UINT64_C(1000000) || now > UINT64_MAX - delay * UINT64_C(1000000)) return SOLARIS_EOVERFLOW;
    solaris_dns_exchange_options_t selected = *options;
    solaris_status_t rc = solaris_dialer_options_normalize(&options->dialer, &selected.dialer);
    if (rc != SOLARIS_OK) return rc;
    solaris_dns_wire_limits_t limits; solaris_dns_wire_limits_init(&limits);
    if (selected.wire_limits.message_bytes) limits.message_bytes = selected.wire_limits.message_bytes;
    if (selected.wire_limits.records) limits.records = selected.wire_limits.records;
    if (selected.wire_limits.pointer_hops) limits.pointer_hops = selected.wire_limits.pointer_hops;
    if (limits.message_bytes < 12 || limits.message_bytes > SOLARIS_DNS_MAX_MESSAGE ||
        limits.records > SOLARIS_DNS_MAX_RECORDS || limits.pointer_hops > SOLARIS_DNS_MAX_POINTER_HOPS) return SOLARIS_EINVAL;
    selected.wire_limits = limits;
    size_t size = solaris_buffer_length(solaris_dns_wire_buffer(query));
    if (size > limits.message_bytes || size + 2 > selected.dialer.pending_byte_limit ||
        (selected.transport == SOLARIS_DNS_TRANSPORT_UDP && size >
            (selected.upstream.family == SOLARIS_ADDRESS_IPV4 ? 65507u : 65527u))) return SOLARIS_EMSGSIZE;
    solaris_dns_exchange_t *exchange = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*exchange));
    if (!exchange) return SOLARIS_ENOMEM;
    memset(exchange, 0, sizeof(*exchange)); exchange->options = selected; exchange->done = done; exchange->context = context;
#if SOLARIS_HAS_TLS
    if (selected.transport == SOLARIS_DNS_TRANSPORT_TLS) {
        exchange->trust = selected.tls_trust; solaris_tls_context_retain(exchange->trust);
        memcpy(exchange->identity, selected.tls_identity, identity_length + 1);
        exchange->options.tls_identity = exchange->identity;
    }
#else
    (void)identity_length;
#endif
    exchange->query = query; solaris_dns_wire_retain(query);
    exchange->result = (solaris_dns_exchange_result_t){.view = selected.view, .upstream = selected.upstream,
        .transport = selected.transport, .started_ns = now, .status = SOLARIS_ECANCELLED};
    rc = solaris_scope_init(&exchange->scope, owner, cancelled, destroyed, exchange);
    if (rc != SOLARIS_OK) { destroyed(exchange); return rc; }
    if (selected.parent_scope) { exchange->parent = selected.parent_scope; solaris_scope_retain(exchange->parent); }
    now = solaris_executor_now_ns(owner);
    if (now >= options->deadline_ns) { settle(exchange, SOLARIS_ETIMEDOUT); return SOLARIS_ETIMEDOUT; }
    delay = (options->deadline_ns - now - 1) / UINT64_C(1000000) + 1;
    solaris_scope_retain(&exchange->scope);
    rc = solaris_deadline_start(owner, delay, deadline, exchange, &exchange->deadline);
    if (rc != SOLARIS_OK) { solaris_scope_release(&exchange->scope); settle(exchange, rc); return rc; }
    exchange->begin = (solaris_deferred_t){.run = begin, .context = exchange};
    solaris_scope_retain(&exchange->scope); rc = solaris_executor_defer(owner, &exchange->begin);
    if (rc != SOLARIS_OK) { solaris_scope_release(&exchange->scope); settle(exchange, rc); return rc; }
    exchange->accepted = 1; *out = exchange; return SOLARIS_OK;
}
solaris_status_t solaris_dns_exchange_cancel(solaris_dns_exchange_t *exchange)
{
    if (!exchange) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(exchange->scope.owner)) return SOLARIS_ETHREAD;
    if (exchange->delivering) return SOLARIS_ECLOSED;
    if (exchange->settled && exchange->result.status == SOLARIS_OK) {
        exchange->result.status = SOLARIS_ECANCELLED;
        exchange->result.completed_ns = solaris_executor_now_ns(exchange->scope.owner);
        exchange->result.duration_ns = exchange->result.completed_ns >= exchange->result.started_ns ?
            exchange->result.completed_ns - exchange->result.started_ns : 0;
    }
    settle(exchange, SOLARIS_ECANCELLED); return SOLARIS_OK;
}
