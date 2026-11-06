#include "adapters/outbound/shadowsocks/internal.h"
#include "adapters/outbound/shadowsocks/packet.h"
#include "dns/system/resolver.h"
#include <assert.h>
#include <string.h>

#define SS_UDP_MAX 65000u
typedef struct ss_udp {
    solaris_datagram_t datagram, *carrier;
    solaris_scope_t scope;
    solaris_deadline_t *deadline;
    solaris_resolve_t *resolve;
    solaris_ss_packet_t *codec;
    solaris_dialer_options_t options;
    solaris_datagram_callbacks_t callbacks;
    solaris_address_t server;
    solaris_io_snapshot_t stats;
    void *context;
    uint64_t expires;
    solaris_status_t close_status;
    int accepted, opened, closing, reading, writable;
} ss_udp_t;
typedef struct ss_send {
    ss_udp_t *udp; const solaris_buffer_t *plain; size_t length;
    solaris_io_done_fn done; void *context;
} ss_send_t;
static void close_status(ss_udp_t *udp, solaris_status_t status);
static void deliver_open(ss_udp_t *udp, solaris_status_t status)
{
    if (udp->opened || !udp->accepted) return;
    udp->opened = 1;
    if (udp->deadline != NULL) solaris_deadline_cancel(udp->deadline);
    udp->callbacks.on_open(udp->context, &udp->datagram, status);
}
static void cancelled(void *context)
{
    ss_udp_t *udp = context;
    if (!udp->closing) { udp->closing = 1; udp->close_status = SOLARIS_ECANCELLED; }
    if (udp->deadline != NULL) solaris_deadline_cancel(udp->deadline);
    if (udp->resolve != NULL) solaris_resolve_cancel(udp->resolve);
    if (udp->carrier != NULL) (void)solaris_datagram_close(udp->carrier);
}
static void destroyed(void *context)
{
    ss_udp_t *udp = context;
    if (udp->accepted) {
        deliver_open(udp, udp->close_status == SOLARIS_OK ? SOLARIS_ECANCELLED : udp->close_status);
        udp->callbacks.on_close(udp->context, &udp->datagram, udp->close_status);
    }
    solaris_ss_packet_destroy(udp->codec); solaris_memory_free(udp);
}
static void close_status(ss_udp_t *udp, solaris_status_t status)
{ if (!udp->closing) { udp->closing = 1; udp->close_status = status; solaris_scope_cancel(&udp->scope); } }
static void timed_out(void *context, solaris_status_t status)
{
    ss_udp_t *udp = context; udp->deadline = NULL;
    if (status == SOLARIS_OK && !udp->opened) close_status(udp, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&udp->scope);
}
static void carrier_opened(void *context, solaris_datagram_t *carrier, solaris_status_t status)
{
    ss_udp_t *udp = context;
    if (udp->scope.cancelled) return;
    if (solaris_executor_now_ns(udp->scope.owner) >= udp->expires) status = SOLARIS_ETIMEDOUT;
    if (status != SOLARIS_OK) { close_status(udp, status); return; }
    (void)solaris_datagram_set_reading(carrier, udp->reading); deliver_open(udp, SOLARIS_OK);
}
static void carrier_packet(void *context, solaris_datagram_t *carrier,
    const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    (void)carrier; ss_udp_t *udp = context;
    if (udp->scope.cancelled || !udp->reading) return;
    if (!solaris_address_equal(source, &udp->server)) { udp->stats.dropped_packets++; return; }
    solaris_buffer_t *plain = NULL; solaris_address_t peer;
    solaris_status_t rc = solaris_ss_packet_decode(udp->codec, solaris_buffer_data(buffer), solaris_buffer_length(buffer), &peer, &plain);
    if (rc == SOLARIS_OK) {
        solaris_buffer_publish(plain); udp->stats.bytes_read += solaris_buffer_length(plain); udp->stats.packets_read++;
        udp->callbacks.on_packet(udp->context, &udp->datagram, &peer, plain);
    } else { udp->stats.dropped_packets++; if (rc == SOLARIS_ENOMEM || rc == SOLARIS_EBUSY) close_status(udp, rc); }
    solaris_buffer_release(plain);
}
static void carrier_writable(void *context, solaris_datagram_t *carrier)
{
    (void)carrier; ss_udp_t *udp = context;
    if (!udp->scope.cancelled && udp->writable) {
        udp->writable = 0; if (udp->callbacks.on_writable != NULL) udp->callbacks.on_writable(udp->context, &udp->datagram);
    }
}
static void carrier_closed(void *context, solaris_datagram_t *carrier, solaris_status_t status)
{ (void)carrier; ss_udp_t *udp = context; udp->carrier = NULL; close_status(udp, status); solaris_scope_release(&udp->scope); }
static const solaris_datagram_callbacks_t carrier_callbacks = {carrier_opened, carrier_packet, carrier_writable, carrier_closed};
static solaris_status_t open_carrier(ss_udp_t *udp)
{
    solaris_dialer_options_t options = udp->options;
    if (options.pending_byte_limit > (UINT32_MAX - 65536u) / 2u) return SOLARIS_EINVAL;
    options.pending_byte_limit = options.pending_byte_limit * 2u + 65536u;
    solaris_status_t rc = solaris_dialer_open_datagram(udp->scope.owner, &options, udp->server.family,
        &carrier_callbacks, udp, &udp->carrier);
    if (rc == SOLARIS_OK) solaris_scope_retain(&udp->scope);
    return rc;
}
static void resolved(void *context, solaris_status_t status, const solaris_address_t *addresses, size_t count)
{
    ss_udp_t *udp = context; udp->resolve = NULL;
    if (!udp->scope.cancelled) {
        if (solaris_executor_now_ns(udp->scope.owner) >= udp->expires) status = SOLARIS_ETIMEDOUT;
        if (status == SOLARIS_OK && count == 0u) status = SOLARIS_EIO;
        if (status == SOLARIS_OK) {
            size_t selected = 0u;
            for (size_t i = 0u; i < count; ++i) if (addresses[i].family == SOLARIS_ADDRESS_IPV4) { selected = i; break; }
            udp->server = addresses[selected]; status = open_carrier(udp);
        }
        if (status != SOLARIS_OK) close_status(udp, status);
    }
    solaris_scope_release(&udp->scope);
}
static void sent(void *context, solaris_status_t status)
{
    ss_send_t *request = context; ss_udp_t *udp = request->udp;
    udp->stats.pending_requests--; udp->stats.pending_bytes -= request->length;
    if (status == SOLARIS_OK) { udp->stats.packets_written++; udp->stats.bytes_written += request->length; }
    request->done(request->context, status);
    if (!udp->scope.cancelled && udp->writable) carrier_writable(udp, udp->carrier);
    solaris_buffer_release(request->plain); solaris_memory_free(request); solaris_scope_release(&udp->scope);
}
static solaris_status_t send(void *state, const solaris_address_t *destination, const solaris_slice_t *data,
    solaris_io_done_fn done, void *context)
{
    ss_udp_t *udp = state;
    if (udp->scope.cancelled || !solaris_executor_accepting(udp->scope.owner)) return SOLARIS_ECLOSED;
    if (!udp->opened) return SOLARIS_EBUSY;
    if (data->length > SS_UDP_MAX || data->length > udp->options.pending_byte_limit) return SOLARIS_EMSGSIZE;
    if (udp->stats.pending_requests >= udp->options.pending_request_limit ||
        udp->stats.pending_bytes > udp->options.pending_byte_limit - data->length) { udp->writable = 1; return SOLARIS_EAGAIN; }
    ss_send_t *request = solaris_memory_allocate(solaris_executor_budget(udp->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    solaris_buffer_t *wire = NULL; solaris_status_t rc = solaris_ss_packet_encode(udp->codec, destination, data, &wire);
    if (rc == SOLARIS_OK) {
        *request = (ss_send_t){udp, data->buffer, data->length, done, context};
        solaris_slice_t slice = {wire, 0u, solaris_buffer_length(wire)};
        rc = solaris_datagram_send(udp->carrier, &udp->server, &slice, sent, request);
    }
    solaris_buffer_release(wire);
    if (rc != SOLARIS_OK) { solaris_memory_free(request); if (rc == SOLARIS_EAGAIN) udp->writable = 1; return rc; }
    solaris_buffer_retain(data->buffer); solaris_scope_retain(&udp->scope);
    udp->stats.pending_requests++; udp->stats.pending_bytes += data->length; return SOLARIS_OK;
}
static solaris_status_t reading(void *state, int enabled)
{ ss_udp_t *udp = state; if (udp->scope.cancelled) return SOLARIS_ECLOSED; udp->reading = enabled; return udp->carrier == NULL ? SOLARIS_OK : solaris_datagram_set_reading(udp->carrier, enabled); }
static solaris_status_t close_datagram(void *state) { close_status(state, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out) { *out = ((ss_udp_t *)state)->stats; return SOLARIS_OK; }
static solaris_status_t local(void *state, solaris_address_t *out)
{ ss_udp_t *udp = state; return udp->carrier == NULL ? SOLARIS_ECLOSED : solaris_datagram_local_address(udp->carrier, out); }
static const solaris_datagram_ops_t ops = {send, reading, close_datagram, snapshot, local};
static uint64_t packet_clock(void *context) { return solaris_executor_now_ns(context); }
solaris_status_t solaris_ss_udp_open(solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *server, const solaris_ss_parameters_t *parameters,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || server == NULL || parameters == NULL || callbacks == NULL ||
        callbacks->on_open == NULL || callbacks->on_packet == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    ss_udp_t *udp = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*udp));
    if (udp == NULL) return SOLARIS_ENOMEM;
    memset(udp, 0, sizeof(*udp));
    udp->callbacks = *callbacks; udp->context = context; udp->server = *server; udp->reading = 1;
    udp->datagram = (solaris_datagram_t){&ops, udp, owner}; udp->stats.max_message_bytes = SS_UDP_MAX;
    solaris_status_t rc = solaris_dialer_options_normalize(options, &udp->options);
    if (rc == SOLARIS_OK) rc = solaris_ss_packet_create(solaris_executor_budget(owner), parameters, packet_clock, owner, &udp->codec);
    if (rc != SOLARIS_OK) { destroyed(udp); return rc; }
    rc = solaris_scope_init(&udp->scope, owner, cancelled, destroyed, udp);
    if (rc != SOLARIS_OK) { destroyed(udp); return rc; }
    uint64_t now = solaris_executor_now_ns(owner), duration = udp->options.open_timeout_ms * UINT64_C(1000000);
    if (duration > UINT64_MAX - now) { close_status(udp, SOLARIS_EOVERFLOW); return SOLARIS_EOVERFLOW; }
    udp->expires = now + duration;
    rc = solaris_deadline_start(owner, udp->options.open_timeout_ms, timed_out, udp, &udp->deadline);
    if (rc != SOLARIS_OK) { close_status(udp, rc); return rc; }
    solaris_scope_retain(&udp->scope);
    if (server->family == SOLARIS_ADDRESS_DOMAIN) {
        rc = solaris_resolve_start(owner, server, 0u, resolved, udp, &udp->resolve);
        if (rc == SOLARIS_OK) solaris_scope_retain(&udp->scope);
    } else rc = open_carrier(udp);
    if (rc != SOLARIS_OK) { close_status(udp, rc); return rc; }
    udp->accepted = 1; *out = &udp->datagram; return SOLARIS_OK;
}
