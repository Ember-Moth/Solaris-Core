#include "adapters/outbound/socks5/internal.h"
#include "dns/system/resolver.h"
#include <assert.h>
#include <limits.h>
#include <string.h>

enum { RESOLVE_SERVER, RESOLVE_RELAY };
typedef struct socks5_udp {
    solaris_datagram_t datagram, *carrier;
    solaris_stream_t *control;
    solaris_scope_t scope;
    solaris_deferred_t opened;
    solaris_deadline_t *deadline;
    solaris_resolve_t *resolve;
    solaris_stream_factory_t stream_factory;
    solaris_dialer_options_t options;
    solaris_socks5_credentials_t credentials;
    solaris_socks5_open_info_t control_info;
    solaris_address_t server, candidates[SOLARIS_RESOLVER_MAX_ADDRESSES], relay;
    size_t candidate_count, candidate;
    solaris_datagram_callbacks_t callbacks;
    solaris_io_snapshot_t stats;
    void *context;
    uint64_t expires;
    solaris_status_t status, open_status;
    int accepted, open_settled, open_delivered, closing, reading, writable, resolve_kind, retry_control;
} socks5_udp_t;
typedef struct socks5_send {
    socks5_udp_t *udp;
    const solaris_buffer_t *plain;
    size_t length;
    solaris_io_done_fn done;
    void *context;
} socks5_send_t;
static void close_status(socks5_udp_t *udp, solaris_status_t status);
static solaris_status_t start_control(socks5_udp_t *udp);
static solaris_status_t start_datagram(socks5_udp_t *udp);
static void deliver_open(void *context)
{
    socks5_udp_t *udp = context;
    if (udp->open_status == SOLARIS_OK && !udp->scope.cancelled && solaris_executor_now_ns(udp->scope.owner) >= udp->expires)
        close_status(udp, SOLARIS_ETIMEDOUT);
    if (udp->open_status == SOLARIS_OK && udp->scope.cancelled) udp->open_status = udp->status == SOLARIS_OK ? SOLARIS_ECANCELLED : udp->status;
    udp->open_delivered = 1;
    udp->callbacks.on_open(udp->context, &udp->datagram, udp->open_status);
    if (!udp->scope.cancelled && udp->carrier != NULL) (void)solaris_datagram_set_reading(udp->carrier, udp->reading);
    solaris_scope_release(&udp->scope);
}
static void settle_open(socks5_udp_t *udp, solaris_status_t status)
{
    if (!udp->accepted || udp->open_settled) return;
    udp->open_settled = 1; udp->open_status = status;
    if (udp->deadline != NULL) solaris_deadline_cancel(udp->deadline);
    solaris_scope_retain(&udp->scope); solaris_status_t rc = solaris_executor_defer(udp->scope.owner, &udp->opened); assert(rc == SOLARIS_OK); (void)rc;
}
static void cancelled(void *context)
{
    socks5_udp_t *udp = context;
    if (!udp->closing) { udp->closing = 1; udp->status = SOLARIS_ECANCELLED; }
    settle_open(udp, udp->status == SOLARIS_OK ? SOLARIS_ECANCELLED : udp->status);
    if (udp->deadline != NULL) solaris_deadline_cancel(udp->deadline);
    if (udp->resolve != NULL) solaris_resolve_cancel(udp->resolve);
    if (udp->control != NULL) (void)solaris_stream_close(udp->control);
    if (udp->carrier != NULL) (void)solaris_datagram_close(udp->carrier);
}
static void destroyed(void *context)
{
    socks5_udp_t *udp = context; assert(udp->control == NULL && udp->carrier == NULL && udp->resolve == NULL);
    if (udp->accepted) udp->callbacks.on_close(udp->context, &udp->datagram, udp->status);
    solaris_socks5_clear(udp, sizeof(*udp)); solaris_memory_free(udp);
}
static void close_status(socks5_udp_t *udp, solaris_status_t status)
{ if (!udp->closing) { udp->closing = 1; udp->status = status; solaris_scope_cancel(&udp->scope); } }
static int expired(socks5_udp_t *udp) { return solaris_executor_now_ns(udp->scope.owner) >= udp->expires; }
static void deadline(void *context, solaris_status_t status)
{
    socks5_udp_t *udp = context; udp->deadline = NULL;
    if (status == SOLARIS_OK && !udp->open_settled) close_status(udp, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&udp->scope);
}
static int unspecified(const solaris_address_t *address)
{
    size_t size = address->family == SOLARIS_ADDRESS_IPV4 ? 4u : address->family == SOLARIS_ADDRESS_IPV6 ? 16u : 0u;
    if (size == 0u) return 0;
    for (size_t i = 0u; i < size; ++i) if (address->ip[i] != 0u) return 0;
    return 1;
}
static int usable_family(socks5_udp_t *udp, const solaris_address_t *address)
{
    return (address->family == SOLARIS_ADDRESS_IPV4 || address->family == SOLARIS_ADDRESS_IPV6) &&
        (udp->options.local_bind.family == 0u || udp->options.local_bind.family == address->family);
}
static void resolved(void *context, solaris_status_t status, const solaris_address_t *addresses, size_t count)
{
    socks5_udp_t *udp = context; udp->resolve = NULL;
    if (!udp->scope.cancelled) {
        if (expired(udp)) status = SOLARIS_ETIMEDOUT;
        if (status == SOLARIS_OK && udp->resolve_kind == RESOLVE_SERVER) {
            udp->candidate_count = udp->candidate = 0u;
            for (unsigned int pass = 0; pass < 2; ++pass) {
                uint32_t family = pass == 0 ? SOLARIS_ADDRESS_IPV4 : SOLARIS_ADDRESS_IPV6;
                for (size_t i = 0; i < count && udp->candidate_count < SOLARIS_RESOLVER_MAX_ADDRESSES; ++i) {
                    if (usable_family(udp, &addresses[i]) && addresses[i].family == family)
                        udp->candidates[udp->candidate_count++] = addresses[i];
                }
            }
            status = udp->candidate_count == 0u ? SOLARIS_EIO : start_control(udp);
        } else if (status == SOLARIS_OK) {
            size_t selected = count;
            for (size_t i = 0u; i < count; ++i) if (usable_family(udp, &addresses[i])) {
                if (selected == count) selected = i;
                if (addresses[i].family == udp->server.family) { selected = i; break; }
            }
            if (selected == count) status = SOLARIS_EIO;
            else { udp->relay = addresses[selected]; status = start_datagram(udp); }
        }
        if (status != SOLARIS_OK) close_status(udp, status);
    }
    solaris_scope_release(&udp->scope);
}
static void control_opened(void *context, solaris_stream_t *control, solaris_status_t status)
{
    (void)control; socks5_udp_t *udp = context;
    if (udp->scope.cancelled) return;
    if (expired(udp)) status = SOLARIS_ETIMEDOUT;
    if (status != SOLARIS_OK) {
        if (!udp->control_info.carrier_connected && !expired(udp) && (status == SOLARIS_EIO || status == SOLARIS_ETIMEDOUT) && udp->candidate + 1u < udp->candidate_count)
            udp->retry_control = 1;
        else close_status(udp, status);
        return;
    }
    udp->relay = udp->control_info.bound;
    if (udp->relay.port == 0u) { close_status(udp, SOLARIS_EIO); return; }
    if (udp->relay.family == SOLARIS_ADDRESS_DOMAIN) {
        udp->resolve_kind = RESOLVE_RELAY;
        status = solaris_resolve_start(udp->scope.owner, &udp->relay, 0u, resolved, udp, &udp->resolve);
        if (status == SOLARIS_OK) solaris_scope_retain(&udp->scope);
    } else status = start_datagram(udp);
    if (status != SOLARIS_OK) close_status(udp, status);
}
static void control_data(void *context, solaris_stream_t *control, const solaris_buffer_t *buffer)
{ (void)control; (void)buffer; socks5_udp_t *udp = context; if (!udp->scope.cancelled) close_status(udp, SOLARIS_EIO); }
static void control_eof(void *context, solaris_stream_t *control)
{ (void)control; socks5_udp_t *udp = context; if (!udp->scope.cancelled) close_status(udp, SOLARIS_EIO); }
static void control_closed(void *context, solaris_stream_t *control, solaris_status_t status)
{
    (void)control; socks5_udp_t *udp = context; udp->control = NULL;
    if (!udp->scope.cancelled) {
        if (udp->retry_control && !expired(udp)) {
            udp->retry_control = 0; udp->candidate++; status = start_control(udp);
            if (status != SOLARIS_OK) close_status(udp, status);
        } else close_status(udp, expired(udp) && !udp->open_settled ? SOLARIS_ETIMEDOUT : status == SOLARIS_OK ? SOLARIS_EIO : status);
    }
    solaris_scope_release(&udp->scope);
}
static const solaris_stream_callbacks_t control_callbacks = {control_opened, control_data, control_eof, NULL, control_closed};
static solaris_status_t start_control(socks5_udp_t *udp)
{
    uint64_t now = solaris_executor_now_ns(udp->scope.owner);
    if (now >= udp->expires) return SOLARIS_ETIMEDOUT;
    udp->server = udp->candidates[udp->candidate];
    solaris_address_t wildcard = {.family = udp->server.family};
    solaris_dialer_options_t options = udp->options;
    uint64_t remaining = udp->expires - now;
    options.open_timeout_ms = remaining / UINT64_C(1000000) + (remaining % UINT64_C(1000000) != 0u);
    if (options.open_timeout_ms == 0u) return SOLARIS_ETIMEDOUT;
    solaris_status_t rc = solaris_socks5_stream_open(udp->scope.owner, &udp->stream_factory, &options, &udp->server,
        &udp->credentials, 3u, &wildcard, &udp->control_info, &control_callbacks, udp, &udp->control);
    if (rc == SOLARIS_OK) solaris_scope_retain(&udp->scope);
    return rc;
}
static void carrier_opened(void *context, solaris_datagram_t *carrier, solaris_status_t status)
{
    socks5_udp_t *udp = context; if (udp->scope.cancelled) return;
    if (expired(udp)) status = SOLARIS_ETIMEDOUT;
    if (status != SOLARIS_OK) { close_status(udp, status); return; }
    (void)solaris_datagram_set_reading(carrier, 0); settle_open(udp, SOLARIS_OK);
}
static void carrier_packet(void *context, solaris_datagram_t *carrier, const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    (void)carrier; socks5_udp_t *udp = context; if (udp->scope.cancelled || !udp->reading) return;
    if (!udp->open_delivered || udp->open_status != SOLARIS_OK) { udp->stats.dropped_packets++; return; }
    if (!solaris_address_equal(source, &udp->relay)) { udp->stats.dropped_packets++; return; }
    solaris_buffer_t *plain = NULL; solaris_address_t peer;
    solaris_status_t rc = solaris_socks5_packet_decode(solaris_executor_budget(udp->scope.owner), solaris_buffer_data(buffer), solaris_buffer_length(buffer), &peer, &plain);
    if (rc == SOLARIS_OK) {
        udp->stats.bytes_read += solaris_buffer_length(plain); udp->stats.packets_read++;
        udp->callbacks.on_packet(udp->context, &udp->datagram, &peer, plain);
    } else { udp->stats.dropped_packets++; if (rc == SOLARIS_ENOMEM) close_status(udp, rc); }
    solaris_buffer_release(plain);
}
static void carrier_writable(void *context, solaris_datagram_t *carrier)
{
    (void)carrier; socks5_udp_t *udp = context;
    if (udp->writable && !udp->scope.cancelled) { udp->writable = 0; if (udp->callbacks.on_writable != NULL) udp->callbacks.on_writable(udp->context, &udp->datagram); }
}
static void carrier_closed(void *context, solaris_datagram_t *carrier, solaris_status_t status)
{
    (void)carrier; socks5_udp_t *udp = context; udp->carrier = NULL;
    if (!udp->scope.cancelled) close_status(udp, status == SOLARIS_OK ? SOLARIS_EIO : status);
    solaris_scope_release(&udp->scope);
}
static const solaris_datagram_callbacks_t carrier_callbacks = {carrier_opened, carrier_packet, carrier_writable, carrier_closed};
static solaris_status_t start_datagram(socks5_udp_t *udp)
{
    if (expired(udp)) return SOLARIS_ETIMEDOUT;
    if (unspecified(&udp->relay)) { uint16_t port = udp->relay.port; udp->relay = udp->server; udp->relay.port = port; }
    if (!usable_family(udp, &udp->relay) || udp->relay.port == 0u) return SOLARIS_EIO;
    solaris_dialer_options_t options = udp->options;
    uint64_t wire_limit = (uint64_t)options.pending_byte_limit + (uint64_t)options.pending_request_limit * 262u;
    options.pending_byte_limit = wire_limit > UINT_MAX ? UINT_MAX : (size_t)wire_limit;
    solaris_status_t rc = solaris_dialer_open_datagram(udp->scope.owner, &options, udp->relay.family, &carrier_callbacks, udp, &udp->carrier);
    if (rc == SOLARIS_OK) solaris_scope_retain(&udp->scope);
    return rc;
}
static void sent(void *context, solaris_status_t status)
{
    socks5_send_t *request = context; socks5_udp_t *udp = request->udp;
    udp->stats.pending_requests--; udp->stats.pending_bytes -= request->length;
    if (status == SOLARIS_OK) { udp->stats.packets_written++; udp->stats.bytes_written += request->length; }
    request->done(request->context, status);
    if (!udp->scope.cancelled && udp->writable) carrier_writable(udp, udp->carrier);
    solaris_buffer_release(request->plain); solaris_memory_free(request); solaris_scope_release(&udp->scope);
}
static solaris_status_t send_packet(void *state, const solaris_address_t *target, const solaris_slice_t *data, solaris_io_done_fn done, void *context)
{
    socks5_udp_t *udp = state;
    if (udp->scope.cancelled || !solaris_executor_accepting(udp->scope.owner)) return SOLARIS_ECLOSED;
    if (!udp->open_delivered || udp->open_status != SOLARIS_OK || udp->carrier == NULL) return SOLARIS_EBUSY;
    if (data->length > SOLARIS_SOCKS5_UDP_MAX || data->length > udp->options.pending_byte_limit) return SOLARIS_EMSGSIZE;
    if (udp->stats.pending_requests >= udp->options.pending_request_limit || udp->stats.pending_bytes > udp->options.pending_byte_limit - data->length) {
        udp->writable = 1; return SOLARIS_EAGAIN;
    }
    socks5_send_t *request = solaris_memory_allocate(solaris_executor_budget(udp->scope.owner), sizeof(*request)); if (request == NULL) return SOLARIS_ENOMEM;
    solaris_buffer_t *wire = NULL; solaris_status_t rc = solaris_socks5_packet_encode(solaris_executor_budget(udp->scope.owner), target, data, &wire);
    if (rc == SOLARIS_OK) {
        *request = (socks5_send_t){udp, data->buffer, data->length, done, context};
        solaris_slice_t slice = {wire, 0u, solaris_buffer_length(wire)};
        rc = solaris_datagram_send(udp->carrier, &udp->relay, &slice, sent, request);
    }
    solaris_buffer_release(wire);
    if (rc != SOLARIS_OK) { solaris_memory_free(request); if (rc == SOLARIS_EAGAIN) udp->writable = 1; return rc; }
    solaris_buffer_retain(data->buffer); solaris_scope_retain(&udp->scope);
    udp->stats.pending_requests++; udp->stats.pending_bytes += data->length; return SOLARIS_OK;
}
static solaris_status_t reading(void *state, int enabled)
{
    socks5_udp_t *udp = state; if (udp->scope.cancelled) return SOLARIS_ECLOSED; udp->reading = enabled;
    return udp->carrier == NULL || !udp->open_delivered ? SOLARIS_OK : solaris_datagram_set_reading(udp->carrier, enabled);
}
static solaris_status_t close_datagram(void *state) { close_status(state, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out) { *out = ((socks5_udp_t *)state)->stats; return SOLARIS_OK; }
static solaris_status_t local_address(void *state, solaris_address_t *out)
{ socks5_udp_t *udp = state; return udp->carrier == NULL ? SOLARIS_ECLOSED : solaris_datagram_local_address(udp->carrier, out); }
static const solaris_datagram_ops_t operations = {send_packet, reading, close_datagram, snapshot, local_address};
solaris_status_t solaris_socks5_udp_open(solaris_executor_t *owner,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *server, const solaris_socks5_credentials_t *credentials,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || server == NULL || server->port == 0u || credentials == NULL || callbacks == NULL ||
        callbacks->on_open == NULL || callbacks->on_packet == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    socks5_udp_t *udp = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*udp)); if (udp == NULL) return SOLARIS_ENOMEM;
    memset(udp, 0, sizeof(*udp)); udp->callbacks = *callbacks; udp->context = context; udp->credentials = *credentials; udp->server = *server; udp->reading = 1;
    if (carrier != NULL) udp->stream_factory = *carrier;
    udp->datagram = (solaris_datagram_t){&operations, udp, owner}; udp->stats.max_message_bytes = SOLARIS_SOCKS5_UDP_MAX;
    udp->opened = (solaris_deferred_t){.run = deliver_open, .context = udp};
    solaris_status_t rc = solaris_dialer_options_normalize(options, &udp->options); if (rc != SOLARIS_OK) { destroyed(udp); return rc; }
    rc = solaris_scope_init(&udp->scope, owner, cancelled, destroyed, udp); if (rc != SOLARIS_OK) { destroyed(udp); return rc; }
    uint64_t now = solaris_executor_now_ns(owner), duration = udp->options.open_timeout_ms * UINT64_C(1000000);
    if (now > UINT64_MAX - duration) { close_status(udp, SOLARIS_EOVERFLOW); return SOLARIS_EOVERFLOW; }
    udp->expires = now + duration;
    rc = solaris_deadline_start(owner, udp->options.open_timeout_ms, deadline, udp, &udp->deadline);
    if (rc != SOLARIS_OK) { close_status(udp, rc); return rc; }
    solaris_scope_retain(&udp->scope);
    if (server->family == SOLARIS_ADDRESS_DOMAIN) {
        udp->resolve_kind = RESOLVE_SERVER; rc = solaris_resolve_start(owner, server, 0u, resolved, udp, &udp->resolve);
        if (rc == SOLARIS_OK) solaris_scope_retain(&udp->scope);
    } else if (usable_family(udp, server)) { udp->candidate_count = 1u; udp->candidates[0] = *server; rc = start_control(udp); }
    else rc = SOLARIS_EINVAL;
    if (rc != SOLARIS_OK) { close_status(udp, rc); return rc; }
    udp->accepted = 1; *out = &udp->datagram; return SOLARIS_OK;
}
