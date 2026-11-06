#include "adapters/outbound/vless/datagram.h"
#include "codec/xudp/codec.h"

typedef struct vless_datagram { void *codec; int reject_udp443; } vless_datagram_t;
static solaris_status_t create(const void *parameters, solaris_budget_t *budget, void **out)
{
    vless_datagram_t *state = solaris_memory_allocate(budget, sizeof(*state));
    if (state == NULL) return SOLARIS_ENOMEM;
    state->codec = NULL; state->reject_udp443 = parameters != NULL && *(const int *)parameters;
    solaris_status_t rc = solaris_xudp_codec.create(NULL, budget, &state->codec);
    if (rc != SOLARIS_OK) { solaris_memory_free(state); return rc; }
    *out = state; return SOLARIS_OK;
}
static solaris_status_t start(void *state, solaris_buffer_t **out)
{ return solaris_xudp_codec.start(((vless_datagram_t *)state)->codec, out); }
static solaris_status_t encode(void *context, const solaris_address_t *destination, const solaris_slice_t *plain, solaris_buffer_t **out)
{
    vless_datagram_t *state = context; *out = NULL;
    if (state->reject_udp443 && destination->port == 443u) return SOLARIS_EACCESS;
    return solaris_xudp_codec.encode(state->codec, destination, plain, out);
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size, size_t *consumed,
    solaris_address_t *source, solaris_buffer_t **out)
{ return solaris_xudp_codec.decode(((vless_datagram_t *)state)->codec, wire, size, consumed, source, out); }
static solaris_status_t finish(void *state) { return solaris_xudp_codec.finish(((vless_datagram_t *)state)->codec); }
static void destroy(void *context)
{ vless_datagram_t *state = context; solaris_xudp_codec.destroy(state->codec); solaris_memory_free(state); }
const solaris_datagram_codec_ops_t solaris_vless_xudp_codec = {
    2u + 265u + 2u + UINT16_MAX, UINT16_MAX, create, start, encode, decode, finish, destroy
};

#include "adapters/outbound/vless/internal.h"
#include "adapters/outbound/vless/vision/codec.h"
#include <openssl/rand.h>
#include <assert.h>
#include <string.h>

/* Physical generations never overlap: the shared backend's on_close is its
 * completion barrier, including every accepted send and late carrier callback.
 * One extra logical scope keeps copied settings alive between generations. */
typedef struct recovering_xudp {
    solaris_datagram_t datagram;
    solaris_scope_t scope;
    solaris_deferred_t reconnect;
    solaris_vless_datagram_parameters_t parameters;
    solaris_stream_factory_t physical_factory;
    solaris_stream_codec_ops_t encryption_codec, protocol_codec;
    solaris_stream_codec_carrier_raw_t protocol_raw;
    solaris_xudp_parameters_t identity;
    solaris_datagram_callbacks_t callbacks;
    solaris_datagram_t *current;
    solaris_io_snapshot_t totals;
    void *context;
    uint64_t generation;
    solaris_status_t status;
    unsigned int failures;
    int accepted, opened, ready, reading, confirmed, terminal, partial, waiting, wire_lost, close_requested;
} recovering_xudp_t;

typedef struct recovering_codec {
    vless_datagram_t base;
    recovering_xudp_t *channel;
} recovering_codec_t;
static solaris_status_t recovery_codec_create(const void *parameters, solaris_budget_t *budget, void **out)
{
    recovering_xudp_t *channel = (recovering_xudp_t *)parameters;
    recovering_codec_t *state = solaris_memory_allocate(budget, sizeof(*state));
    if (state == NULL) return SOLARIS_ENOMEM;
    memset(state, 0, sizeof(*state)); state->channel = channel;
    state->base.reject_udp443 = channel->parameters.reject_udp443;
    solaris_status_t rc = solaris_xudp_codec.create(&channel->identity, budget, &state->base.codec);
    if (rc != SOLARIS_OK) { solaris_memory_free(state); return rc; }
    *out = state; return SOLARIS_OK;
}
static solaris_status_t recovery_codec_decode(void *context, const uint8_t *wire, size_t size,
    size_t *consumed, solaris_address_t *source, solaris_buffer_t **out)
{
    recovering_codec_t *state = context;
    solaris_status_t rc = decode(&state->base, wire, size, consumed, source, out);
    state->channel->partial &= ~1;
    if (rc == SOLARIS_EAGAIN && size != 0u) state->channel->partial |= 1;
    if (rc != SOLARIS_OK && rc != SOLARIS_EAGAIN) state->channel->terminal = 1;
    return rc;
}
static const solaris_datagram_codec_ops_t recovery_codec = {
    2u + 273u + 2u + UINT16_MAX, UINT16_MAX,
    recovery_codec_create, start, encode, recovery_codec_decode, finish, destroy
};
static void recovery_close(recovering_xudp_t *channel, solaris_status_t status)
{
    if (channel->scope.cancelled) return;
    channel->close_requested = 1; channel->status = status; solaris_scope_cancel(&channel->scope);
}
static void recovery_cancelled(void *context)
{
    recovering_xudp_t *channel = context;
    if (!channel->close_requested) channel->status = SOLARIS_ECANCELLED;
    if (channel->current != NULL) (void)solaris_datagram_close(channel->current);
}
static void recovery_destroyed(void *context)
{
    recovering_xudp_t *channel = context;
    assert(channel->current == NULL);
    if (channel->accepted) {
        if (!channel->opened) channel->callbacks.on_open(channel->context, &channel->datagram,
            channel->status == SOLARIS_OK ? SOLARIS_ECANCELLED : channel->status);
        channel->callbacks.on_close(channel->context, &channel->datagram, channel->status);
    }
    solaris_proxy_transport_clear(&channel->parameters.transport);
    solaris_vless_encryption_client_release(channel->parameters.encryption);
    solaris_traffic_counter_release(channel->parameters.transport.dialer.traffic);
    solaris_memory_free(channel);
}
/* Observe only the physical carrier. A protocol's local close is not a
 * transport loss, so malformed TLS records cannot trigger reconnect simply
 * because their filter reports EIO. */
typedef struct recovery_wire {
    recovering_xudp_t *channel;
    solaris_stream_callbacks_t callbacks;
    void *context;
} recovery_wire_t;
static void wire_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{ recovery_wire_t *wire = context; wire->callbacks.on_open(wire->context, stream, status); }
static void wire_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{ recovery_wire_t *wire = context; wire->callbacks.on_data(wire->context, stream, buffer); }
static void wire_eof(void *context, solaris_stream_t *stream)
{
    recovery_wire_t *wire = context; wire->channel->wire_lost = 1;
    wire->callbacks.on_eof(wire->context, stream);
}
static void wire_writable(void *context, solaris_stream_t *stream)
{ recovery_wire_t *wire = context; if (wire->callbacks.on_writable != NULL) wire->callbacks.on_writable(wire->context, stream); }
static void wire_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    recovery_wire_t *wire = context;
    if (status == SOLARIS_EIO || status == SOLARIS_ECLOSED) wire->channel->wire_lost = 1;
    wire->callbacks.on_close(wire->context, stream, status);
    solaris_scope_release(&wire->channel->scope); solaris_memory_free(wire);
}
static const solaris_stream_callbacks_t wire_callbacks = {wire_opened, wire_data, wire_eof, wire_writable, wire_closed};
static solaris_status_t recovery_physical(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *callback_context, solaris_stream_t **out)
{
    recovering_xudp_t *channel = context;
    recovery_wire_t *wire = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*wire));
    if (wire == NULL) return SOLARIS_ENOMEM;
    *wire = (recovery_wire_t){channel, *callbacks, callback_context};
    solaris_status_t rc = solaris_carrier_open(&channel->physical_factory, owner, options, peer,
        &wire_callbacks, wire, out);
    if (rc != SOLARIS_OK) solaris_memory_free(wire);
    else solaris_scope_retain(&channel->scope);
    return rc;
}
/* Decorate the existing protocol codecs without duplicating their framing.
 * Each layer owns a separate partial-input bit, so a fully decoded outer
 * record cannot erase an incomplete inner frame. */
typedef struct observed_parameters {
    recovering_xudp_t *channel;
    const solaris_stream_codec_ops_t *ops;
    const void *parameters;
    int partial_bit;
} observed_parameters_t;
typedef struct observed_codec {
    observed_parameters_t parameters;
    void *state;
} observed_codec_t;
static solaris_status_t observed_create(const void *parameters, solaris_budget_t *budget, void **out)
{
    const observed_parameters_t *p = parameters;
    observed_codec_t *codec = solaris_memory_allocate(budget, sizeof(*codec));
    if (codec == NULL) return SOLARIS_ENOMEM;
    memset(codec, 0, sizeof(*codec)); codec->parameters = *p; codec->parameters.parameters = NULL;
    solaris_status_t rc = p->ops->create(p->parameters, budget, &codec->state);
    if (rc != SOLARIS_OK) { solaris_memory_free(codec); return rc; }
    solaris_scope_retain(&p->channel->scope);
    *out = codec; return SOLARIS_OK;
}
static solaris_status_t observed_start(void *context, solaris_buffer_t **out)
{ observed_codec_t *codec = context; return codec->parameters.ops->start(codec->state, out); }
static solaris_status_t observed_encode(void *context, const solaris_slice_t *plain, solaris_buffer_t **out)
{ observed_codec_t *codec = context; return codec->parameters.ops->encode(codec->state, plain, out); }
static solaris_status_t observed_decode(void *context, const uint8_t *wire, size_t size, size_t *consumed, solaris_buffer_t **out)
{
    observed_codec_t *codec = context; recovering_xudp_t *channel = codec->parameters.channel;
    solaris_status_t rc = codec->parameters.ops->decode(codec->state, wire, size, consumed, out);
    channel->partial &= ~codec->parameters.partial_bit;
    if (rc == SOLARIS_EAGAIN && size != 0u) channel->partial |= codec->parameters.partial_bit;
    if (rc != SOLARIS_OK && rc != SOLARIS_EAGAIN) channel->terminal = 1;
    return rc;
}
static solaris_status_t observed_finish(void *context)
{
    observed_codec_t *codec = context; solaris_status_t rc = codec->parameters.ops->finish(codec->state);
    if (rc != SOLARIS_OK) codec->parameters.channel->terminal = 1;
    return rc;
}
static void observed_destroy(void *context)
{ observed_codec_t *codec = context; codec->parameters.ops->destroy(codec->state);
    solaris_scope_release(&codec->parameters.channel->scope); solaris_memory_free(codec); }
static int observed_ready(void *context)
{ observed_codec_t *codec = context; return codec->parameters.ops->ready(codec->state); }
static solaris_status_t observed_preface(void *context, solaris_buffer_t **out, uint64_t *delay)
{ observed_codec_t *codec = context; return codec->parameters.ops->next_preface(codec->state, out, delay); }
static solaris_status_t observed_read_raw(void *context)
{ observed_codec_t *codec = context; return codec->parameters.ops->raw->read(codec->state); }
static solaris_status_t observed_write_raw(void *context)
{ observed_codec_t *codec = context; return codec->parameters.ops->raw->write(codec->state); }
static uint32_t observed_requested(void *context)
{ observed_codec_t *codec = context; return codec->parameters.ops->carrier_raw->requested(codec->state); }
static void observed_applied(void *context, uint32_t directions)
{ observed_codec_t *codec = context; codec->parameters.ops->carrier_raw->applied(codec->state, directions); }
static const solaris_stream_codec_raw_ops_t observed_raw = {observed_read_raw, observed_write_raw};
static void observe_codec(solaris_stream_codec_ops_t *out, const solaris_stream_codec_ops_t *ops,
    solaris_stream_codec_carrier_raw_t *carrier_raw)
{
    *out = *ops; out->create = observed_create; out->start = observed_start; out->encode = observed_encode;
    out->decode = observed_decode; out->finish = observed_finish; out->destroy = observed_destroy;
    if (ops->ready != NULL) out->ready = observed_ready;
    if (ops->next_preface != NULL) out->next_preface = observed_preface;
    if (ops->raw != NULL) out->raw = &observed_raw;
    if (ops->carrier_raw != NULL) {
        *carrier_raw = (solaris_stream_codec_carrier_raw_t){ops->carrier_raw->required, observed_requested, observed_applied};
        out->carrier_raw = carrier_raw;
    }
}
static solaris_status_t recovery_carrier(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *callback_context, solaris_stream_t **out)
{
    recovering_xudp_t *channel = context;
    solaris_vless_datagram_parameters_t *p = &channel->parameters;
    if (p->encryption == NULL)
        return solaris_proxy_transport_open(&p->transport, owner, options, peer, callbacks, callback_context, out);
    solaris_stream_factory_t factory = {.context = &p->transport, .open = solaris_proxy_transport_open};
    observed_parameters_t observed = {channel, &solaris_vless_encryption_codec, p->encryption, 2};
    return solaris_filter_open(owner, &factory, options, peer, &channel->encryption_codec,
        &observed, callbacks, callback_context, out);
}
static solaris_status_t recovery_mux(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *callback_context, solaris_stream_t **out)
{
    recovering_xudp_t *channel = context;
    solaris_vless_parameters_t request = {.command = 3u};
    memcpy(request.uuid, channel->parameters.uuid, sizeof(request.uuid));
    solaris_stream_factory_t factory = {.context = channel, .open = recovery_carrier};
    if (channel->parameters.vision) {
        request.vision = 1u;
        solaris_vless_vision_parameters_t vision = {.request = request, .crypto = channel->parameters.crypto};
        observed_parameters_t observed = {channel, &solaris_vless_vision_codec, &vision, 4};
        return solaris_filter_open(owner, &factory, options, peer, &channel->protocol_codec,
            &observed, callbacks, callback_context, out);
    }
    observed_parameters_t observed = {channel, &solaris_vless_stream_codec, &request, 4};
    return solaris_filter_open(owner, &factory, options, peer, &channel->protocol_codec,
        &observed, callbacks, callback_context, out);
}
static void recovery_opened(void *context, solaris_datagram_t *current, solaris_status_t status)
{
    recovering_xudp_t *channel = context; assert(current == channel->current);
    channel->ready = status == SOLARIS_OK && !channel->scope.cancelled;
    if (!channel->opened) {
        channel->opened = 1;
        channel->callbacks.on_open(channel->context, &channel->datagram,
            channel->scope.cancelled ? SOLARIS_ECANCELLED : status);
    } else if (channel->ready && channel->waiting) {
        channel->waiting = 0;
        if (channel->callbacks.on_writable != NULL)
            channel->callbacks.on_writable(channel->context, &channel->datagram);
    }
    if (status != SOLARIS_OK) recovery_close(channel, status);
}
static void recovery_packet(void *context, solaris_datagram_t *current,
    const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    recovering_xudp_t *channel = context; assert(current == channel->current);
    if (channel->scope.cancelled) return;
    channel->confirmed = 1; channel->failures = 0u;
    channel->callbacks.on_packet(channel->context, &channel->datagram, source, buffer);
}
static void recovery_writable(void *context, solaris_datagram_t *current)
{
    recovering_xudp_t *channel = context; assert(current == channel->current);
    if (!channel->scope.cancelled && channel->callbacks.on_writable != NULL)
        channel->callbacks.on_writable(channel->context, &channel->datagram);
}
static solaris_status_t recovery_next(recovering_xudp_t *channel);
static void recovery_reconnect(void *context)
{
    recovering_xudp_t *channel = context;
    if (!channel->scope.cancelled) {
        solaris_status_t rc = recovery_next(channel);
        if (rc != SOLARIS_OK) recovery_close(channel, rc);
    }
    solaris_scope_release(&channel->scope);
}
static void recovery_closed(void *context, solaris_datagram_t *current, solaris_status_t status)
{
    recovering_xudp_t *channel = context; assert(current == channel->current);
    solaris_io_snapshot_t stats; (void)solaris_datagram_get_snapshot(current, &stats);
    channel->totals.bytes_read += stats.bytes_read; channel->totals.bytes_written += stats.bytes_written;
    channel->totals.packets_read += stats.packets_read; channel->totals.packets_written += stats.packets_written;
    channel->totals.dropped_packets += stats.dropped_packets;
    channel->current = NULL; channel->ready = 0;
    if (!channel->scope.cancelled) {
        /* No identity is migrated until a real reply proves initial remote
         * acceptance. Malformed framing/End and partial EOF are terminal.
         * A new generation with no replies gets only one retry. */
        if (channel->confirmed && channel->wire_lost && !channel->terminal && !channel->partial &&
            (status == SOLARIS_OK || status == SOLARIS_EIO || status == SOLARIS_ECLOSED) &&
            ++channel->failures <= 2u && solaris_executor_accepting(channel->scope.owner)) {
            solaris_scope_retain(&channel->scope);
            solaris_status_t rc = solaris_executor_defer(channel->scope.owner, &channel->reconnect);
            assert(rc == SOLARIS_OK); (void)rc;
        } else recovery_close(channel, status);
    }
    solaris_scope_release(&channel->scope);
}
static const solaris_datagram_callbacks_t recovery_callbacks = {
    recovery_opened, recovery_packet, recovery_writable, recovery_closed
};
static solaris_status_t recovery_next(recovering_xudp_t *channel)
{
    assert(channel->current == NULL);
    if (channel->generation == UINT64_MAX) return SOLARIS_EOVERFLOW;
    channel->generation++; channel->terminal = channel->partial = channel->wire_lost = 0;
    solaris_stream_factory_t factory = {.context = channel, .open = recovery_mux};
    solaris_status_t rc = solaris_datagram_stream_open(channel->scope.owner, &factory,
        &channel->parameters.transport.dialer, &channel->parameters.transport.server,
        &recovery_codec, channel, &recovery_callbacks, channel, &channel->current);
    if (rc == SOLARIS_OK) {
        solaris_scope_retain(&channel->scope);
        if (!channel->reading) (void)solaris_datagram_set_reading(channel->current, 0);
    }
    return rc;
}
static solaris_status_t recovery_send(void *context, const solaris_address_t *destination,
    const solaris_slice_t *data, solaris_io_done_fn done, void *user)
{
    recovering_xudp_t *channel = context;
    if (channel->scope.cancelled) return SOLARIS_ECLOSED;
    if (!channel->opened) return SOLARIS_EBUSY;
    if (channel->parameters.reject_udp443 && destination->port == 443u) return SOLARIS_EACCESS;
    if (data->length > UINT16_MAX || data->length > channel->parameters.transport.dialer.pending_byte_limit)
        return SOLARIS_EMSGSIZE;
    if (!channel->ready || channel->current == NULL) { channel->waiting = 1; return SOLARIS_EAGAIN; }
    solaris_status_t rc = solaris_datagram_send(channel->current, destination, data, done, user);
    if (rc == SOLARIS_ECLOSED && channel->confirmed && !channel->terminal && !channel->partial) {
        channel->waiting = 1; return SOLARIS_EAGAIN;
    }
    return rc;
}
static solaris_status_t recovery_reading(void *context, int enabled)
{
    recovering_xudp_t *channel = context;
    if (channel->scope.cancelled) return SOLARIS_ECLOSED;
    channel->reading = enabled;
    if (channel->current != NULL) return solaris_datagram_set_reading(channel->current, enabled);
    return SOLARIS_OK;
}
static solaris_status_t recovery_close_datagram(void *context)
{ recovery_close(context, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t recovery_snapshot(void *context, solaris_io_snapshot_t *out)
{
    recovering_xudp_t *channel = context; *out = channel->totals;
    if (channel->current != NULL) {
        solaris_io_snapshot_t stats; (void)solaris_datagram_get_snapshot(channel->current, &stats);
        out->bytes_read += stats.bytes_read; out->bytes_written += stats.bytes_written;
        out->packets_read += stats.packets_read; out->packets_written += stats.packets_written;
        out->dropped_packets += stats.dropped_packets;
        out->pending_bytes = stats.pending_bytes; out->pending_requests = stats.pending_requests;
    }
    return SOLARIS_OK;
}
static solaris_status_t recovery_local(void *context, solaris_address_t *out)
{ (void)context; (void)out; return SOLARIS_ENOTSUP; }
static const solaris_datagram_ops_t recovery_ops = {
    recovery_send, recovery_reading, recovery_close_datagram, recovery_snapshot, recovery_local
};
solaris_status_t solaris_vless_datagram_open(solaris_executor_t *owner,
    const solaris_vless_datagram_parameters_t *parameters,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || parameters == NULL || callbacks == NULL || callbacks->on_open == NULL ||
        callbacks->on_packet == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    recovering_xudp_t *channel = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*channel));
    if (channel == NULL) return SOLARIS_ENOMEM;
    memset(channel, 0, sizeof(*channel)); channel->parameters = *parameters;
    if (channel->parameters.transport.tls != NULL) solaris_tls_context_retain(channel->parameters.transport.tls);
    solaris_vless_encryption_client_retain(channel->parameters.encryption);
    solaris_traffic_counter_retain(channel->parameters.transport.dialer.traffic);
    solaris_status_t rc = solaris_dialer_options_normalize(&parameters->transport.dialer, &channel->parameters.transport.dialer);
    if (rc != SOLARIS_OK) { recovery_destroyed(channel); return rc; }
    rc = parameters->crypto.random != NULL ? parameters->crypto.random(parameters->crypto.context, channel->identity.global_id, 8u) :
        RAND_bytes(channel->identity.global_id, 8u) ? SOLARIS_OK : SOLARIS_EIO;
    int nonzero = 0; for (size_t i = 0u; i < 8u; ++i) nonzero |= channel->identity.global_id[i] != 0u;
    if (rc != SOLARIS_OK || !nonzero) { recovery_destroyed(channel); return rc == SOLARIS_OK ? SOLARIS_EIO : rc; }
    channel->physical_factory = channel->parameters.transport.carrier;
    channel->parameters.transport.carrier = (solaris_stream_factory_t){channel, recovery_physical};
    observe_codec(&channel->encryption_codec, &solaris_vless_encryption_codec, NULL);
    observe_codec(&channel->protocol_codec, parameters->vision ? &solaris_vless_vision_codec : &solaris_vless_stream_codec,
        &channel->protocol_raw);
    channel->callbacks = *callbacks; channel->context = context; channel->reading = 1;
    channel->totals.max_message_bytes = UINT16_MAX;
    channel->datagram = (solaris_datagram_t){&recovery_ops, channel, owner};
    channel->reconnect = (solaris_deferred_t){.run = recovery_reconnect, .context = channel};
    rc = solaris_scope_init(&channel->scope, owner, recovery_cancelled, recovery_destroyed, channel);
    if (rc != SOLARIS_OK) { recovery_destroyed(channel); return rc; }
    rc = recovery_next(channel);
    if (rc != SOLARIS_OK) { recovery_close(channel, rc); return rc; }
    channel->accepted = 1; *out = &channel->datagram; return SOLARIS_OK;
}
