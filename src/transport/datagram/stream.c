#include "transport/datagram/stream.h"
#include <assert.h>
#include <string.h>

#define DATAGRAM_READ_MAX 65536u
#define DATAGRAM_STEPS 32u

typedef struct packet_request {
    struct packet_request *next;
    solaris_slice_t plain;
    solaris_buffer_t *wire;
    solaris_io_done_fn done;
    void *context;
} packet_request_t;
typedef struct datagram_stream {
    solaris_datagram_t datagram;
    solaris_stream_t *carrier;
    solaris_scope_t scope;
    solaris_deferred_t pump;
    solaris_deadline_t *deadline;
    uint64_t open_deadline_ns;
    solaris_dialer_options_t options;
    solaris_datagram_callbacks_t callbacks;
    void *context, *codec_state;
    const solaris_datagram_codec_ops_t *codec;
    solaris_buffer_t *preface;
    packet_request_t *head, *tail;
    uint8_t *receive;
    size_t begin, end, capacity;
    solaris_io_snapshot_t stats;
    solaris_status_t close_status;
    int accepted, opened, connected, preface_done, writing, reading;
    int close_requested, writable_requested, carrier_eof;
} datagram_stream_t;

static void schedule(datagram_stream_t *channel);
static void close_status(datagram_stream_t *channel, solaris_status_t status);

static void finish_request(datagram_stream_t *channel, solaris_status_t status)
{
    packet_request_t *request = channel->head;
    channel->head = request->next;
    if (channel->head == NULL) channel->tail = NULL;
    channel->stats.pending_requests--; channel->stats.pending_bytes -= request->plain.length;
    if (status == SOLARIS_OK) {
        channel->stats.bytes_written += request->plain.length; channel->stats.packets_written++;
    }
    request->done(request->context, status);
    solaris_buffer_release(request->plain.buffer); solaris_buffer_release(request->wire); solaris_memory_free(request);
    if (channel->writable_requested && !channel->scope.cancelled) {
        channel->writable_requested = 0;
        if (channel->callbacks.on_writable != NULL) channel->callbacks.on_writable(channel->context, &channel->datagram);
    }
}
static void cancelled(void *context)
{
    datagram_stream_t *channel = context;
    if (!channel->close_requested) { channel->close_requested = 1; channel->close_status = SOLARIS_ECANCELLED; }
    if (channel->deadline != NULL) solaris_deadline_cancel(channel->deadline);
    if (channel->carrier != NULL) (void)solaris_stream_close(channel->carrier);
    if (channel->accepted) schedule(channel);
}
static void destroyed(void *context)
{
    datagram_stream_t *channel = context;
    assert(channel->carrier == NULL && channel->head == NULL);
    if (channel->accepted) channel->callbacks.on_close(channel->context, &channel->datagram, channel->close_status);
    if (channel->codec_state != NULL) channel->codec->destroy(channel->codec_state);
    solaris_buffer_release(channel->preface); solaris_memory_free(channel->receive); solaris_memory_free(channel);
}
static void close_status(datagram_stream_t *channel, solaris_status_t status)
{
    if (channel->close_requested) return;
    channel->close_requested = 1; channel->close_status = status; solaris_scope_cancel(&channel->scope);
}
static void timed_out(void *context, solaris_status_t status)
{
    datagram_stream_t *channel = context; channel->deadline = NULL;
    if (status == SOLARIS_OK && !channel->opened) close_status(channel, SOLARIS_ETIMEDOUT);
    solaris_scope_release(&channel->scope);
}
static void carrier_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    (void)stream; datagram_stream_t *channel = context;
    if (channel->scope.cancelled) return;
    if (status == SOLARIS_OK) {
        channel->connected = 1;
        status = channel->codec->start(channel->codec_state, &channel->preface);
        if (status == SOLARIS_OK && channel->preface != NULL &&
            solaris_buffer_length(channel->preface) > channel->codec->frame_limit) status = SOLARIS_EMSGSIZE;
    }
    if (status != SOLARIS_OK) close_status(channel, status);
    else schedule(channel);
}
static void carrier_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    datagram_stream_t *channel = context;
    if (channel->scope.cancelled) return;
    size_t count = solaris_buffer_length(buffer), remaining = channel->end - channel->begin;
    if (count > DATAGRAM_READ_MAX || count > channel->capacity - remaining) {
        close_status(channel, SOLARIS_EMSGSIZE); return;
    }
    if (count > channel->capacity - channel->end) {
        memmove(channel->receive, channel->receive + channel->begin, remaining);
        channel->begin = 0u; channel->end = remaining;
    }
    memcpy(channel->receive + channel->end, solaris_buffer_data(buffer), count); channel->end += count;
    (void)solaris_stream_set_reading(stream, 0); schedule(channel);
}
static void carrier_eof(void *context, solaris_stream_t *stream)
{
    (void)stream; datagram_stream_t *channel = context; channel->carrier_eof = 1;
    if (!channel->scope.cancelled) schedule(channel);
}
static void carrier_writable(void *context, solaris_stream_t *stream)
{ (void)stream; datagram_stream_t *channel = context; if (!channel->scope.cancelled) schedule(channel); }
static void carrier_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    (void)stream; datagram_stream_t *channel = context; channel->carrier = NULL;
    if (!channel->scope.cancelled) {
        if (status == SOLARIS_OK && channel->carrier_eof) schedule(channel);
        else close_status(channel, status == SOLARIS_OK ? SOLARIS_EIO : status);
    }
    solaris_scope_release(&channel->scope);
}
static const solaris_stream_callbacks_t carrier_callbacks = {
    carrier_opened, carrier_data, carrier_eof, carrier_writable, carrier_closed
};
static void wire_written(void *context, solaris_status_t status)
{
    datagram_stream_t *channel = context; channel->writing = 0;
    if (!channel->scope.cancelled) {
        if (status != SOLARIS_OK) close_status(channel, status);
        else {
            if (!channel->preface_done) {
                channel->preface_done = 1; solaris_buffer_release(channel->preface); channel->preface = NULL;
            } else finish_request(channel, SOLARIS_OK);
            schedule(channel);
        }
    }
    solaris_scope_release(&channel->scope);
}
static void write_buffer(datagram_stream_t *channel, solaris_buffer_t *buffer)
{
    solaris_slice_t slice = {buffer, 0u, solaris_buffer_length(buffer)};
    solaris_status_t rc = solaris_stream_write(channel->carrier, &slice, wire_written, channel);
    if (rc == SOLARIS_OK) { channel->writing = 1; solaris_scope_retain(&channel->scope); }
    else if (rc != SOLARIS_EAGAIN) close_status(channel, rc);
}
static void pump(void *context)
{
    datagram_stream_t *channel = context;
    if (!channel->scope.cancelled && !channel->opened &&
        solaris_executor_now_ns(channel->scope.owner) >= channel->open_deadline_ns) close_status(channel, SOLARIS_ETIMEDOUT);
    if (!channel->scope.cancelled && channel->connected && channel->carrier != NULL && !channel->writing) {
        if (!channel->preface_done) {
            if (channel->preface == NULL) channel->preface_done = 1;
            else write_buffer(channel, channel->preface);
        }
        if (channel->preface_done && !channel->opened && !channel->scope.cancelled) {
            channel->opened = 1;
            if (channel->deadline != NULL) solaris_deadline_cancel(channel->deadline);
            channel->callbacks.on_open(channel->context, &channel->datagram, SOLARIS_OK);
        }
        if (channel->opened && !channel->scope.cancelled && channel->head != NULL)
            write_buffer(channel, channel->head->wire);
    }
    int needs_input = channel->begin == channel->end;
    unsigned int steps = 0u;
    while (!channel->scope.cancelled && channel->opened && channel->reading &&
           channel->begin < channel->end && steps++ < DATAGRAM_STEPS) {
        size_t consumed = 0u; solaris_address_t source = {0}; solaris_buffer_t *plain = NULL;
        solaris_status_t rc = channel->codec->decode(channel->codec_state, channel->receive + channel->begin,
            channel->end - channel->begin, &consumed, &source, &plain);
        assert(consumed <= channel->end - channel->begin);
        channel->begin += consumed;
        if (rc == SOLARIS_EAGAIN) {
            assert(plain == NULL && consumed == 0u);
            if (channel->end - channel->begin >= channel->codec->frame_limit) close_status(channel, SOLARIS_EMSGSIZE);
            needs_input = 1; break;
        }
        if (rc != SOLARIS_OK && rc != SOLARIS_ECLOSED) { solaris_buffer_release(plain); close_status(channel, rc); break; }
        if (plain != NULL) {
            solaris_buffer_publish(plain);
            channel->stats.bytes_read += solaris_buffer_length(plain); channel->stats.packets_read++;
            channel->callbacks.on_packet(channel->context, &channel->datagram, &source, plain);
            solaris_buffer_release(plain);
        }
        if (rc == SOLARIS_ECLOSED) { close_status(channel, rc); break; }
        if (consumed == 0u && plain == NULL) { close_status(channel, SOLARIS_EIO); break; }
        needs_input = channel->begin == channel->end;
    }
    if (!channel->scope.cancelled && channel->opened && channel->reading && channel->carrier_eof && needs_input) {
        solaris_status_t rc = channel->begin != channel->end ? SOLARIS_EIO : channel->codec->finish(channel->codec_state);
        close_status(channel, rc);
    }
    if (channel->scope.cancelled) {
        solaris_status_t rc = channel->close_status == SOLARIS_OK ? SOLARIS_ECANCELLED : channel->close_status;
        if (!channel->opened) { channel->opened = 1; channel->callbacks.on_open(channel->context, &channel->datagram, rc); }
        while (channel->head != NULL) finish_request(channel, rc);
    } else {
        if (channel->begin == channel->end) channel->begin = channel->end = 0u;
        if (channel->carrier != NULL && !channel->carrier_eof) {
            solaris_status_t rc = solaris_stream_set_reading(channel->carrier, channel->reading && needs_input);
            if (rc != SOLARIS_OK) close_status(channel, rc);
        }
        if (steps > DATAGRAM_STEPS && !channel->scope.cancelled) schedule(channel);
    }
    solaris_scope_release(&channel->scope);
}
static void schedule(datagram_stream_t *channel)
{
    if (channel->pump.queued) return;
    solaris_scope_retain(&channel->scope);
    solaris_status_t rc = solaris_executor_defer(channel->scope.owner, &channel->pump); assert(rc == SOLARIS_OK); (void)rc;
}
static solaris_status_t send_packet(void *state, const solaris_address_t *destination,
    const solaris_slice_t *plain, solaris_io_done_fn done, void *context)
{
    datagram_stream_t *channel = state;
    if (channel->scope.cancelled || !solaris_executor_accepting(channel->scope.owner)) return SOLARIS_ECLOSED;
    if (!channel->opened) return SOLARIS_EBUSY;
    if (plain->length > channel->stats.max_message_bytes || plain->length > channel->options.pending_byte_limit) return SOLARIS_EMSGSIZE;
    if (channel->stats.pending_requests >= channel->options.pending_request_limit ||
        channel->stats.pending_bytes > channel->options.pending_byte_limit - plain->length) {
        channel->writable_requested = 1; return SOLARIS_EAGAIN;
    }
    packet_request_t *request = solaris_memory_allocate(solaris_executor_budget(channel->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request));
    solaris_status_t rc = channel->codec->encode(channel->codec_state, destination, plain, &request->wire);
    if (rc == SOLARIS_OK && (request->wire == NULL || solaris_buffer_length(request->wire) > channel->codec->frame_limit)) rc = SOLARIS_EIO;
    if (rc != SOLARIS_OK) { solaris_buffer_release(request->wire); solaris_memory_free(request); return rc; }
    request->plain = *plain; solaris_buffer_retain(plain->buffer); request->done = done; request->context = context;
    channel->stats.pending_requests++; channel->stats.pending_bytes += plain->length;
    if (channel->tail != NULL) channel->tail->next = request;
    else channel->head = request;
    channel->tail = request; schedule(channel); return SOLARIS_OK;
}
static solaris_status_t set_reading(void *state, int enabled)
{
    datagram_stream_t *channel = state;
    if (channel->scope.cancelled) return SOLARIS_ECLOSED;
    channel->reading = enabled;
    if (!enabled && channel->carrier != NULL) (void)solaris_stream_set_reading(channel->carrier, 0);
    schedule(channel); return SOLARIS_OK;
}
static solaris_status_t close_datagram(void *state) { close_status(state, SOLARIS_OK); return SOLARIS_OK; }
static solaris_status_t snapshot(void *state, solaris_io_snapshot_t *out)
{ *out = ((datagram_stream_t *)state)->stats; return SOLARIS_OK; }
static solaris_status_t local_address(void *state, solaris_address_t *out)
{ (void)state; (void)out; return SOLARIS_ENOTSUP; }
static const solaris_datagram_ops_t operations = {send_packet, set_reading, close_datagram, snapshot, local_address};

solaris_status_t solaris_datagram_stream_open(solaris_executor_t *owner,
    const solaris_stream_factory_t *factory, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_datagram_codec_ops_t *codec, const void *parameters,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || peer == NULL || codec == NULL || codec->frame_limit == 0u || codec->frame_limit > 1024u * 1024u ||
        codec->message_limit > codec->frame_limit || codec->create == NULL || codec->start == NULL || codec->encode == NULL ||
        codec->decode == NULL || codec->finish == NULL || codec->destroy == NULL || callbacks == NULL ||
        callbacks->on_open == NULL || callbacks->on_packet == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    datagram_stream_t *channel = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*channel));
    if (channel == NULL) return SOLARIS_ENOMEM;
    memset(channel, 0, sizeof(*channel)); channel->codec = codec; channel->reading = 1;
    channel->callbacks = *callbacks; channel->context = context;
    channel->datagram = (solaris_datagram_t){&operations, channel, owner}; channel->pump.run = pump; channel->pump.context = channel;
    solaris_status_t rc = solaris_dialer_options_normalize(options, &channel->options);
    if (rc != SOLARIS_OK) { destroyed(channel); return rc; }
    channel->stats.max_message_bytes = codec->message_limit;
    channel->capacity = codec->frame_limit + DATAGRAM_READ_MAX;
    channel->receive = solaris_memory_allocate(solaris_executor_budget(owner), channel->capacity);
    if (channel->receive == NULL) { destroyed(channel); return SOLARIS_ENOMEM; }
    rc = codec->create(parameters, solaris_executor_budget(owner), &channel->codec_state);
    if (rc != SOLARIS_OK) { destroyed(channel); return rc; }
    rc = solaris_scope_init(&channel->scope, owner, cancelled, destroyed, channel);
    if (rc != SOLARIS_OK) { destroyed(channel); return rc; }
    uint64_t now = solaris_executor_now_ns(owner), duration = channel->options.open_timeout_ms * UINT64_C(1000000);
    if (duration > UINT64_MAX - now) { close_status(channel, SOLARIS_EOVERFLOW); return SOLARIS_EOVERFLOW; }
    channel->open_deadline_ns = now + duration;
    solaris_scope_retain(&channel->scope);
    rc = solaris_deadline_start(owner, channel->options.open_timeout_ms, timed_out, channel, &channel->deadline);
    if (rc != SOLARIS_OK) { solaris_scope_release(&channel->scope); close_status(channel, rc); return rc; }
    solaris_dialer_options_t wire_options = channel->options;
    if (wire_options.pending_byte_limit < codec->frame_limit) wire_options.pending_byte_limit = codec->frame_limit;
    wire_options.pending_request_limit = 1u; wire_options.read_chunk_size = 16384u;
    rc = solaris_carrier_open(factory, owner, &wire_options, peer, &carrier_callbacks, channel, &channel->carrier);
    if (rc != SOLARIS_OK) { close_status(channel, rc); return rc; }
    solaris_scope_retain(&channel->scope); channel->accepted = 1; *out = &channel->datagram; return SOLARIS_OK;
}
