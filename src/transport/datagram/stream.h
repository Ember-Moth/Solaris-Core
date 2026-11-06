#ifndef SOLARIS_DATAGRAM_STREAM_H
#define SOLARIS_DATAGRAM_STREAM_H

#include "contracts/io/carrier.h"

/* Framing only: no network, executor or queue ownership. start transfers a
 * preface reference; encode transfers one complete frame and only commits
 * codec state on success. decode may consume control framing without emitting
 * a packet. EAGAIN consumes nothing; finish validates terminal parser state.
 * ECLOSED is a terminal frame and may emit one final packet before closure.
 * Other errors emit no packet. Every returned buffer is released by backend. */
typedef struct solaris_datagram_codec_ops {
    size_t frame_limit, message_limit;
    solaris_status_t (*create)(const void *, solaris_budget_t *, void **);
    solaris_status_t (*start)(void *, solaris_buffer_t **);
    solaris_status_t (*encode)(void *, const solaris_address_t *, const solaris_slice_t *, solaris_buffer_t **);
    solaris_status_t (*decode)(void *, const uint8_t *, size_t, size_t *, solaris_address_t *, solaris_buffer_t **);
    solaris_status_t (*finish)(void *);
    void (*destroy)(void *);
} solaris_datagram_codec_ops_t;

/* The factory is borrowed until this call returns and must copy/retain its
 * configuration. The resulting datagram owns the stream through on_close.
 * Open means carrier plus any eager preface written, not remote UDP
 * reachability. Codecs may prefix the first frame with a lazy request.
 * Stream deliveries are bounded to 64 KiB; codec frames may span deliveries. */
solaris_status_t solaris_datagram_stream_open(solaris_executor_t *owner,
    const solaris_stream_factory_t *factory, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_datagram_codec_ops_t *codec, const void *parameters,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out);

#endif
