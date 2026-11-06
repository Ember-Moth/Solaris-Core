#ifndef SOLARIS_STREAM_FILTER_H
#define SOLARIS_STREAM_FILTER_H

#include "contracts/io/carrier.h"

/* A record codec transforms bytes without owning sockets, workers, or queues.
 * create copies its borrowed parameters. Each returned output buffer transfers
 * one reference to the filter. decode may consume framing without emitting;
 * EAGAIN means more bytes are needed and must not return an output. A successful
 * decode must consume bytes or produce output. finish verifies terminal parser
 * state, including authentication/partial-record requirements. */
typedef struct solaris_stream_codec_raw_ops {
    solaris_status_t (*read)(void *state);
    solaris_status_t (*write)(void *state);
} solaris_stream_codec_raw_ops_t;
typedef struct solaris_stream_codec_carrier_raw {
    uint32_t required;
    uint32_t (*requested)(void *state);
    void (*applied)(void *state, uint32_t directions);
} solaris_stream_codec_carrier_raw_t;
typedef struct solaris_stream_codec_ops {
    size_t receive_limit;
    solaris_status_t (*create)(const void *parameters, solaris_budget_t *budget, void **state);
    solaris_status_t (*start)(void *state, solaris_buffer_t **preface);
    solaris_status_t (*encode)(void *state, const solaris_slice_t *plain, solaris_buffer_t **wire);
    solaris_status_t (*decode)(void *state, const uint8_t *wire, size_t size,
                              size_t *consumed, solaris_buffer_t **plain);
    solaris_status_t (*finish)(void *state);
    void (*destroy)(void *state);
    /* Optional authenticated-handshake gate. Until ready returns true, decode
     * runs independently of application read pause and must emit no plaintext.
     * A transition to ready ends a decode step, before application records. */
    int (*ready)(void *state);
    /* Optional continuation after start/each preface write. delay_ms precedes
     * this buffer; NULL means the preface ends after that delay. The filter
     * owns the timer, deadline, output buffer and cancellation barrier. */
    solaris_status_t (*next_preface)(void *state, solaris_buffer_t **preface,
                                   uint64_t *delay_ms);
    /* Optional bypass of this codec. The filter orders writes at a barrier. */
    const solaris_stream_codec_raw_ops_t *raw;
    /* A codec may request its carrier's transition after a decoded boundary or
     * after the current encoded frame's write completion. Each request remains
     * set until applied; no next encode occurs before the write barrier ends. */
    const solaris_stream_codec_carrier_raw_t *carrier_raw;
} solaris_stream_codec_ops_t;

/* Open succeeds after the carrier and encoded preface are written and the
 * optional ready gate passes. Without a ready gate it does
 * not imply that a protocol without an acknowledgement authenticated the peer.
 * Caller callbacks obey the ordinary stream lifetime and owner contracts. */
solaris_status_t solaris_filter_open(solaris_executor_t *owner,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *peer, const solaris_stream_codec_ops_t *codec,
    const void *parameters, const solaris_stream_callbacks_t *callbacks,
    void *context, solaris_stream_t **out);

#endif
