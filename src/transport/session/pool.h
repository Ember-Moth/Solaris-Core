#ifndef SOLARIS_SESSION_POOL_H
#define SOLARIS_SESSION_POOL_H
#include "contracts/io/carrier.h"

/* Codecs own framing only. A batch preserves carrier-write boundaries (e.g.
 * padding records). Every buffer reference transfers to the caller, including
 * partial output on error. All operations and policy state are owner-only. */
#define SOLARIS_SESSION_BATCH_MAX 18u
typedef struct solaris_session_batch {
    solaris_buffer_t *buffers[SOLARIS_SESSION_BATCH_MAX];
    size_t count;
} solaris_session_batch_t;
void solaris_session_batch_clear(solaris_session_batch_t *batch);
enum { SOLARIS_SESSION_NONE, SOLARIS_SESSION_DATA, SOLARIS_SESSION_READY, SOLARIS_SESSION_END };
typedef struct solaris_session_event {
    uint32_t kind, id;
    solaris_status_t status;
    solaris_buffer_t *data;
    solaris_session_batch_t reply;
} solaris_session_event_t;
typedef struct solaris_session_codec {
    size_t frame_limit;
    solaris_status_t (*create)(void *parameters, solaris_budget_t *budget, void **state);
    solaris_status_t (*start)(void *state, solaris_session_batch_t *out);
    /* wait_ack is set per child. False publishes open after its prefix is
     * written; true requires a READY event as well. */
    solaris_status_t (*open)(void *state, uint32_t id, const solaris_address_t *peer, int *wait_ack, solaris_session_batch_t *out);
    solaris_status_t (*write)(void *state, uint32_t id, const solaris_slice_t *data, solaris_session_batch_t *out);
    solaris_status_t (*end)(void *state, uint32_t id, solaris_session_batch_t *out);
    solaris_status_t (*decode)(void *state, const uint8_t *data, size_t size, size_t *used, solaris_session_event_t *event);
    void (*destroy)(void *state);
} solaris_session_codec_t;
typedef struct solaris_session_pool solaris_session_pool_t;
typedef struct solaris_session_pool_options {
    solaris_stream_factory_t carrier;
    solaris_address_t peer;
    solaris_dialer_options_t dialer;
    const solaris_session_codec_t *codec;
    /* Borrowed until on_close. Codec create copies/retains each session state. */
    void *parameters;
    size_t session_limit, streams_per_session;
    /* Zero selects at least 1 MiB / 64 requests, raised to the child
     * defaults when larger. Child limits still apply independently. */
    size_t session_pending_bytes, session_pending_requests;
    uint64_t idle_timeout_ms;
    /* Zero checks each idle session at its exact timeout. Otherwise sweep at
     * this interval, retaining the newest min_idle_sessions without dialing
     * replacements. Retire and executor stop always close retained sessions. */
    uint64_t idle_check_interval_ms;
    size_t min_idle_sessions;
    /* A missing READY on an acknowledged open proves this carrier unhealthy.
     * Fail it and its children; never replay application writes. */
    int ack_timeout_fails_session;
    void (*on_close)(void *context);
    void *context;
} solaris_session_pool_options_t;
/* Latest eligible session first. A streams_per_session of one implements idle
 * reuse; larger values multiplex. One paused child can block session receive
 * at its next DATA frame; no unbounded per-child receive queues are created.
 * Closing a child cancels its queued writes and sends a full-close marker.
 * A carrier error fails every child, without automatic replay/reconnection. */
solaris_status_t solaris_session_pool_create(solaris_executor_t *owner,
    const solaris_session_pool_options_t *options, solaris_session_pool_t **out);
solaris_status_t solaris_session_pool_open(solaris_session_pool_t *pool,
    const solaris_dialer_options_t *options, const solaris_address_t *peer, const solaris_stream_callbacks_t *callbacks,
    void *context, solaris_stream_t **out);
/* Retire rejects new children, closes idle sessions, and drains active ones. */
void solaris_session_pool_retire(solaris_session_pool_t *pool);
#endif
