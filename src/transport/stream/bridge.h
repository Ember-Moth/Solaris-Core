#ifndef SOLARIS_STREAM_BRIDGE_H
#define SOLARIS_STREAM_BRIDGE_H

#include "contracts/io/channel.h"
#include "runtime/executor/executor.h"

typedef struct solaris_stream_bridge solaris_stream_bridge_t;
typedef struct solaris_stream_bridge_options {
    solaris_budget_t *budget;
    /* Each direction separately reserves these bounds. A write is one chunk;
     * larger slices return EMSGSIZE, without partial acceptance. */
    size_t byte_limit, request_limit, max_chunk_size;
} solaris_stream_bridge_options_t;

/* Inert, thread-safe allocation, with one external reference and no callbacks.
 * Each attach must run on its selected owner. The caller keeps a reference
 * while dispatching attach tasks; the executors must outlive those tasks. */
solaris_status_t solaris_stream_bridge_create(const solaris_stream_bridge_options_t *options,
                                             solaris_stream_bridge_t **out);
void solaris_stream_bridge_retain(solaris_stream_bridge_t *bridge);
/* The last external release abandons an incomplete pair. A complete pair owns
 * itself until both close callbacks return. An external ref never pins I/O. */
void solaris_stream_bridge_release(solaris_stream_bridge_t *bridge);
/* Attach side 0 or 1 exactly once. Rejected attachment has no callbacks. A
 * runtime admission failure also cancels an already attached peer. Accepted
 * attachment promises deferred open and final close on this owner, including
 * peer-attach failure or stop. Both scopes exist before either successful open.
 * A closed pair is never reusable, including across executor generations. */
solaris_status_t solaris_stream_bridge_attach(solaris_stream_bridge_t *bridge, unsigned int side,
    solaris_executor_t *owner, const solaris_stream_callbacks_t *callbacks,
    void *context, solaris_stream_t **out);

/* The pair carries bytes only; it never operates a real stream on another
 * owner. Reading starts disabled. Writes require peer read credit and retain
 * their slice until completion. EAGAIN accepts nothing. Peer pause stops new
 * credit grants, but never revokes already reserved credit; accepted chunks
 * wait for resume within the byte/request bounds.
 * Writable is rearmed by EAGAIN and announces already reserved credit for one
 * max-sized chunk. The sender owner must serialize its producers: a real
 * source may enable non-rejectable data callbacks using this credit, and must
 * pause that source when its credit is consumed.
 *
 * Write completion means the peer's data callback returned, not downstream
 * network delivery. Completions return to the sender in write order. Shutdown
 * follows preceding DATA and delivers peer EOF before completing. Closing
 * either endpoint cancels the pair and drains accepted open/write/shutdown,
 * both owners' acknowledgements and callbacks before final close. No callback
 * is made under the bridge lock. Raw transitions return ENOTSUP. */
#endif
