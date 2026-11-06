#ifndef SOLARIS_IO_H
#define SOLARIS_IO_H

#include "contracts/io/address.h"
#include "contracts/io/buffer.h"

typedef struct solaris_executor solaris_executor_t;
typedef struct solaris_stream solaris_stream_t;
typedef struct solaris_datagram solaris_datagram_t;
typedef void (*solaris_io_done_fn)(void *context, solaris_status_t status);

typedef struct solaris_io_snapshot {
    uint64_t bytes_read, bytes_written;
    uint64_t packets_read, packets_written, dropped_packets;
    /* Queued writes/sends; shutdown/DNS are separately tracked by the scope. */
    size_t pending_bytes, pending_requests, max_message_bytes;
    int32_t last_system_error;
    uint32_t read_eof, write_shutdown;
    uint32_t raw_read, raw_write;
} solaris_io_snapshot_t;

/* All methods run on the object's owner. Successful async operations retain
 * their slices and complete later exactly once. Rejection owns nothing and
 * produces no completion. Handles are engine-owned until on_close returns;
 * data and handles in callbacks are borrowed. Retain a buffer to keep it. */
typedef struct solaris_stream_callbacks {
    void (*on_open)(void *context, solaris_stream_t *stream, solaris_status_t status);
    void (*on_data)(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer);
    void (*on_eof)(void *context, solaris_stream_t *stream);
    void (*on_writable)(void *context, solaris_stream_t *stream);
    void (*on_close)(void *context, solaris_stream_t *stream, solaris_status_t status);
} solaris_stream_callbacks_t;

typedef struct solaris_datagram_callbacks {
    void (*on_open)(void *context, solaris_datagram_t *datagram, solaris_status_t status);
    void (*on_packet)(void *context, solaris_datagram_t *datagram,
                      const solaris_address_t *source, const solaris_buffer_t *buffer);
    void (*on_writable)(void *context, solaris_datagram_t *datagram);
    void (*on_close)(void *context, solaris_datagram_t *datagram, solaris_status_t status);
} solaris_datagram_callbacks_t;

enum { SOLARIS_STREAM_RAW_READ = 1u, SOLARIS_STREAM_RAW_WRITE = 2u };
typedef struct solaris_stream_raw_ops {
    uint32_t (*capabilities)(void *state);
    solaris_status_t (*read)(void *state);
    solaris_status_t (*write)(void *state, solaris_io_done_fn done, void *context);
} solaris_stream_raw_ops_t;

typedef struct solaris_stream_ops {
    solaris_status_t (*write)(void *state, const solaris_slice_t *data, solaris_io_done_fn done, void *context);
    solaris_status_t (*shutdown_write)(void *state, solaris_io_done_fn done, void *context);
    solaris_status_t (*set_reading)(void *state, int enabled);
    solaris_status_t (*close)(void *state);
    solaris_status_t (*snapshot)(void *state, solaris_io_snapshot_t *out);
    const solaris_stream_raw_ops_t *raw;
} solaris_stream_ops_t;

typedef struct solaris_datagram_ops {
    solaris_status_t (*send)(void *state, const solaris_address_t *destination,
                            const solaris_slice_t *data, solaris_io_done_fn done, void *context);
    solaris_status_t (*set_reading)(void *state, int enabled);
    solaris_status_t (*close)(void *state);
    solaris_status_t (*snapshot)(void *state, solaris_io_snapshot_t *out);
    solaris_status_t (*local_address)(void *state, solaris_address_t *out);
} solaris_datagram_ops_t;

struct solaris_stream { const solaris_stream_ops_t *ops; void *state; solaris_executor_t *owner; };
struct solaris_datagram { const solaris_datagram_ops_t *ops; void *state; solaris_executor_t *owner; };

solaris_status_t solaris_stream_write(solaris_stream_t *stream, const solaris_slice_t *data,
                                      solaris_io_done_fn done, void *context);
solaris_status_t solaris_stream_shutdown_write(solaris_stream_t *stream, solaris_io_done_fn done, void *context);
solaris_status_t solaris_stream_set_reading(solaris_stream_t *stream, int enabled);
solaris_status_t solaris_stream_close(solaris_stream_t *stream);
solaris_status_t solaris_stream_get_snapshot(solaris_stream_t *stream, solaris_io_snapshot_t *out);
/* Raw transitions bypass exactly one transform layer. The protocol must
 * establish the boundary. Read is synchronous and preserves already-decoded
 * bytes before unread carrier bytes; it never invokes data callbacks inline.
 * Write is an ordered async barrier after all previously accepted writes and
 * before later writes. Rejected transitions own nothing and never call done.
 * Neither operation exposes a backend object or transfers channel ownership. */
solaris_status_t solaris_stream_raw_capabilities(solaris_stream_t *stream, uint32_t *out);
solaris_status_t solaris_stream_read_raw(solaris_stream_t *stream);
solaris_status_t solaris_stream_write_raw(solaris_stream_t *stream, solaris_io_done_fn done, void *context);
solaris_status_t solaris_datagram_send(solaris_datagram_t *datagram, const solaris_address_t *destination,
                                       const solaris_slice_t *data, solaris_io_done_fn done, void *context);
solaris_status_t solaris_datagram_set_reading(solaris_datagram_t *datagram, int enabled);
solaris_status_t solaris_datagram_close(solaris_datagram_t *datagram);
solaris_status_t solaris_datagram_get_snapshot(solaris_datagram_t *datagram, solaris_io_snapshot_t *out);
solaris_status_t solaris_datagram_local_address(solaris_datagram_t *datagram, solaris_address_t *out);

typedef struct solaris_datagram_message {
    solaris_address_t destination;
    solaris_slice_t data;
    solaris_io_done_fn done;
    void *context;
} solaris_datagram_message_t;

/* Portable ordered-prefix submission, not a claim of a native batch syscall. */
solaris_status_t solaris_datagram_send_batch(solaris_datagram_t *datagram,
                                             const solaris_datagram_message_t *messages,
                                             size_t count, size_t *accepted);

#endif
