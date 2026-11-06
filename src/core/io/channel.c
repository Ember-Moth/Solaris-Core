#include "contracts/io/channel.h"
#include "runtime/executor/executor.h"

#define REQUIRE_OWNER(object) do { \
    if ((object) == NULL) return SOLARIS_EINVAL; \
    if (!solaris_executor_is_owner((object)->owner)) return SOLARIS_ETHREAD; \
} while (0)

solaris_status_t solaris_stream_write(solaris_stream_t *stream, const solaris_slice_t *data,
                                      solaris_io_done_fn done, void *context)
{
    REQUIRE_OWNER(stream);
    if (!solaris_slice_valid(data) || done == NULL) return SOLARIS_EINVAL;
    return stream->ops->write(stream->state, data, done, context);
}
solaris_status_t solaris_stream_shutdown_write(solaris_stream_t *stream, solaris_io_done_fn done, void *context)
{
    REQUIRE_OWNER(stream);
    if (done == NULL) return SOLARIS_EINVAL;
    return stream->ops->shutdown_write(stream->state, done, context);
}
solaris_status_t solaris_stream_set_reading(solaris_stream_t *stream, int enabled)
{ REQUIRE_OWNER(stream); return stream->ops->set_reading(stream->state, enabled != 0); }
solaris_status_t solaris_stream_close(solaris_stream_t *stream)
{ REQUIRE_OWNER(stream); return stream->ops->close(stream->state); }
solaris_status_t solaris_stream_get_snapshot(solaris_stream_t *stream, solaris_io_snapshot_t *out)
{ REQUIRE_OWNER(stream); if (out == NULL) return SOLARIS_EINVAL; return stream->ops->snapshot(stream->state, out); }
solaris_status_t solaris_stream_raw_capabilities(solaris_stream_t *stream, uint32_t *out)
{
    REQUIRE_OWNER(stream); if (out == NULL) return SOLARIS_EINVAL;
    *out = stream->ops->raw == NULL ? 0u : stream->ops->raw->capabilities(stream->state); return SOLARIS_OK;
}
solaris_status_t solaris_stream_read_raw(solaris_stream_t *stream)
{
    REQUIRE_OWNER(stream);
    if (stream->ops->raw == NULL || stream->ops->raw->read == NULL) return SOLARIS_ENOTSUP;
    return stream->ops->raw->read(stream->state);
}
solaris_status_t solaris_stream_write_raw(solaris_stream_t *stream, solaris_io_done_fn done, void *context)
{
    REQUIRE_OWNER(stream); if (done == NULL) return SOLARIS_EINVAL;
    if (stream->ops->raw == NULL || stream->ops->raw->write == NULL) return SOLARIS_ENOTSUP;
    return stream->ops->raw->write(stream->state, done, context);
}

solaris_status_t solaris_datagram_send(solaris_datagram_t *datagram, const solaris_address_t *destination,
                                       const solaris_slice_t *data, solaris_io_done_fn done, void *context)
{
    REQUIRE_OWNER(datagram);
    if (destination == NULL || !solaris_slice_valid(data) || done == NULL) return SOLARIS_EINVAL;
    return datagram->ops->send(datagram->state, destination, data, done, context);
}
solaris_status_t solaris_datagram_set_reading(solaris_datagram_t *datagram, int enabled)
{ REQUIRE_OWNER(datagram); return datagram->ops->set_reading(datagram->state, enabled != 0); }
solaris_status_t solaris_datagram_close(solaris_datagram_t *datagram)
{ REQUIRE_OWNER(datagram); return datagram->ops->close(datagram->state); }
solaris_status_t solaris_datagram_get_snapshot(solaris_datagram_t *datagram, solaris_io_snapshot_t *out)
{ REQUIRE_OWNER(datagram); if (out == NULL) return SOLARIS_EINVAL; return datagram->ops->snapshot(datagram->state, out); }
solaris_status_t solaris_datagram_local_address(solaris_datagram_t *datagram, solaris_address_t *out)
{ REQUIRE_OWNER(datagram); if (out == NULL) return SOLARIS_EINVAL; return datagram->ops->local_address(datagram->state, out); }

solaris_status_t solaris_datagram_send_batch(solaris_datagram_t *datagram,
                                             const solaris_datagram_message_t *messages,
                                             size_t count, size_t *accepted)
{
    if (accepted == NULL) return SOLARIS_EINVAL;
    *accepted = 0u;
    REQUIRE_OWNER(datagram);
    if (messages == NULL && count != 0u) return SOLARIS_EINVAL;
    for (size_t i = 0; i < count; i++) {
        solaris_status_t rc = solaris_datagram_send(datagram, &messages[i].destination,
                                                   &messages[i].data, messages[i].done, messages[i].context);
        if (rc != SOLARIS_OK) return rc;
        (*accepted)++;
    }
    return SOLARIS_OK;
}
