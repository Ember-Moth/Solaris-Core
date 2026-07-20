#ifndef APROXY_LIMITS_H
#define APROXY_LIMITS_H

#include <stddef.h>

#define APROXY_DEFAULT_STREAM_PENDING_BYTES (4u * 1024u * 1024u)

static inline size_t aproxy_stream_pending_limit(size_t configured)
{
    return configured == 0u ? APROXY_DEFAULT_STREAM_PENDING_BYTES
                            : configured;
}

static inline int aproxy_size_add_exceeds(size_t current,
                                          size_t added,
                                          size_t limit)
{
    return current > limit || added > limit - current;
}

#endif
