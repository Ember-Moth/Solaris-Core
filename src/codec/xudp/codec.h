#ifndef SOLARIS_XUDP_CODEC_H
#define SOLARIS_XUDP_CODEC_H
#include "transport/datagram/stream.h"

/* One session per physical stream. A nonzero global_id attaches the first
 * packet to an existing server-side UDP mapping across physical streams.
 * Identity lifetime and carrier recovery belong to the adapter. NULL keeps
 * Single XUDP wire compatibility for standalone codec consumers. */
typedef struct solaris_xudp_parameters { uint8_t global_id[8]; } solaris_xudp_parameters_t;
extern const solaris_datagram_codec_ops_t solaris_xudp_codec;
#endif
