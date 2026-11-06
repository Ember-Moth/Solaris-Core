#ifndef SOLARIS_UOT_CODEC_H
#define SOLARIS_UOT_CODEC_H

#include "transport/datagram/stream.h"

#define SOLARIS_UOT_V2_ADDRESS "sp.v2.udp-over-tcp.arpa"
/* Version 2, non-connect mode. The first encoded datagram includes the request
 * with its actual destination; every frame still carries its own peer. */
extern const solaris_datagram_codec_ops_t solaris_uot_v2_codec;

#endif
