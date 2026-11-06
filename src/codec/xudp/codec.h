#ifndef SOLARIS_XUDP_CODEC_H
#define SOLARIS_XUDP_CODEC_H
#include "transport/datagram/stream.h"

/* Single XUDP, session ID zero, one physical stream per datagram channel.
 * Each packet includes its destination; no reconnect or global-ID reuse. */
extern const solaris_datagram_codec_ops_t solaris_xudp_codec;
#endif
