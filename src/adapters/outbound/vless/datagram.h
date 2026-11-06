#ifndef SOLARIS_VLESS_DATAGRAM_H
#define SOLARIS_VLESS_DATAGRAM_H
#include "transport/datagram/stream.h"
/* Parameters points to an int: reject UDP/443 for the base Vision flow. */
extern const solaris_datagram_codec_ops_t solaris_vless_xudp_codec;
#endif
