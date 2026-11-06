#ifndef SOLARIS_VLESS_DATAGRAM_H
#define SOLARIS_VLESS_DATAGRAM_H
#include "transport/datagram/stream.h"
#include "config/outbound/proxy.h"
#include "adapters/outbound/vless/encryption/client.h"
/* Parameters points to an int: reject UDP/443 for the base Vision flow. */
extern const solaris_datagram_codec_ops_t solaris_vless_xudp_codec;

typedef struct solaris_vless_datagram_parameters {
    solaris_proxy_transport_t transport;
    solaris_vless_encryption_client_t *encryption;
    solaris_crypto_source_t crypto;
    uint8_t uuid[16];
    int vision, reject_udp443;
} solaris_vless_datagram_parameters_t;

/* Owns copies/references of all protocol settings. Host carrier and socket
 * policy contexts retain the normal lifetime through final on_close. An
 * authenticated channel recovers a lost carrier using a stable GlobalID;
 * accepted sends complete once and are never replayed. */
solaris_status_t solaris_vless_datagram_open(solaris_executor_t *owner,
    const solaris_vless_datagram_parameters_t *parameters,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out);
#endif
