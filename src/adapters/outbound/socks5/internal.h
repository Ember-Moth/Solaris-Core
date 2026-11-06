#ifndef SOLARIS_SOCKS5_INTERNAL_H
#define SOLARIS_SOCKS5_INTERNAL_H
#include "adapters/outbound/socks5/codec.h"
#include "contracts/io/carrier.h"

typedef struct solaris_socks5_open_info {
    solaris_address_t bound;
    int carrier_connected;
} solaris_socks5_open_info_t;

/* info is optional and borrowed until on_close. It distinguishes a failed
 * physical candidate from a server/authentication/protocol refusal. */
solaris_status_t solaris_socks5_stream_open(solaris_executor_t *owner,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *server, const solaris_socks5_credentials_t *credentials,
    uint8_t command, const solaris_address_t *target, solaris_socks5_open_info_t *info,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out);
solaris_status_t solaris_socks5_udp_open(solaris_executor_t *owner,
    const solaris_stream_factory_t *carrier, const solaris_dialer_options_t *options,
    const solaris_address_t *server, const solaris_socks5_credentials_t *credentials,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out);
#endif
