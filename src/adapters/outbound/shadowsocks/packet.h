#ifndef SOLARIS_SS_PACKET_H
#define SOLARIS_SS_PACKET_H
#include "adapters/outbound/shadowsocks/internal.h"
/* One owner serializes a packet session. This codec owns no socket or timer.
 * Modern server-session retention uses the injected monotonic clock; header
 * timestamps use the independent Unix clock in parameters.source. */
typedef struct solaris_ss_packet solaris_ss_packet_t;
solaris_status_t solaris_ss_packet_create(solaris_budget_t *budget, const solaris_ss_parameters_t *parameters,
    uint64_t (*now_ns)(void *), void *context, solaris_ss_packet_t **out);
void solaris_ss_packet_destroy(solaris_ss_packet_t *codec);
/* Caller releases a non-null output even on failure. Decode mutates replay
 * state only after authentication and all semantic/address validation. */
solaris_status_t solaris_ss_packet_decode(solaris_ss_packet_t *codec, const uint8_t *wire, size_t size,
    solaris_address_t *source, solaris_buffer_t **out);
solaris_status_t solaris_ss_packet_encode(solaris_ss_packet_t *codec, const solaris_address_t *destination,
    const solaris_slice_t *data, solaris_buffer_t **out);
#endif
