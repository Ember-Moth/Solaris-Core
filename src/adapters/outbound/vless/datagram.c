#include "adapters/outbound/vless/datagram.h"
#include "codec/xudp/codec.h"

typedef struct vless_datagram { void *codec; int reject_udp443; } vless_datagram_t;
static solaris_status_t create(const void *parameters, solaris_budget_t *budget, void **out)
{
    vless_datagram_t *state = solaris_memory_allocate(budget, sizeof(*state));
    if (state == NULL) return SOLARIS_ENOMEM;
    state->codec = NULL; state->reject_udp443 = parameters != NULL && *(const int *)parameters;
    solaris_status_t rc = solaris_xudp_codec.create(NULL, budget, &state->codec);
    if (rc != SOLARIS_OK) { solaris_memory_free(state); return rc; }
    *out = state; return SOLARIS_OK;
}
static solaris_status_t start(void *state, solaris_buffer_t **out)
{ return solaris_xudp_codec.start(((vless_datagram_t *)state)->codec, out); }
static solaris_status_t encode(void *context, const solaris_address_t *destination, const solaris_slice_t *plain, solaris_buffer_t **out)
{
    vless_datagram_t *state = context; *out = NULL;
    if (state->reject_udp443 && destination->port == 443u) return SOLARIS_EACCESS;
    return solaris_xudp_codec.encode(state->codec, destination, plain, out);
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size, size_t *consumed,
    solaris_address_t *source, solaris_buffer_t **out)
{ return solaris_xudp_codec.decode(((vless_datagram_t *)state)->codec, wire, size, consumed, source, out); }
static solaris_status_t finish(void *state) { return solaris_xudp_codec.finish(((vless_datagram_t *)state)->codec); }
static void destroy(void *context)
{ vless_datagram_t *state = context; solaris_xudp_codec.destroy(state->codec); solaris_memory_free(state); }
const solaris_datagram_codec_ops_t solaris_vless_xudp_codec = {
    2u + 265u + 2u + UINT16_MAX, UINT16_MAX, create, start, encode, decode, finish, destroy
};
