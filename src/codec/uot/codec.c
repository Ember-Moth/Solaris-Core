#include "codec/uot/codec.h"
#include "codec/address/socks.h"
#include <string.h>

typedef struct uot_codec { solaris_budget_t *budget; int requested; } uot_codec_t;
static solaris_status_t create(const void *parameters, solaris_budget_t *budget, void **out)
{
    (void)parameters; uot_codec_t *codec = solaris_memory_allocate(budget, sizeof(*codec));
    if (codec == NULL) return SOLARIS_ENOMEM;
    codec->budget = budget; codec->requested = 0; *out = codec; return SOLARIS_OK;
}
static solaris_status_t start(void *state, solaris_buffer_t **out)
{
    (void)state; *out = NULL; return SOLARIS_OK;
}
static solaris_status_t encode(void *state, const solaris_address_t *destination,
    const solaris_slice_t *plain, solaris_buffer_t **out)
{
    *out = NULL;
    if (plain->length > UINT16_MAX) return SOLARIS_EMSGSIZE;
    uint8_t address[260]; size_t n;
    solaris_status_t rc = solaris_socks_address_write(destination, address, sizeof(address), &n);
    if (rc != SOLARIS_OK) return rc;
    uot_codec_t *codec = state;
    size_t prefix = codec->requested ? 0u : 1u + n;
    rc = solaris_buffer_allocate(codec->budget, prefix + n + 2u + plain->length, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out);
    if (prefix != 0u) { wire[0] = 0u; memcpy(wire + 1u, address, n); }
    address[0] = address[0] == 1u ? 0u : address[0] == 4u ? 1u : 2u;
    memcpy(wire + prefix, address, n); n += prefix;
    wire[n++] = (uint8_t)(plain->length >> 8); wire[n++] = (uint8_t)plain->length;
    if (plain->length != 0u) memcpy(wire + n, solaris_buffer_data(plain->buffer) + plain->offset, plain->length);
    rc = solaris_buffer_set_length(*out, n + plain->length);
    if (rc == SOLARIS_OK) codec->requested = 1;
    return rc;
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size,
    size_t *consumed, solaris_address_t *source, solaris_buffer_t **out)
{
    *consumed = 0u; *out = NULL;
    if (size == 0u) return SOLARIS_EAGAIN;
    if (wire[0] > 2u) return SOLARIS_EIO;
    uint8_t address[260]; size_t n = size < sizeof(address) ? size : sizeof(address);
    memcpy(address, wire, n); address[0] = wire[0] == 0u ? 1u : wire[0] == 1u ? 4u : 3u;
    solaris_address_t decoded; size_t header;
    solaris_status_t rc = solaris_socks_address_read(address, n, &decoded, &header);
    if (rc != SOLARIS_OK) return rc;
    if (size - header < 2u) return SOLARIS_EAGAIN;
    size_t length = ((size_t)wire[header] << 8) | wire[header + 1u]; header += 2u;
    if (size - header < length) return SOLARIS_EAGAIN;
    rc = solaris_buffer_copy(((uot_codec_t *)state)->budget, wire + header, length, out);
    if (rc == SOLARIS_OK) { *source = decoded; *consumed = header + length; }
    return rc;
}
static solaris_status_t finish(void *state) { (void)state; return SOLARIS_OK; }
static void destroy(void *state) { solaris_memory_free(state); }
const solaris_datagram_codec_ops_t solaris_uot_v2_codec = {
    1u + 260u + 260u + 2u + UINT16_MAX, UINT16_MAX, create, start, encode, decode, finish, destroy
};
