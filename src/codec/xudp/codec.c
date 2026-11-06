#include "codec/xudp/codec.h"
#include "codec/address/vmess.h"
#include <string.h>

typedef struct xudp_codec {
    solaris_budget_t *budget;
    solaris_address_t first;
    int requested, ended;
} xudp_codec_t;
static solaris_status_t create(const void *parameters, solaris_budget_t *budget, void **out)
{
    (void)parameters; xudp_codec_t *codec = solaris_memory_allocate(budget, sizeof(*codec));
    if (codec == NULL) return SOLARIS_ENOMEM;
    memset(codec, 0, sizeof(*codec)); codec->budget = budget; *out = codec; return SOLARIS_OK;
}
static solaris_status_t start(void *state, solaris_buffer_t **out)
{ (void)state; *out = NULL; return SOLARIS_OK; }
static solaris_status_t encode(void *state, const solaris_address_t *destination,
    const solaris_slice_t *plain, solaris_buffer_t **out)
{
    xudp_codec_t *codec = state; *out = NULL;
    if (codec->ended) return SOLARIS_ECLOSED;
    if (plain->length > UINT16_MAX) return SOLARIS_EMSGSIZE;
    uint8_t address[260]; size_t n;
    solaris_status_t rc = solaris_vmess_address_write(destination, address, sizeof(address), &n);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_buffer_allocate(codec->budget, 9u + n + plain->length, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out); size_t header = 5u + n;
    wire[0] = (uint8_t)(header >> 8); wire[1] = (uint8_t)header;
    wire[2] = wire[3] = 0u; wire[4] = codec->requested ? 2u : 1u; wire[5] = 1u; wire[6] = 2u;
    memcpy(wire + 7u, address, n); n += 7u;
    wire[n++] = (uint8_t)(plain->length >> 8); wire[n++] = (uint8_t)plain->length;
    if (plain->length != 0u) memcpy(wire + n, solaris_buffer_data(plain->buffer) + plain->offset, plain->length);
    rc = solaris_buffer_set_length(*out, n + plain->length);
    if (rc == SOLARIS_OK && !codec->requested) { codec->first = *destination; codec->requested = 1; }
    return rc;
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size,
    size_t *consumed, solaris_address_t *source, solaris_buffer_t **out)
{
    xudp_codec_t *codec = state; *consumed = 0u; *out = NULL;
    if (codec->ended) return SOLARIS_ECLOSED;
    if (size < 2u) return SOLARIS_EAGAIN;
    size_t metadata = ((size_t)wire[0] << 8) | wire[1];
    if (metadata < 4u || metadata > 265u) return SOLARIS_EIO;
    if (size < metadata + 2u) return SOLARIS_EAGAIN;
    uint8_t status = wire[4], flags = wire[5];
    if ((flags & ~3u) != 0u || (status != 2u && status != 3u && status != 4u)) return SOLARIS_EIO;
    if (status != 4u && (wire[2] != 0u || wire[3] != 0u || !codec->requested)) return SOLARIS_EIO;
    if (status != 2u && metadata != 4u) return SOLARIS_EIO;
    solaris_address_t address = codec->first;
    if (metadata > 4u) {
        if (wire[6] != 2u) return SOLARIS_EIO;
        size_t count;
        solaris_status_t rc = solaris_vmess_address_read(wire + 7u, metadata - 5u, &address, &count);
        if (rc != SOLARIS_OK || count != metadata - 5u) return SOLARIS_EIO;
    }
    size_t n = metadata + 2u, length = 0u;
    if ((flags & 1u) != 0u) {
        if (size - n < 2u) return SOLARIS_EAGAIN;
        length = ((size_t)wire[n] << 8) | wire[n + 1u]; n += 2u;
        if (size - n < length) return SOLARIS_EAGAIN;
    }
    if ((flags & 2u) != 0u) return SOLARIS_EIO;
    if ((flags & 1u) != 0u && status != 4u) {
        solaris_status_t rc = solaris_buffer_copy(codec->budget, wire + n, length, out);
        if (rc != SOLARIS_OK) return rc;
        *source = address;
    }
    *consumed = n + length;
    if (status == 3u) { codec->ended = 1; return SOLARIS_ECLOSED; }
    return SOLARIS_OK;
}
static solaris_status_t finish(void *state) { (void)state; return SOLARIS_OK; }
static void destroy(void *state) { solaris_memory_free(state); }
const solaris_datagram_codec_ops_t solaris_xudp_codec = {
    2u + 265u + 2u + UINT16_MAX, UINT16_MAX, create, start, encode, decode, finish, destroy
};
