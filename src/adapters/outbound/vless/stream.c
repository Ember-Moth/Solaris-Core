#include "adapters/outbound/vless/internal.h"
#include "codec/address/vmess.h"
#include <string.h>

typedef struct vless_codec {
    solaris_budget_t *budget;
    solaris_vless_parameters_t parameters;
    int response;
} vless_codec_t;

static solaris_status_t codec_create(const void *parameters, solaris_budget_t *budget, void **out)
{
    if (parameters == NULL || (((const solaris_vless_parameters_t *)parameters)->command != 1u &&
        ((const solaris_vless_parameters_t *)parameters)->command != 3u)) return SOLARIS_EINVAL;
    vless_codec_t *codec = solaris_memory_allocate(budget, sizeof(*codec));
    if (codec == NULL) return SOLARIS_ENOMEM;
    memset(codec, 0, sizeof(*codec)); codec->budget = budget; codec->parameters = *(const solaris_vless_parameters_t *)parameters;
    *out = codec; return SOLARIS_OK;
}
solaris_status_t solaris_vless_request(const solaris_vless_parameters_t *parameters, solaris_budget_t *budget, solaris_buffer_t **out)
{
    const solaris_address_t *address = &parameters->destination;
    uint8_t bytes[300]; size_t n = 0u;
    bytes[n++] = 0u;
    memcpy(bytes + n, parameters->uuid, 16u); n += 16u;
    if (parameters->vision) {
        bytes[n++] = 18u; bytes[n++] = 10u; bytes[n++] = 16u;
        memcpy(bytes + n, "xtls-rprx-vision", 16u); n += 16u;
    } else bytes[n++] = 0u;
    bytes[n++] = parameters->command;
    if (parameters->command != 3u) {
        size_t length;
        solaris_status_t rc = solaris_vmess_address_write(address, bytes + n, sizeof(bytes) - n, &length);
        if (rc != SOLARIS_OK) return rc;
        n += length;
    }
    return solaris_buffer_copy(budget, bytes, n, out);
}
static solaris_status_t codec_start(void *state, solaris_buffer_t **out)
{ vless_codec_t *codec = state; return solaris_vless_request(&codec->parameters, codec->budget, out); }
solaris_status_t solaris_vless_response(const uint8_t *wire, size_t size, size_t *consumed)
{
    *consumed = 0u;
    if (size < 2u) return SOLARIS_EAGAIN;
    if (wire[0] != 0u) return SOLARIS_EIO;
    size_t length = 2u + wire[1];
    if (size < length) return SOLARIS_EAGAIN;
    *consumed = length; return SOLARIS_OK;
}
static solaris_status_t codec_encode(void *state, const solaris_slice_t *plain, solaris_buffer_t **out)
{
    vless_codec_t *codec = state;
    if (plain->length == 0u) { *out = NULL; return SOLARIS_OK; }
    return solaris_buffer_copy(codec->budget, solaris_buffer_data(plain->buffer) + plain->offset, plain->length, out);
}
static solaris_status_t codec_decode(void *state, const uint8_t *wire, size_t size, size_t *consumed, solaris_buffer_t **out)
{
    vless_codec_t *codec = state;
    *consumed = 0u; *out = NULL;
    if (!codec->response) {
        solaris_status_t rc = solaris_vless_response(wire, size, consumed);
        if (rc == SOLARIS_OK) codec->response = 1;
        return rc;
    }
    solaris_status_t rc = solaris_buffer_copy(codec->budget, wire, size, out);
    if (rc == SOLARIS_OK) *consumed = size;
    return rc;
}
static solaris_status_t codec_finish(void *state)
{ return ((vless_codec_t *)state)->response ? SOLARIS_OK : SOLARIS_EIO; }
static void codec_destroy(void *state) { solaris_memory_free(state); }
const solaris_stream_codec_ops_t solaris_vless_stream_codec = {
    .receive_limit = 32768u, .create = codec_create, .start = codec_start,
    .encode = codec_encode, .decode = codec_decode, .finish = codec_finish, .destroy = codec_destroy
};
