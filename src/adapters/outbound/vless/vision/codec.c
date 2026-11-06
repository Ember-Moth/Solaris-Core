#include "adapters/outbound/vless/vision/codec.h"
#include "adapters/outbound/vless/vision/tls.h"
#include <openssl/rand.h>
#include <string.h>

#define VISION_CHUNK 4096u
#define VISION_PADDING_MAX 1399u
typedef struct vision_codec {
    solaris_budget_t *budget;
    solaris_vless_vision_parameters_t parameters;
    solaris_vless_tls_records_t tx_records, rx_records;
    solaris_vless_tls_hello_t hello;
    uint32_t requested;
    unsigned int padding_packets;
    int started, response, tx_padding, rx_padding, rx_uuid;
} vision_codec_t;
static solaris_status_t uniform(vision_codec_t *codec, uint32_t bound, uint32_t *out)
{
    uint32_t threshold = (0u - bound) % bound;
    for (unsigned int attempt = 0u; attempt < 16u; ++attempt) {
        uint8_t bytes[4]; solaris_crypto_source_t *source = &codec->parameters.crypto;
        solaris_status_t rc = source->random != NULL ? source->random(source->context, bytes, 4u) :
            RAND_bytes(bytes, 4u) ? SOLARIS_OK : SOLARIS_EIO;
        if (rc != SOLARIS_OK) return rc;
        uint32_t n = ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) | ((uint32_t)bytes[2] << 8u) | bytes[3];
        if (n >= threshold) { *out = n % bound; return SOLARIS_OK; }
    }
    return SOLARIS_EIO;
}
static solaris_status_t padding(vision_codec_t *codec, size_t content, int long_padding, size_t *out)
{
    uint32_t n; int large = content < 900u && long_padding;
    solaris_status_t rc = uniform(codec, large ? 500u : 256u, &n);
    if (rc == SOLARIS_OK) *out = large ? 900u + n - content : n;
    return rc;
}
static void write16(uint8_t *out, size_t value) { out[0] = (uint8_t)(value >> 8u); out[1] = (uint8_t)value; }
static size_t frame(uint8_t *wire, uint8_t command, const uint8_t *data, size_t size, size_t pad)
{
    wire[0] = command; write16(wire + 1u, size); write16(wire + 3u, pad);
    if (size != 0u) memcpy(wire + 5u, data, size);
    memset(wire + 5u + size, 0, pad); return 5u + size + pad;
}
static solaris_status_t create(const void *parameters, solaris_budget_t *budget, void **out)
{
    const solaris_vless_vision_parameters_t *p = parameters;
    if (p == NULL || !p->request.vision || (p->request.command != 1u && p->request.command != 3u)) return SOLARIS_EINVAL;
    vision_codec_t *codec = solaris_memory_allocate(budget, sizeof(*codec));
    if (codec == NULL) return SOLARIS_ENOMEM;
    memset(codec, 0, sizeof(*codec)); codec->budget = budget; codec->parameters = *p;
    codec->tx_padding = codec->rx_padding = codec->rx_uuid = 1; codec->padding_packets = 8u; *out = codec; return SOLARIS_OK;
}
static solaris_status_t start(void *state, solaris_buffer_t **out)
{
    vision_codec_t *codec = state; *out = NULL;
    if (codec->started) return SOLARIS_EBUSY;
    size_t pad; solaris_status_t rc = padding(codec, 0u, 1, &pad);
    if (rc != SOLARIS_OK) return rc;
    solaris_buffer_t *request;
    rc = solaris_vless_request(&codec->parameters.request, codec->budget, &request);
    if (rc != SOLARIS_OK) return rc;
    size_t header = solaris_buffer_length(request), size = header + 21u + pad;
    rc = solaris_buffer_allocate(codec->budget, size, out);
    if (rc == SOLARIS_OK) {
        uint8_t *wire = solaris_buffer_mutable_data(*out); memcpy(wire, solaris_buffer_data(request), header);
        memcpy(wire + header, codec->parameters.request.uuid, 16u); (void)frame(wire + header + 16u, 0u, NULL, 0u, pad);
        (void)solaris_buffer_set_length(*out, size); codec->started = 1;
    }
    solaris_buffer_release(request); return rc;
}
static solaris_status_t encode(void *state, const solaris_slice_t *plain, solaris_buffer_t **out)
{
    vision_codec_t *codec = state; *out = NULL;
    if (!codec->started) return SOLARIS_EBUSY;
    if (plain->length == 0u) return SOLARIS_OK;
    const uint8_t *input = solaris_buffer_data(plain->buffer) + plain->offset;
    if (!codec->tx_padding) return solaris_buffer_copy(codec->budget, input, plain->length, out);
    size_t frames = plain->length / VISION_CHUNK + (plain->length % VISION_CHUNK != 0u);
    if (frames > (SIZE_MAX - plain->length) / (5u + VISION_PADDING_MAX)) return SOLARIS_EOVERFLOW;
    size_t capacity = plain->length + frames * (5u + VISION_PADDING_MAX);
    solaris_status_t rc = solaris_buffer_allocate(codec->budget, capacity, out);
    if (rc != SOLARIS_OK) return rc;
    solaris_vless_tls_records_t records = codec->tx_records;
    solaris_vless_tls_observe(&records, NULL, input, plain->length);
    int boundary = solaris_vless_tls_application_boundary(&records);
    int raw = codec->hello.tls13 && boundary;
    int end = boundary && codec->hello.done;
    int wrapping = codec->tx_padding; unsigned int packets = codec->padding_packets;
    uint32_t requests = codec->requested; uint8_t *wire = solaris_buffer_mutable_data(*out); size_t offset = 0u;
    for (size_t sent = 0u; sent < plain->length;) {
        if (!wrapping) { memcpy(wire + offset, input + sent, plain->length - sent); offset += plain->length - sent; break; }
        size_t count = plain->length - sent; if (count > VISION_CHUNK) count = VISION_CHUNK;
        int final = sent + count == plain->length;
        uint8_t command = final && end ? (raw ? 2u : 1u) : 0u;
        if (command == 0u && packets <= 1u && (!records.tls || records.invalid || (codec->hello.done && !codec->hello.tls13))) command = 1u;
        size_t pad; rc = padding(codec, count, records.tls, &pad);
        if (rc != SOLARIS_OK) { solaris_buffer_release(*out); *out = NULL; return rc; }
        offset += frame(wire + offset, command, input + sent, count, pad); sent += count;
        if (packets != 0u) packets--;
        if (command != 0u) wrapping = 0;
        if (command == 2u) requests |= SOLARIS_STREAM_RAW_WRITE;
    }
    codec->tx_records = records; codec->tx_padding = wrapping; codec->padding_packets = packets; codec->requested = requests;
    return solaris_buffer_set_length(*out, offset);
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size, size_t *consumed, solaris_buffer_t **out)
{
    vision_codec_t *codec = state; *consumed = 0u; *out = NULL;
    if (!codec->response) {
        solaris_status_t rc = solaris_vless_response(wire, size, consumed);
        if (rc == SOLARIS_OK) codec->response = 1;
        return rc;
    }
    if (!codec->rx_padding) {
        solaris_status_t rc = solaris_buffer_copy(codec->budget, wire, size, out);
        if (rc == SOLARIS_OK) {
            if (!codec->hello.done) solaris_vless_tls_observe(&codec->rx_records, &codec->hello, wire, size);
            *consumed = size;
        }
        return rc;
    }
    size_t header = codec->rx_uuid ? 16u : 0u;
    if (size < header + 5u) return SOLARIS_EAGAIN;
    if (header != 0u && memcmp(wire, codec->parameters.request.uuid, 16u) != 0) return SOLARIS_EACCESS;
    uint8_t command = wire[header];
    if (command > 2u) return SOLARIS_EIO;
    size_t content = ((size_t)wire[header + 1u] << 8u) | wire[header + 2u];
    size_t pad = ((size_t)wire[header + 3u] << 8u) | wire[header + 4u]; header += 5u;
    if (size - header < content + pad) return SOLARIS_EAGAIN;
    if (content != 0u) {
        solaris_status_t rc = solaris_buffer_copy(codec->budget, wire + header, content, out);
        if (rc != SOLARIS_OK) return rc;
        solaris_vless_tls_observe(&codec->rx_records, &codec->hello, wire + header, content);
    }
    if (command == 2u && (!codec->hello.tls13 || !solaris_vless_tls_application_boundary(&codec->rx_records))) {
        solaris_buffer_release(*out); *out = NULL; return SOLARIS_EIO;
    }
    codec->rx_uuid = 0;
    if (command != 0u) codec->rx_padding = 0;
    if (command == 2u) codec->requested |= SOLARIS_STREAM_RAW_READ;
    *consumed = header + content + pad; return SOLARIS_OK;
}
static solaris_status_t finish(void *state) { return ((vision_codec_t *)state)->response ? SOLARIS_OK : SOLARIS_EIO; }
static void destroy(void *state) { solaris_memory_free(state); }
static uint32_t requested(void *state) { return ((vision_codec_t *)state)->requested; }
static void applied(void *state, uint32_t directions) { ((vision_codec_t *)state)->requested &= ~directions; }
static const solaris_stream_codec_carrier_raw_t carrier_raw = {
    SOLARIS_STREAM_RAW_READ | SOLARIS_STREAM_RAW_WRITE, requested, applied
};
const solaris_stream_codec_ops_t solaris_vless_vision_codec = {
    .receive_limit = 196608u, .create = create, .start = start, .encode = encode, .decode = decode,
    .finish = finish, .destroy = destroy, .carrier_raw = &carrier_raw
};
