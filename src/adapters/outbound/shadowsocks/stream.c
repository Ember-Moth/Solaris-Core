#include "adapters/outbound/shadowsocks/internal.h"
#include "codec/address/socks.h"
#include <openssl/crypto.h>
#include <string.h>

typedef struct ss_stream {
    solaris_budget_t *budget;
    solaris_ss_parameters_t parameters;
    EVP_AEAD_CTX send, receive;
    uint8_t send_nonce[12], receive_nonce[12], salt[32], response_salt[32];
    size_t payload_length;
    int initialized, response, need_payload, replay_checked;
} ss_stream_t;
static void increment(uint8_t nonce[12])
{ for (size_t i = 0u; i < 12u; ++i) if (++nonce[i] != 0u) break; }
static solaris_status_t seal(ss_stream_t *ss, uint8_t *out, size_t capacity, const uint8_t *plain, size_t size)
{
    size_t written = 0u;
    if (!EVP_AEAD_CTX_seal(&ss->send, out, &written, capacity, ss->send_nonce, 12u, plain, size, NULL, 0u)) return SOLARIS_EIO;
    increment(ss->send_nonce); return written == size + 16u ? SOLARIS_OK : SOLARIS_EIO;
}
static solaris_status_t unseal(ss_stream_t *ss, uint8_t *out, size_t capacity, const uint8_t *wire, size_t size)
{
    size_t written = 0u;
    if (!EVP_AEAD_CTX_open(&ss->receive, out, &written, capacity, ss->receive_nonce, 12u, wire, size, NULL, 0u)) return SOLARIS_EACCESS;
    increment(ss->receive_nonce); return written == size - 16u ? SOLARIS_OK : SOLARIS_EIO;
}
static solaris_status_t create(const void *parameters, solaris_budget_t *budget, void **out)
{
    ss_stream_t *ss = solaris_memory_allocate(budget, sizeof(*ss));
    if (ss == NULL) return SOLARIS_ENOMEM;
    memset(ss, 0, sizeof(*ss)); ss->budget = budget; ss->parameters = *(const solaris_ss_parameters_t *)parameters;
    solaris_replay_retain(ss->parameters.replay); *out = ss; return SOLARIS_OK;
}
static solaris_status_t start(void *state, solaris_buffer_t **out)
{
    ss_stream_t *ss = state; solaris_ss_key_t *key = &ss->parameters.key;
    solaris_status_t rc = solaris_ss_random(&ss->parameters.source, ss->salt, key->length);
    if (rc != SOLARIS_OK) return rc;
    if (!key->modern && (rc = solaris_ss_replay(&ss->parameters, ss->salt)) != SOLARIS_OK) return rc;
    rc = solaris_ss_aead(key, ss->salt, key->length, &ss->send);
    if (rc != SOLARIS_OK) return rc;
    uint8_t header[1200], fixed[11]; size_t length = 0u;
    rc = solaris_socks_address_encode(&ss->parameters.destination, header, sizeof(header), &length);
    if (rc != SOLARIS_OK) return rc;
    size_t fixed_size = 2u;
    if (key->modern) {
        uint8_t random[2]; rc = solaris_ss_random(&ss->parameters.source, random, sizeof(random));
        if (rc != SOLARIS_OK) return rc;
        size_t padding = 1u + (((size_t)random[0] << 8) | random[1]) % 900u;
        header[length++] = (uint8_t)(padding >> 8); header[length++] = (uint8_t)padding;
        rc = solaris_ss_random(&ss->parameters.source, header + length, padding);
        if (rc != SOLARIS_OK) return rc;
        length += padding; fixed[0] = 0u; solaris_ss_write64(fixed + 1u, solaris_ss_time(&ss->parameters.source)); fixed_size = 11u;
    }
    fixed[fixed_size - 2u] = (uint8_t)(length >> 8); fixed[fixed_size - 1u] = (uint8_t)length;
    size_t prefix = key->length + key->identity_count * 16u;
    size_t total = prefix + fixed_size + 16u + length + 16u;
    rc = solaris_buffer_allocate(ss->budget, total, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *bytes = solaris_buffer_mutable_data(*out); memcpy(bytes, ss->salt, key->length);
    rc = solaris_ss_identity_headers(key, ss->salt, NULL, bytes + key->length);
    if (rc == SOLARIS_OK) rc = seal(ss, bytes + prefix, fixed_size + 16u, fixed, fixed_size);
    if (rc == SOLARIS_OK) rc = seal(ss, bytes + prefix + fixed_size + 16u, length + 16u, header, length);
    if (rc == SOLARIS_OK) rc = solaris_buffer_set_length(*out, total);
    return rc;
}
static solaris_status_t encode(void *state, const solaris_slice_t *plain, solaris_buffer_t **out)
{
    ss_stream_t *ss = state; *out = NULL;
    if (plain->length == 0u) return SOLARIS_OK;
    size_t maximum = ss->parameters.key.modern ? 65535u : 16383u;
    size_t chunks = plain->length / maximum + (plain->length % maximum != 0u);
    if (chunks > (SIZE_MAX - plain->length) / 34u) return SOLARIS_EOVERFLOW;
    size_t total = plain->length + chunks * 34u;
    solaris_status_t rc = solaris_buffer_allocate(ss->budget, total, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *bytes = solaris_buffer_mutable_data(*out); size_t pos = 0u, offset = 0u;
    while (offset < plain->length) {
        size_t size = plain->length - offset; if (size > maximum) size = maximum;
        uint8_t length[2] = {(uint8_t)(size >> 8), (uint8_t)size};
        rc = seal(ss, bytes + pos, total - pos, length, 2u); if (rc != SOLARIS_OK) return rc; pos += 18u;
        rc = seal(ss, bytes + pos, total - pos, solaris_buffer_data(plain->buffer) + plain->offset + offset, size);
        if (rc != SOLARIS_OK) return rc;
        pos += size + 16u; offset += size;
    }
    return solaris_buffer_set_length(*out, total);
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size, size_t *consumed, solaris_buffer_t **out)
{
    ss_stream_t *ss = state; solaris_ss_key_t *key = &ss->parameters.key;
    *consumed = 0u; *out = NULL;
    if (!ss->initialized) {
        if (size < key->length) return SOLARIS_EAGAIN;
        solaris_status_t rc = solaris_ss_aead(key, wire, key->length, &ss->receive);
        if (rc != SOLARIS_OK) return rc;
        memcpy(ss->response_salt, wire, key->length); ss->initialized = 1;
        *consumed = key->length; return SOLARIS_OK;
    }
    if (!ss->response && key->modern) {
        size_t length = 11u + key->length;
        if (size < length + 16u) return SOLARIS_EAGAIN;
        uint8_t header[43]; solaris_status_t rc = unseal(ss, header, sizeof(header), wire, length + 16u);
        if (rc != SOLARIS_OK) return rc;
        if (header[0] != 1u || !solaris_ss_time_valid(&ss->parameters.source, solaris_ss_read64(header + 1u)) ||
            CRYPTO_memcmp(header + 9u, ss->salt, key->length) != 0) return SOLARIS_EACCESS;
        ss->payload_length = ((size_t)header[length - 2u] << 8) | header[length - 1u];
        ss->need_payload = 1; ss->response = 1; *consumed = length + 16u; return SOLARIS_OK;
    }
    if (!ss->need_payload) {
        if (size < 18u) return SOLARIS_EAGAIN;
        uint8_t length[2]; solaris_status_t rc = unseal(ss, length, sizeof(length), wire, 18u);
        if (rc != SOLARIS_OK) return rc;
        ss->payload_length = ((size_t)length[0] << 8) | length[1];
        if (!key->modern && ss->payload_length > 16383u) return SOLARIS_EIO;
        ss->need_payload = 1; *consumed = 18u; return SOLARIS_OK;
    }
    if (size < ss->payload_length + 16u) return SOLARIS_EAGAIN;
    solaris_status_t rc = solaris_buffer_allocate(ss->budget, ss->payload_length, out);
    if (rc != SOLARIS_OK) return rc;
    rc = unseal(ss, solaris_buffer_mutable_data(*out), ss->payload_length, wire, ss->payload_length + 16u);
    if (rc == SOLARIS_OK && !key->modern && !ss->replay_checked) {
        rc = solaris_ss_replay(&ss->parameters, ss->response_salt); if (rc == SOLARIS_OK) ss->replay_checked = 1;
    }
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_buffer_set_length(*out, ss->payload_length);
    if (rc == SOLARIS_OK) { *consumed = ss->payload_length + 16u; ss->need_payload = 0; ss->response = 1; }
    return rc;
}
static solaris_status_t finish(void *state)
{ ss_stream_t *ss = state; return ss->response && !ss->need_payload ? SOLARIS_OK : SOLARIS_EIO; }
static void destroy(void *state)
{
    ss_stream_t *ss = state; EVP_AEAD_CTX_cleanup(&ss->send); EVP_AEAD_CTX_cleanup(&ss->receive);
    solaris_replay_release(ss->parameters.replay); OPENSSL_cleanse(ss, sizeof(*ss)); solaris_memory_free(ss);
}
const solaris_stream_codec_ops_t solaris_ss_stream_codec = {
    .receive_limit = 98304u, .create = create, .start = start, .encode = encode,
    .decode = decode, .finish = finish, .destroy = destroy
};
