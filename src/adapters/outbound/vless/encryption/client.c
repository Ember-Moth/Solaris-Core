#include "adapters/outbound/vless/encryption/client.h"
#include "adapters/outbound/vless/encryption/crypto.h"
#include <openssl/bytestring.h>
#include <openssl/crypto.h>
#include <openssl/curve25519.h>
#include <openssl/mlkem.h>
#include <stdatomic.h>
#include <string.h>

enum { SERVER_PFS, SERVER_TICKET, SERVER_PADDING_LENGTH, SERVER_PADDING, SERVER_RANDOM, RECORDS };
#define ENCRYPTION_CHUNK 8192u
struct solaris_vless_encryption_client {
    atomic_uint references;
    solaris_vless_encryption_config_t config;
    solaris_crypto_source_t crypto;
    void *clock_context;
    uint64_t (*now_ns)(void *);
    uint64_t expires_ns, cache_generation;
    uint8_t ticket[16], pfs_key[64];
};
typedef struct encryption_stream {
    solaris_vless_encryption_client_t *client;
    solaris_budget_t *budget;
    solaris_vless_encryption_aead_t nfs, tx, rx;
    solaris_vless_encryption_ctr_t tx_ctr, rx_ctr;
    solaris_vless_encryption_mask_t tx_mask, rx_mask;
    struct MLKEM768_private_key pfs_mlkem;
    uint8_t pfs_x25519[32], pfs_public[1216], united[96], iv[16], ticket[16];
    solaris_buffer_t *hello;
    size_t lengths[16], delays[16], parts, part, offset, padding_size;
    uint64_t cache_generation;
    uint32_t ticket_seconds;
    int stage, resumed, ready, authenticated, started, raw_read, raw_write;
} encryption_stream_t;

solaris_status_t solaris_vless_encryption_client_create(const solaris_vless_encryption_config_t *config,
    solaris_budget_t *budget, const solaris_crypto_source_t *crypto,
    void *clock_context, uint64_t (*now_ns)(void *), solaris_vless_encryption_client_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (config == NULL || budget == NULL || now_ns == NULL || config->key_count == 0u ||
        config->key_count > SOLARIS_VLESS_ENCRYPTION_KEYS || config->padding_count == 0u ||
        config->padding_count > SOLARIS_VLESS_ENCRYPTION_PADDING) return SOLARIS_EINVAL;
    solaris_vless_encryption_client_t *client = solaris_memory_allocate(budget, sizeof(*client));
    if (client == NULL) return SOLARIS_ENOMEM;
    memset(client, 0, sizeof(*client)); atomic_init(&client->references, 1u); client->config = *config;
    if (crypto != NULL) client->crypto = *crypto;
    client->clock_context = clock_context; client->now_ns = now_ns; *out = client; return SOLARIS_OK;
}
void solaris_vless_encryption_client_retain(solaris_vless_encryption_client_t *client)
{ if (client != NULL) (void)atomic_fetch_add_explicit(&client->references, 1u, memory_order_relaxed); }
void solaris_vless_encryption_client_release(solaris_vless_encryption_client_t *client)
{
    if (client != NULL && atomic_fetch_sub_explicit(&client->references, 1u, memory_order_acq_rel) == 1u) {
        OPENSSL_cleanse(client, sizeof(*client)); solaris_memory_free(client);
    }
}
static solaris_status_t create(const void *parameters, solaris_budget_t *budget, void **out)
{
    if (parameters == NULL) return SOLARIS_EINVAL;
    encryption_stream_t *stream = solaris_memory_allocate(budget, sizeof(*stream));
    if (stream == NULL) return SOLARIS_ENOMEM;
    memset(stream, 0, sizeof(*stream)); stream->client = (solaris_vless_encryption_client_t *)parameters;
    solaris_vless_encryption_client_retain(stream->client); stream->budget = budget; *out = stream; return SOLARIS_OK;
}
static solaris_status_t select_range(encryption_stream_t *stream, const solaris_vless_encryption_range_t *range, size_t *out)
{
    uint32_t choice; *out = 0u;
    solaris_status_t rc = solaris_vless_encryption_uniform(&stream->client->crypto, 100u, &choice);
    if (rc != SOLARIS_OK || choice >= range->probability) return rc;
    *out = range->minimum;
    if (range->minimum == range->maximum) return SOLARIS_OK;
    rc = solaris_vless_encryption_uniform(&stream->client->crypto, range->maximum - range->minimum, &choice);
    if (rc == SOLARIS_OK) *out += choice;
    return rc;
}
static solaris_status_t padding(encryption_stream_t *stream, size_t *total)
{
    *total = 0u;
    for (size_t i = 0u; i < stream->client->config.padding_count; ++i) {
        size_t n; solaris_status_t rc = select_range(stream, &stream->client->config.padding[i], &n);
        if (rc != SOLARIS_OK) return rc;
        if ((i & 1u) == 0u) { stream->lengths[i / 2u] = n; *total += n; stream->parts++; }
        else stream->delays[i / 2u] = n;
    }
    return *total >= 35u && *total <= 65553u ? SOLARIS_OK : SOLARIS_EINVAL;
}
static solaris_status_t relay(encryption_stream_t *stream, uint8_t *wire)
{
    const solaris_vless_encryption_config_t *config = &stream->client->config;
    solaris_vless_encryption_ctr_t previous = {0};
    uint8_t shared[32] = {0}; solaris_status_t rc = SOLARIS_OK;
    for (size_t i = 0u; i < config->key_count; ++i) {
        const solaris_vless_encryption_key_t *key = &config->keys[i]; size_t size;
        if (key->length == 32u) {
            uint8_t private_key[32]; rc = solaris_vless_encryption_random(&stream->client->crypto, private_key, 32u);
            if (rc == SOLARIS_OK) {
                X25519_public_from_private(wire, private_key);
                if (!X25519(shared, private_key, key->bytes)) rc = SOLARIS_EACCESS;
            }
            OPENSSL_cleanse(private_key, sizeof(private_key)); size = 32u;
        } else {
            struct MLKEM768_public_key public_key; CBS input; CBS_init(&input, key->bytes, key->length);
            if (!MLKEM768_parse_public_key(&public_key, &input)) rc = SOLARIS_EINVAL;
            else MLKEM768_encap(wire, shared, &public_key);
            size = 1088u;
        }
        if (rc != SOLARIS_OK) break;
        if (config->mode != 0u) {
            solaris_vless_encryption_ctr_t mask;
            solaris_vless_encryption_ctr_init(&mask, key->bytes, key->length, stream->iv);
            solaris_vless_encryption_ctr_apply(&mask, wire, wire, size); OPENSSL_cleanse(&mask, sizeof(mask));
        }
        if (i != 0u) solaris_vless_encryption_ctr_apply(&previous, wire, wire, 32u);
        if (i + 1u < config->key_count) {
            uint8_t hash[32]; solaris_vless_encryption_hash(config->keys[i + 1u].bytes, config->keys[i + 1u].length, hash);
            solaris_vless_encryption_ctr_init(&previous, shared, 32u, stream->iv);
            solaris_vless_encryption_ctr_apply(&previous, hash, wire + size, 32u); wire += size + 32u;
        }
    }
    if (rc == SOLARIS_OK) {
        memcpy(stream->united + 64u, shared, 32u);
        rc = solaris_vless_encryption_aead_init(&stream->nfs, config->chacha, stream->iv, 16u, shared, 32u);
    }
    OPENSSL_cleanse(shared, sizeof(shared)); OPENSSL_cleanse(&previous, sizeof(previous)); return rc;
}
static void write_length(uint8_t out[2], size_t value)
{ out[0] = (uint8_t)(value >> 8u); out[1] = (uint8_t)value; }
static solaris_status_t next_preface(void *state, solaris_buffer_t **out, uint64_t *delay_ms)
{
    encryption_stream_t *stream = state; *out = NULL; *delay_ms = 0u;
    size_t part = stream->part;
    while (part < stream->parts) {
        if (part != 0u) *delay_ms += stream->delays[part - 1u];
        size_t count = stream->lengths[part++];
        if (count == 0u) continue;
        solaris_status_t rc = solaris_buffer_copy(stream->budget,
            solaris_buffer_data(stream->hello) + stream->offset, count, out);
        if (rc != SOLARIS_OK) return rc;
        stream->offset += count; stream->part = part; return SOLARIS_OK;
    }
    stream->part = part;
    solaris_buffer_release(stream->hello); stream->hello = NULL; return SOLARIS_OK;
}
static solaris_status_t start(void *state, solaris_buffer_t **out)
{
    encryption_stream_t *stream = state; solaris_vless_encryption_client_t *client = stream->client;
    const solaris_vless_encryption_config_t *config = &client->config; *out = NULL;
    if (stream->started) return SOLARIS_EBUSY;
    stream->started = 1;
    uint64_t now = client->now_ns(client->clock_context);
    stream->resumed = config->resume && now < client->expires_ns;
    if (stream->resumed) {
        memcpy(stream->united, client->pfs_key, 64u); memcpy(stream->ticket, client->ticket, 16u);
        stream->cache_generation = client->cache_generation;
    }
    size_t relays = 16u;
    for (size_t i = 0u; i < config->key_count; ++i) relays += (config->keys[i].length == 32u ? 32u : 1088u) + (i == 0u ? 0u : 32u);
    size_t pad_size = 0u;
    solaris_status_t rc = stream->resumed ? SOLARIS_OK : padding(stream, &pad_size);
    if (rc != SOLARIS_OK) return rc;
    size_t hello_size = relays + (stream->resumed ? 50u : 1250u + pad_size);
    rc = solaris_buffer_allocate(stream->budget, hello_size, &stream->hello);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(stream->hello);
    rc = solaris_vless_encryption_random(&client->crypto, stream->iv, 16u);
    if (rc != SOLARIS_OK) return rc;
    memcpy(wire, stream->iv, 16u); rc = relay(stream, wire + 16u);
    if (rc != SOLARIS_OK) return rc;
    uint8_t length[2]; write_length(length, stream->resumed ? 32u : 1232u);
    rc = solaris_vless_encryption_seal(&stream->nfs, NULL, length, 2u, NULL, 0u, wire + relays);
    if (rc != SOLARIS_OK) return rc;
    if (stream->resumed) {
        rc = solaris_vless_encryption_seal(&stream->nfs, NULL, stream->ticket, 16u, NULL, 0u, wire + relays + 18u);
        if (rc == SOLARIS_OK) rc = solaris_vless_encryption_aead_init(&stream->tx, config->chacha,
            wire + relays + 18u, 32u, stream->united, 96u);
        if (rc != SOLARIS_OK) return rc;
        if (config->mode == 2u) solaris_vless_encryption_ctr_init(&stream->tx_ctr, stream->united, 96u, stream->iv);
        stream->ready = 1; stream->stage = SERVER_RANDOM; stream->parts = 1u; stream->lengths[0] = hello_size;
        solaris_vless_encryption_aead_clear(&stream->nfs);
    } else {
        uint8_t seed[64]; rc = solaris_vless_encryption_random(&client->crypto, seed, sizeof(seed));
        if (rc == SOLARIS_OK && !MLKEM768_private_key_from_seed(&stream->pfs_mlkem, seed, sizeof(seed))) rc = SOLARIS_EIO;
        OPENSSL_cleanse(seed, sizeof(seed));
        if (rc != SOLARIS_OK) return rc;
        struct MLKEM768_public_key public_key; MLKEM768_public_from_private(&public_key, &stream->pfs_mlkem);
        CBB encoded; CBB_zero(&encoded);
        if (!CBB_init_fixed(&encoded, stream->pfs_public, 1184u) || !MLKEM768_marshal_public_key(&encoded, &public_key) || CBB_len(&encoded) != 1184u) rc = SOLARIS_EIO;
        CBB_cleanup(&encoded); if (rc != SOLARIS_OK) return rc;
        rc = solaris_vless_encryption_random(&client->crypto, stream->pfs_x25519, 32u);
        if (rc != SOLARIS_OK) return rc;
        X25519_public_from_private(stream->pfs_public + 1184u, stream->pfs_x25519);
        rc = solaris_vless_encryption_seal(&stream->nfs, NULL, stream->pfs_public, 1216u, NULL, 0u, wire + relays + 18u);
        if (rc != SOLARIS_OK) return rc;
        uint8_t *pad = wire + relays + 1250u; write_length(length, pad_size - 18u);
        rc = solaris_vless_encryption_seal(&stream->nfs, NULL, length, 2u, NULL, 0u, pad);
        if (rc != SOLARIS_OK) return rc;
        memset(pad + 18u, 0, pad_size - 34u);
        rc = solaris_vless_encryption_seal(&stream->nfs, NULL, pad + 18u, pad_size - 34u, NULL, 0u, pad + 18u);
        if (rc != SOLARIS_OK) return rc;
        stream->lengths[0] += relays + 1250u; stream->stage = SERVER_PFS;
    }
    (void)solaris_buffer_set_length(stream->hello, hello_size);
    uint64_t delay; return next_preface(stream, out, &delay);
}
static solaris_status_t encode(void *state, const solaris_slice_t *plain, solaris_buffer_t **out)
{
    encryption_stream_t *stream = state; *out = NULL;
    if (!stream->ready) return SOLARIS_EBUSY;
    if (plain->length == 0u) return SOLARIS_OK;
    if (stream->raw_write) {
        solaris_status_t rc = solaris_buffer_allocate(stream->budget, plain->length, out);
        if (rc != SOLARIS_OK) return rc;
        const uint8_t *input = solaris_buffer_data(plain->buffer) + plain->offset;
        uint8_t *wire = solaris_buffer_mutable_data(*out);
        if (stream->client->config.mode == 2u) rc = solaris_vless_encryption_mask_stream(&stream->tx_ctr, &stream->tx_mask, 1, input, plain->length, wire);
        else memcpy(wire, input, plain->length);
        if (rc != SOLARIS_OK) { solaris_buffer_release(*out); *out = NULL; return rc; }
        return solaris_buffer_set_length(*out, plain->length);
    }
    size_t records = plain->length / ENCRYPTION_CHUNK + (plain->length % ENCRYPTION_CHUNK != 0u);
    if (records > (SIZE_MAX - plain->length) / 21u) return SOLARIS_EOVERFLOW;
    size_t capacity = plain->length + records * 21u;
    solaris_status_t rc = solaris_buffer_allocate(stream->budget, capacity, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out); const uint8_t *input = solaris_buffer_data(plain->buffer) + plain->offset;
    size_t offset = 0u;
    for (size_t sent = 0u; sent < plain->length;) {
        size_t count = plain->length - sent; if (count > ENCRYPTION_CHUNK) count = ENCRYPTION_CHUNK;
        rc = solaris_vless_encryption_record_seal(&stream->tx, &stream->tx_ctr, stream->client->config.mode == 2u,
            stream->client->config.chacha, stream->united, input + sent, count, wire + offset);
        if (rc != SOLARIS_OK) { solaris_buffer_release(*out); *out = NULL; return rc; }
        sent += count; offset += count + 21u;
    }
    return solaris_buffer_set_length(*out, capacity);
}
static solaris_status_t failed(encryption_stream_t *stream, solaris_status_t status)
{
    if (stream->resumed && !stream->authenticated && stream->cache_generation == stream->client->cache_generation) {
        stream->client->expires_ns = 0u;
        OPENSSL_cleanse(stream->client->ticket, 16u); OPENSSL_cleanse(stream->client->pfs_key, 64u);
    }
    return status;
}
static solaris_status_t server_pfs(encryption_stream_t *stream, const uint8_t *wire)
{
    uint8_t public_key[1120], nonce[12]; memset(nonce, 255, sizeof(nonce));
    solaris_status_t rc = solaris_vless_encryption_unseal(&stream->nfs, nonce, wire, 1136u, NULL, 0u, public_key);
    if (rc != SOLARIS_OK) return rc;
    if (public_key[1119] >= 128u || !MLKEM768_decap(stream->united, public_key, 1088u, &stream->pfs_mlkem) ||
        !X25519(stream->united + 32u, stream->pfs_x25519, public_key + 1088u)) return SOLARIS_EACCESS;
    rc = solaris_vless_encryption_aead_init(&stream->tx, stream->client->config.chacha,
        stream->pfs_public, 1216u, stream->united, 96u);
    if (rc == SOLARIS_OK) rc = solaris_vless_encryption_aead_init(&stream->rx, stream->client->config.chacha,
        public_key, 1120u, stream->united, 96u);
    OPENSSL_cleanse(&stream->pfs_mlkem, sizeof(stream->pfs_mlkem)); OPENSSL_cleanse(stream->pfs_x25519, 32u);
    solaris_vless_encryption_aead_clear(&stream->nfs);
    if (rc == SOLARIS_OK && stream->client->config.mode == 2u)
        solaris_vless_encryption_ctr_init(&stream->tx_ctr, stream->united, 96u, stream->iv);
    return rc;
}
static void cache_ticket(encryption_stream_t *stream)
{
    solaris_vless_encryption_client_t *client = stream->client;
    if (!client->config.resume || stream->ticket_seconds == 0u) return;
    uint64_t now = client->now_ns(client->clock_context), duration = (uint64_t)stream->ticket_seconds * UINT64_C(1000000000);
    if (now > UINT64_MAX - duration) return;
    memcpy(client->ticket, stream->ticket, 16u); memcpy(client->pfs_key, stream->united, 64u);
    client->expires_ns = now + duration; client->cache_generation++;
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size, size_t *consumed, solaris_buffer_t **out)
{
    encryption_stream_t *stream = state; *consumed = 0u; *out = NULL; solaris_status_t rc;
    if (stream->raw_read) {
        rc = solaris_buffer_allocate(stream->budget, size, out); if (rc != SOLARIS_OK) return rc;
        uint8_t *plain = solaris_buffer_mutable_data(*out);
        if (stream->client->config.mode == 2u) rc = solaris_vless_encryption_mask_stream(&stream->rx_ctr, &stream->rx_mask, 0, wire, size, plain);
        else memcpy(plain, wire, size);
        if (rc != SOLARIS_OK) { solaris_buffer_release(*out); *out = NULL; return rc; }
        (void)solaris_buffer_set_length(*out, size); *consumed = size; return SOLARIS_OK;
    }
    switch (stream->stage) {
    case SERVER_PFS:
        if (size < 1136u) return SOLARIS_EAGAIN;
        rc = server_pfs(stream, wire);
        if (rc != SOLARIS_OK) return failed(stream, rc);
        stream->stage = SERVER_TICKET; *consumed = 1136u; return SOLARIS_OK;
    case SERVER_TICKET:
        if (size < 32u) return SOLARIS_EAGAIN;
        rc = solaris_vless_encryption_unseal(&stream->rx, NULL, wire, 32u, NULL, 0u, stream->ticket);
        if (rc != SOLARIS_OK) return failed(stream, rc);
        stream->ticket_seconds = ((uint32_t)stream->ticket[0] << 8u) | stream->ticket[1];
        stream->stage = SERVER_PADDING_LENGTH; *consumed = 32u; return SOLARIS_OK;
    case SERVER_PADDING_LENGTH: {
        if (size < 18u) return SOLARIS_EAGAIN;
        uint8_t length[2]; rc = solaris_vless_encryption_unseal(&stream->rx, NULL, wire, 18u, NULL, 0u, length);
        if (rc != SOLARIS_OK) return failed(stream, rc);
        stream->padding_size = ((size_t)length[0] << 8u) | length[1];
        if (stream->padding_size < 17u) return failed(stream, SOLARIS_EIO);
        stream->stage = SERVER_PADDING; *consumed = 18u; return SOLARIS_OK;
    }
    case SERVER_PADDING: {
        if (size < stream->padding_size) return SOLARIS_EAGAIN;
        uint8_t *plain = solaris_memory_allocate(stream->budget, stream->padding_size - 16u);
        if (plain == NULL) return SOLARIS_ENOMEM;
        rc = solaris_vless_encryption_unseal(&stream->rx, NULL, wire, stream->padding_size, NULL, 0u, plain);
        OPENSSL_cleanse(plain, stream->padding_size - 16u); solaris_memory_free(plain);
        if (rc != SOLARIS_OK) return failed(stream, rc);
        if (stream->client->config.mode == 2u) solaris_vless_encryption_ctr_init(&stream->rx_ctr, stream->united, 96u, stream->ticket);
        stream->authenticated = stream->ready = 1; stream->stage = RECORDS; cache_ticket(stream);
        *consumed = stream->padding_size; return SOLARIS_OK;
    }
    case SERVER_RANDOM:
        if (size < 16u) return SOLARIS_EAGAIN;
        rc = solaris_vless_encryption_aead_init(&stream->rx, stream->client->config.chacha, wire, 16u, stream->united, 96u);
        if (rc != SOLARIS_OK) return failed(stream, rc);
        if (stream->client->config.mode == 2u) solaris_vless_encryption_ctr_init(&stream->rx_ctr, stream->united, 96u, wire);
        stream->stage = RECORDS; *consumed = 16u; return SOLARIS_OK;
    default: break;
    }
    size_t length;
    rc = solaris_vless_encryption_record_size(&stream->rx_ctr, stream->client->config.mode == 2u, wire, size, &length);
    if (rc != SOLARIS_OK) return rc == SOLARIS_EAGAIN ? rc : failed(stream, rc);
    rc = solaris_buffer_allocate(stream->budget, length - 16u, out);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_vless_encryption_record_open(&stream->rx, &stream->rx_ctr, stream->client->config.mode == 2u,
        stream->client->config.chacha, stream->united, wire, size, solaris_buffer_mutable_data(*out));
    if (rc != SOLARIS_OK) { solaris_buffer_release(*out); *out = NULL; return failed(stream, rc); }
    stream->authenticated = 1;
    (void)solaris_buffer_set_length(*out, length - 16u); *consumed = length + 5u; return SOLARIS_OK;
}
static int ready(void *state) { return ((encryption_stream_t *)state)->ready; }
static solaris_status_t finish(void *state)
{
    encryption_stream_t *stream = state;
    if (stream->raw_read && stream->client->config.mode == 2u &&
        (stream->rx_mask.header_size != 0u || stream->rx_mask.remaining != 0u)) return SOLARIS_EIO;
    return stream->stage == RECORDS && stream->authenticated ? SOLARIS_OK : failed(stream, SOLARIS_EIO);
}
static solaris_status_t read_raw(void *state)
{
    encryption_stream_t *stream = state;
    if (!stream->authenticated || stream->stage != RECORDS) return SOLARIS_EBUSY;
    stream->raw_read = 1; return SOLARIS_OK;
}
static solaris_status_t write_raw(void *state)
{
    encryption_stream_t *stream = state;
    if (!stream->authenticated || stream->stage != RECORDS) return SOLARIS_EBUSY;
    stream->raw_write = 1; return SOLARIS_OK;
}
static void destroy(void *state)
{
    encryption_stream_t *stream = state;
    /* A reset/timeout can end the carrier without a decodable response or EOF.
     * Conservatively discard an unconfirmed resumption even on local cancel;
     * only its matching generation may be invalidated. Never retry its data. */
    (void)failed(stream, SOLARIS_ECANCELLED);
    solaris_vless_encryption_aead_clear(&stream->nfs); solaris_vless_encryption_aead_clear(&stream->tx);
    solaris_vless_encryption_aead_clear(&stream->rx); solaris_buffer_release(stream->hello);
    solaris_vless_encryption_client_release(stream->client); OPENSSL_cleanse(stream, sizeof(*stream)); solaris_memory_free(stream);
}
static const solaris_stream_codec_raw_ops_t raw_operations = {read_raw, write_raw};
const solaris_stream_codec_ops_t solaris_vless_encryption_codec = {
    .receive_limit = 98304u, .create = create, .start = start, .encode = encode, .decode = decode,
    .finish = finish, .destroy = destroy, .ready = ready, .next_preface = next_preface, .raw = &raw_operations
};
