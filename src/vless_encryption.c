/*
 * Wire-compatible implementation of XTLS VLESS Encryption at
 * Xray-core b17a88f9b46d. This file is licensed under MPL-2.0.
 */

#include "vless/encryption.h"

#include "platform.h"

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/aead.h>
#include <openssl/bytestring.h>
#include <openssl/curve25519.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/mlkem.h>
#include <openssl/rand.h>
#include <uv.h>

#include "aproxy/ring.h"
#include "blake3.h"

#define VLESS_ENCRYPTION_IV_LEN 16u
#define VLESS_ENCRYPTION_KEY_LEN 32u
#define VLESS_ENCRYPTION_PFS_PUBLIC_LEN                                  \
    (MLKEM768_PUBLIC_KEY_BYTES + X25519_PUBLIC_VALUE_LEN)
#define VLESS_ENCRYPTION_SERVER_PFS_LEN                                  \
    (MLKEM768_CIPHERTEXT_BYTES + X25519_PUBLIC_VALUE_LEN)
#define VLESS_ENCRYPTION_TAG_LEN 16u
#define VLESS_ENCRYPTION_HEADER_LEN 5u
#define VLESS_ENCRYPTION_MAX_CIPHERTEXT 16640u
#define VLESS_ENCRYPTION_INPUT_LIMIT (256u * 1024u)
#define VLESS_ENCRYPTION_MAX_PADDING_FIELDS 64u
#define VLESS_ENCRYPTION_MAX_PADDING_PARTS 32u

typedef enum encryption_key_type {
    ENCRYPTION_KEY_X25519 = 0,
    ENCRYPTION_KEY_MLKEM768 = 1,
} encryption_key_type_t;

typedef struct encryption_key {
    uint8_t *encoded;
    size_t encoded_len;
    encryption_key_type_t type;
    struct MLKEM768_public_key mlkem;
} encryption_key_t;

typedef struct padding_parameter {
    uint16_t chance;
    uint16_t from;
    uint16_t to;
} padding_parameter_t;

struct vless_encryption_client_config {
    encryption_key_t keys[VLESS_ENCRYPTION_MAX_KEYS];
    padding_parameter_t padding_lengths[VLESS_ENCRYPTION_MAX_PADDING_PARTS];
    padding_parameter_t padding_gaps[VLESS_ENCRYPTION_MAX_PADDING_PARTS];
    size_t key_count;
    size_t padding_length_count;
    size_t padding_gap_count;
    size_t relays_len;
    vless_encryption_mode_t mode;
    vless_encryption_rtt_t rtt;
    uv_mutex_t ticket_lock;
    uint8_t ticket[16];
    uint8_t pfs_key[64];
    time_t ticket_expires_at;
    int ticket_lock_initialized;
    int ticket_valid;
};

typedef struct encryption_aead {
    EVP_AEAD_CTX ctx;
    uint8_t nonce[12];
    int initialized;
} encryption_aead_t;

typedef enum encryption_phase {
    ENCRYPTION_PHASE_NEW = 0,
    ENCRYPTION_PHASE_WAIT_SERVER_PFS,
    ENCRYPTION_PHASE_WAIT_TICKET,
    ENCRYPTION_PHASE_WAIT_PADDING_LENGTH,
    ENCRYPTION_PHASE_WAIT_PADDING,
    ENCRYPTION_PHASE_WAIT_SERVER_RANDOM,
    ENCRYPTION_PHASE_RECORDS,
    ENCRYPTION_PHASE_FAILED,
} encryption_phase_t;

struct vless_encryption_client {
    vless_encryption_client_config_t *config;
    aproxy_ring_t input;
    aproxy_buffer_t prewrite;
    aproxy_buffer_t record_scratch;
    encryption_aead_t nfs_aead;
    encryption_aead_t send_aead;
    encryption_aead_t receive_aead;
    EVP_CIPHER_CTX *send_ctr;
    EVP_CIPHER_CTX *receive_ctr;
    struct MLKEM768_private_key pfs_mlkem_private;
    uint8_t pfs_public[VLESS_ENCRYPTION_PFS_PUBLIC_LEN];
    uint8_t pfs_x25519_private[X25519_PRIVATE_KEY_LEN];
    uint8_t iv[VLESS_ENCRYPTION_IV_LEN];
    uint8_t nfs_key[VLESS_ENCRYPTION_KEY_LEN];
    uint8_t united_key[96];
    uint8_t ticket[16];
    uint8_t record_header[VLESS_ENCRYPTION_HEADER_LEN];
    size_t peer_padding_len;
    size_t record_ciphertext_len;
    encryption_phase_t phase;
    int send_ready;
    int receive_ready;
    int record_header_ready;
    int resumed;
    int prewrite_sent;
    int use_aes;
};

static void derive_key(uint8_t out[32],
                       const uint8_t *context,
                       size_t context_len,
                       const uint8_t *material,
                       size_t material_len)
{
    blake3_hasher hasher;
    blake3_hasher_init_derive_key_raw(&hasher, context, context_len);
    blake3_hasher_update(&hasher, material, material_len);
    blake3_hasher_finalize(&hasher, out, 32u);
}

static void hash_key(uint8_t out[32], const uint8_t *key, size_t key_len)
{
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, key, key_len);
    blake3_hasher_finalize(&hasher, out, 32u);
}

static int random_between(uint32_t from, uint32_t to, uint32_t *out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (from > to) {
        const uint32_t swap = from;
        from = to;
        to = swap;
    }
    if (from == to) {
        *out = from;
        return APROXY_OK;
    }
    const uint32_t range = to - from;
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % range);
    uint32_t value = 0u;
    do {
        if (RAND_bytes((uint8_t *)&value, sizeof(value)) != 1) {
            return APROXY_ERR_CRYPTO;
        }
    } while (value >= limit);
    *out = from + value % range;
    return APROXY_OK;
}

static int parse_uint(const char *begin,
                      const char *end,
                      unsigned long maximum,
                      unsigned long *out)
{
    if (begin == NULL || end == NULL || out == NULL || begin == end) {
        return APROXY_ERR_PARSE;
    }
    errno = 0;
    char *parsed_end = NULL;
    const unsigned long value = strtoul(begin, &parsed_end, 10);
    if (errno != 0 || parsed_end != end || value > maximum) {
        return APROXY_ERR_PARSE;
    }
    *out = value;
    return APROXY_OK;
}

static int parse_padding_parameter(const char *raw,
                                   size_t index,
                                   padding_parameter_t *out)
{
    const char *first = strchr(raw, '-');
    const char *second = first == NULL ? NULL : strchr(first + 1, '-');
    if (first == NULL || second == NULL || strchr(second + 1, '-') != NULL) {
        return APROXY_ERR_PARSE;
    }
    unsigned long chance = 0ul;
    unsigned long from = 0ul;
    unsigned long to = 0ul;
    if (parse_uint(raw, first, 100ul, &chance) != APROXY_OK ||
        parse_uint(first + 1, second, UINT16_MAX, &from) != APROXY_OK ||
        parse_uint(second + 1, raw + strlen(raw), UINT16_MAX, &to) !=
            APROXY_OK ||
        (index == 0u &&
         (chance < 100ul || from < 35ul || to < 35ul))) {
        return APROXY_ERR_PARSE;
    }
    out->chance = (uint16_t)chance;
    out->from = (uint16_t)from;
    out->to = (uint16_t)to;
    return APROXY_OK;
}

static int base64url_value(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return (int)(ch - 'A');
    }
    if (ch >= 'a' && ch <= 'z') {
        return (int)(ch - 'a') + 26;
    }
    if (ch >= '0' && ch <= '9') {
        return (int)(ch - '0') + 52;
    }
    if (ch == '-') {
        return 62;
    }
    if (ch == '_') {
        return 63;
    }
    return -1;
}

static int base64url_decode(const char *input,
                            uint8_t **decoded,
                            size_t *decoded_len)
{
    if (input == NULL || decoded == NULL || decoded_len == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const size_t len = strlen(input);
    if (len == 0u || len > 2048u || len % 4u == 1u) {
        return APROXY_ERR_PARSE;
    }
    const size_t output_len = len * 6u / 8u;
    uint8_t *output = (uint8_t *)malloc(output_len == 0u ? 1u : output_len);
    if (output == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    uint32_t accumulator = 0u;
    unsigned int bits = 0u;
    size_t position = 0u;
    for (size_t i = 0u; i < len; i++) {
        const int value = base64url_value((unsigned char)input[i]);
        if (value < 0) {
            free(output);
            return APROXY_ERR_PARSE;
        }
        accumulator = (accumulator << 6u) | (uint32_t)value;
        bits += 6u;
        if (bits >= 8u) {
            bits -= 8u;
            output[position++] = (uint8_t)(accumulator >> bits);
            accumulator &= bits == 0u ? 0u : (1u << bits) - 1u;
        }
    }
    if (position != output_len || accumulator != 0u) {
        free(output);
        return APROXY_ERR_PARSE;
    }
    *decoded = output;
    *decoded_len = output_len;
    return APROXY_OK;
}

static int parse_key(encryption_key_t *key, const char *raw)
{
    uint8_t *decoded = NULL;
    size_t decoded_len = 0u;
    int rc = base64url_decode(raw, &decoded, &decoded_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (decoded_len == X25519_PUBLIC_VALUE_LEN) {
        key->type = ENCRYPTION_KEY_X25519;
    } else if (decoded_len == MLKEM768_PUBLIC_KEY_BYTES) {
        CBS input;
        CBS_init(&input, decoded, decoded_len);
        if (!MLKEM768_parse_public_key(&key->mlkem, &input)) {
            free(decoded);
            return APROXY_ERR_PARSE;
        }
        key->type = ENCRYPTION_KEY_MLKEM768;
    } else {
        free(decoded);
        return APROXY_ERR_PARSE;
    }
    key->encoded = decoded;
    key->encoded_len = decoded_len;
    return APROXY_OK;
}

static void config_clear(vless_encryption_client_config_t *config)
{
    if (config == NULL) {
        return;
    }
    for (size_t i = 0u; i < config->key_count; i++) {
        free(config->keys[i].encoded);
    }
    if (config->ticket_lock_initialized) {
        uv_mutex_destroy(&config->ticket_lock);
    }
    OPENSSL_cleanse(config, sizeof(*config));
}

int vless_encryption_client_config_parse(
    const char *raw,
    vless_encryption_client_config_t **out)
{
    if (raw == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    const size_t raw_len = strlen(raw);
    if (raw_len == 0u || raw[0] == '.' || raw[raw_len - 1u] == '.' ||
        strstr(raw, "..") != NULL) {
        return APROXY_ERR_PARSE;
    }
    char *copy = strdup(raw);
    if (copy == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    char *fields[3u + VLESS_ENCRYPTION_MAX_PADDING_FIELDS +
                 VLESS_ENCRYPTION_MAX_KEYS + 1u];
    size_t field_count = 0u;
    char *save = NULL;
    for (char *field = strtok_r(copy, ".", &save); field != NULL;
         field = strtok_r(NULL, ".", &save)) {
        if (field_count >= sizeof(fields) / sizeof(fields[0])) {
            free(copy);
            return APROXY_ERR_PARSE;
        }
        fields[field_count++] = field;
    }
    if (field_count < 4u || strcmp(fields[0], VLESS_ENCRYPTION_METHOD) != 0) {
        free(copy);
        return APROXY_ERR_UNSUPPORTED;
    }

    vless_encryption_client_config_t *config =
        (vless_encryption_client_config_t *)calloc(1u, sizeof(*config));
    if (config == NULL) {
        free(copy);
        return APROXY_ERR_NO_MEMORY;
    }
    int rc = APROXY_OK;
    if (strcmp(fields[1], "native") == 0) {
        config->mode = VLESS_ENCRYPTION_MODE_NATIVE;
    } else if (strcmp(fields[1], "xorpub") == 0) {
        config->mode = VLESS_ENCRYPTION_MODE_XORPUB;
    } else if (strcmp(fields[1], "random") == 0) {
        config->mode = VLESS_ENCRYPTION_MODE_RANDOM;
    } else {
        rc = APROXY_ERR_PARSE;
        goto fail;
    }
    if (strcmp(fields[2], "1rtt") == 0) {
        config->rtt = VLESS_ENCRYPTION_1RTT;
    } else if (strcmp(fields[2], "0rtt") == 0) {
        config->rtt = VLESS_ENCRYPTION_0RTT;
    } else {
        rc = APROXY_ERR_PARSE;
        goto fail;
    }

    int keys_started = 0;
    size_t padding_fields = 0u;
    size_t maximum_padding = 0u;
    size_t maximum_gap = 0u;
    for (size_t i = 3u; i < field_count; i++) {
        encryption_key_t candidate;
        memset(&candidate, 0, sizeof(candidate));
        rc = parse_key(&candidate, fields[i]);
        if (rc == APROXY_OK) {
            keys_started = 1;
            if (config->key_count >= VLESS_ENCRYPTION_MAX_KEYS) {
                free(candidate.encoded);
                rc = APROXY_ERR_PARSE;
                goto fail;
            }
            config->keys[config->key_count++] = candidate;
            continue;
        }
        if (rc == APROXY_ERR_NO_MEMORY) {
            goto fail;
        }
        if (keys_started || padding_fields >= VLESS_ENCRYPTION_MAX_PADDING_FIELDS) {
            rc = APROXY_ERR_PARSE;
            goto fail;
        }
        padding_parameter_t parameter;
        rc = parse_padding_parameter(fields[i], padding_fields, &parameter);
        if (rc != APROXY_OK) {
            goto fail;
        }
        if ((padding_fields & 1u) == 0u) {
            config->padding_lengths[config->padding_length_count++] =
                parameter;
            maximum_padding += parameter.from > parameter.to
                                   ? parameter.from
                                   : parameter.to;
            if (maximum_padding > 65553u) {
                rc = APROXY_ERR_PARSE;
                goto fail;
            }
        } else {
            config->padding_gaps[config->padding_gap_count++] = parameter;
            maximum_gap += parameter.from > parameter.to ? parameter.from
                                                          : parameter.to;
            if (maximum_gap > 10000u) {
                rc = APROXY_ERR_PARSE;
                goto fail;
            }
        }
        padding_fields++;
    }
    if (config->key_count == 0u) {
        rc = APROXY_ERR_PARSE;
        goto fail;
    }
    for (size_t i = 0u; i < config->key_count; i++) {
        const size_t exchange_len =
            config->keys[i].type == ENCRYPTION_KEY_X25519
                ? X25519_PUBLIC_VALUE_LEN
                : MLKEM768_CIPHERTEXT_BYTES;
        config->relays_len += exchange_len;
        if (i + 1u < config->key_count) {
            config->relays_len += 32u;
        }
    }
    if (uv_mutex_init(&config->ticket_lock) != 0) {
        rc = APROXY_ERR_NO_MEMORY;
        goto fail;
    }
    config->ticket_lock_initialized = 1;
    free(copy);
    *out = config;
    return APROXY_OK;

fail:
    free(copy);
    config_clear(config);
    free(config);
    return rc;
}

void vless_encryption_client_config_free(
    vless_encryption_client_config_t *config)
{
    if (config == NULL) {
        return;
    }
    config_clear(config);
    free(config);
}

vless_encryption_mode_t vless_encryption_client_config_mode(
    const vless_encryption_client_config_t *config)
{
    return config == NULL ? VLESS_ENCRYPTION_MODE_NATIVE : config->mode;
}

vless_encryption_rtt_t vless_encryption_client_config_rtt(
    const vless_encryption_client_config_t *config)
{
    return config == NULL ? VLESS_ENCRYPTION_1RTT : config->rtt;
}

size_t vless_encryption_client_config_key_count(
    const vless_encryption_client_config_t *config)
{
    return config == NULL ? 0u : config->key_count;
}

static void aead_cleanup(encryption_aead_t *aead)
{
    if (aead->initialized) {
        EVP_AEAD_CTX_cleanup(&aead->ctx);
    }
    OPENSSL_cleanse(aead, sizeof(*aead));
}

static int aead_init(encryption_aead_t *aead,
                     const uint8_t *context,
                     size_t context_len,
                     const uint8_t *material,
                     size_t material_len,
                     int use_aes)
{
    uint8_t key[32];
    derive_key(key, context, context_len, material, material_len);
    aead_cleanup(aead);
    const EVP_AEAD *algorithm = use_aes ? EVP_aead_aes_256_gcm()
                                        : EVP_aead_chacha20_poly1305();
    if (!EVP_AEAD_CTX_init(&aead->ctx, algorithm, key, sizeof(key),
                           VLESS_ENCRYPTION_TAG_LEN, NULL)) {
        OPENSSL_cleanse(key, sizeof(key));
        return APROXY_ERR_CRYPTO;
    }
    OPENSSL_cleanse(key, sizeof(key));
    aead->initialized = 1;
    return APROXY_OK;
}

static void nonce_increase(uint8_t nonce[12])
{
    for (size_t i = 12u; i > 0u; i--) {
        nonce[i - 1u]++;
        if (nonce[i - 1u] != 0u) {
            break;
        }
    }
}

static int nonce_is_max(const uint8_t nonce[12])
{
    uint8_t combined = 0xffu;
    for (size_t i = 0u; i < 12u; i++) {
        combined &= nonce[i];
    }
    return combined == 0xffu;
}

static int aead_seal_to(encryption_aead_t *aead,
                        uint8_t *output,
                        size_t output_capacity,
                        size_t *output_len,
                        const uint8_t *plaintext,
                        size_t plaintext_len,
                        const uint8_t *additional_data,
                        size_t additional_data_len,
                        const uint8_t *explicit_nonce)
{
    if (!aead->initialized) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const uint8_t *nonce = explicit_nonce;
    if (nonce == NULL) {
        nonce_increase(aead->nonce);
        nonce = aead->nonce;
    }
    return EVP_AEAD_CTX_seal(&aead->ctx, output, output_len,
                             output_capacity, nonce, 12u, plaintext,
                             plaintext_len, additional_data,
                             additional_data_len)
               ? APROXY_OK
               : APROXY_ERR_CRYPTO;
}

static int aead_open_to(encryption_aead_t *aead,
                        uint8_t *output,
                        size_t output_capacity,
                        size_t *output_len,
                        const uint8_t *ciphertext,
                        size_t ciphertext_len,
                        const uint8_t *additional_data,
                        size_t additional_data_len,
                        const uint8_t *explicit_nonce)
{
    if (!aead->initialized) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const uint8_t *nonce = explicit_nonce;
    if (nonce == NULL) {
        nonce_increase(aead->nonce);
        nonce = aead->nonce;
    }
    return EVP_AEAD_CTX_open(&aead->ctx, output, output_len,
                             output_capacity, nonce, 12u, ciphertext,
                             ciphertext_len, additional_data,
                             additional_data_len)
               ? APROXY_OK
               : APROXY_ERR_CRYPTO;
}

static int ctr_new(const uint8_t *material,
                   size_t material_len,
                   const uint8_t iv[16],
                   EVP_CIPHER_CTX **out)
{
    static const uint8_t context[] = {'V', 'L', 'E', 'S', 'S'};
    uint8_t key[32];
    derive_key(key, context, sizeof(context), material, material_len);
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        OPENSSL_cleanse(key, sizeof(key));
        return APROXY_ERR_CRYPTO;
    }
    OPENSSL_cleanse(key, sizeof(key));
    *out = ctx;
    return APROXY_OK;
}

static int ctr_xor(EVP_CIPHER_CTX *ctx, uint8_t *data, size_t len)
{
    while (len > 0u) {
        const int chunk = len > (size_t)INT_MAX ? INT_MAX : (int)len;
        int written = 0;
        if (EVP_EncryptUpdate(ctx, data, &written, data, chunk) != 1 ||
            written != chunk) {
            return APROXY_ERR_CRYPTO;
        }
        data += (size_t)chunk;
        len -= (size_t)chunk;
    }
    return APROXY_OK;
}

static void encode_length(uint8_t output[2], size_t length)
{
    output[0] = (uint8_t)(length >> 8u);
    output[1] = (uint8_t)length;
}

static size_t decode_length(const uint8_t input[2])
{
    return ((size_t)input[0] << 8u) | input[1];
}

static void encode_record_header(uint8_t output[5], size_t length)
{
    output[0] = 23u;
    output[1] = 3u;
    output[2] = 3u;
    output[3] = (uint8_t)(length >> 8u);
    output[4] = (uint8_t)length;
}

static int decode_record_header(const uint8_t input[5], size_t *length)
{
    const size_t decoded = ((size_t)input[3] << 8u) | input[4];
    if (input[0] != 23u || input[1] != 3u || input[2] != 3u ||
        decoded < 17u || decoded > VLESS_ENCRYPTION_MAX_CIPHERTEXT) {
        return APROXY_ERR_INVALID_FRAME;
    }
    *length = decoded;
    return APROXY_OK;
}

static int choose_padding(vless_encryption_client_config_t *config,
                          size_t *total)
{
    *total = 0u;
    if (config->padding_length_count == 0u) {
        uint32_t first = 0u;
        uint32_t second = 0u;
        int rc = random_between(111u, 1111u, &first);
        if (rc == APROXY_OK) {
            uint32_t selected = 0u;
            rc = random_between(0u, 100u, &selected);
            if (rc == APROXY_OK && selected <= 50u) {
                rc = random_between(0u, 3333u, &second);
            }
        }
        if (rc != APROXY_OK) {
            return rc;
        }
        *total = (size_t)first + second;
        return APROXY_OK;
    }
    for (size_t i = 0u; i < config->padding_length_count; i++) {
        uint32_t selected = 0u;
        int rc = random_between(0u, 100u, &selected);
        if (rc != APROXY_OK) {
            return rc;
        }
        if (config->padding_lengths[i].chance >= selected) {
            uint32_t length = 0u;
            rc = random_between(config->padding_lengths[i].from,
                                config->padding_lengths[i].to, &length);
            if (rc != APROXY_OK) {
                return rc;
            }
            *total += length;
        }
    }
    return *total >= 35u && *total <= 65553u ? APROXY_OK
                                              : APROXY_ERR_PARSE;
}

static int config_load_ticket(vless_encryption_client_config_t *config,
                              uint8_t pfs_key[64],
                              uint8_t ticket[16])
{
    int available = 0;
    uv_mutex_lock(&config->ticket_lock);
    if (config->ticket_valid && time(NULL) < config->ticket_expires_at) {
        memcpy(pfs_key, config->pfs_key, 64u);
        memcpy(ticket, config->ticket, 16u);
        available = 1;
    } else {
        config->ticket_valid = 0;
    }
    uv_mutex_unlock(&config->ticket_lock);
    return available;
}

static void config_store_ticket(vless_encryption_client_config_t *config,
                                const uint8_t pfs_key[64],
                                const uint8_t ticket[16],
                                size_t seconds)
{
    if (config->rtt != VLESS_ENCRYPTION_0RTT || seconds == 0u) {
        return;
    }
    uv_mutex_lock(&config->ticket_lock);
    memcpy(config->pfs_key, pfs_key, 64u);
    memcpy(config->ticket, ticket, 16u);
    config->ticket_expires_at = time(NULL) + (time_t)seconds;
    config->ticket_valid = 1;
    uv_mutex_unlock(&config->ticket_lock);
}

static void config_invalidate_ticket(vless_encryption_client_config_t *config)
{
    uv_mutex_lock(&config->ticket_lock);
    config->ticket_valid = 0;
    uv_mutex_unlock(&config->ticket_lock);
}

static int build_relays(vless_encryption_client_t *client,
                        uint8_t *output,
                        size_t output_len)
{
    vless_encryption_client_config_t *config = client->config;
    if (output_len != config->relays_len) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uint8_t *position = output;
    EVP_CIPHER_CTX *previous = NULL;
    int rc = APROXY_OK;
    for (size_t i = 0u; i < config->key_count; i++) {
        encryption_key_t *key = &config->keys[i];
        size_t exchange_len = X25519_PUBLIC_VALUE_LEN;
        if (key->type == ENCRYPTION_KEY_X25519) {
            uint8_t private_key[X25519_PRIVATE_KEY_LEN];
            X25519_keypair(position, private_key);
            if (!X25519(client->nfs_key, private_key, key->encoded)) {
                OPENSSL_cleanse(private_key, sizeof(private_key));
                rc = APROXY_ERR_CRYPTO;
                goto out;
            }
            OPENSSL_cleanse(private_key, sizeof(private_key));
        } else {
            exchange_len = MLKEM768_CIPHERTEXT_BYTES;
            MLKEM768_encap(position, client->nfs_key, &key->mlkem);
        }
        if (config->mode != VLESS_ENCRYPTION_MODE_NATIVE) {
            EVP_CIPHER_CTX *mask = NULL;
            rc = ctr_new(key->encoded, key->encoded_len, client->iv, &mask);
            if (rc != APROXY_OK) {
                goto out;
            }
            rc = ctr_xor(mask, position, exchange_len);
            EVP_CIPHER_CTX_free(mask);
            if (rc != APROXY_OK) {
                goto out;
            }
        }
        if (previous != NULL) {
            rc = ctr_xor(previous, position, 32u);
            EVP_CIPHER_CTX_free(previous);
            previous = NULL;
            if (rc != APROXY_OK) {
                goto out;
            }
        }
        if (i + 1u == config->key_count) {
            position += exchange_len;
            break;
        }
        rc = ctr_new(client->nfs_key, sizeof(client->nfs_key), client->iv,
                     &previous);
        if (rc != APROXY_OK) {
            goto out;
        }
        uint8_t next_hash[32];
        hash_key(next_hash, config->keys[i + 1u].encoded,
                 config->keys[i + 1u].encoded_len);
        memcpy(position + exchange_len, next_hash, sizeof(next_hash));
        OPENSSL_cleanse(next_hash, sizeof(next_hash));
        rc = ctr_xor(previous, position + exchange_len, 32u);
        if (rc != APROXY_OK) {
            goto out;
        }
        position += exchange_len + 32u;
    }
    if ((size_t)(position - output) != output_len) {
        rc = APROXY_ERR_INVALID_FRAME;
    }

out:
    EVP_CIPHER_CTX_free(previous);
    return rc;
}

static int prepare_random_ctrs(vless_encryption_client_t *client,
                               const uint8_t receive_iv[16])
{
    if (client->config->mode != VLESS_ENCRYPTION_MODE_RANDOM) {
        return APROXY_OK;
    }
    EVP_CIPHER_CTX_free(client->send_ctr);
    EVP_CIPHER_CTX_free(client->receive_ctr);
    client->send_ctr = NULL;
    client->receive_ctr = NULL;
    int rc = ctr_new(client->united_key, sizeof(client->united_key),
                     client->iv, &client->send_ctr);
    if (rc == APROXY_OK) {
        rc = ctr_new(client->united_key, sizeof(client->united_key),
                     receive_iv, &client->receive_ctr);
    }
    return rc;
}

int vless_encryption_client_new(
    vless_encryption_client_config_t *config,
    vless_encryption_client_t **out)
{
    if (config == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    vless_encryption_client_t *client =
        (vless_encryption_client_t *)calloc(1u, sizeof(*client));
    if (client == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    client->config = config;
    aproxy_ring_init(&client->input);
    aproxy_buffer_init(&client->prewrite);
    aproxy_buffer_init(&client->record_scratch);
    client->phase = ENCRYPTION_PHASE_NEW;
    client->use_aes = EVP_has_aes_hardware();
    *out = client;
    return APROXY_OK;
}

void vless_encryption_client_free(vless_encryption_client_t *client)
{
    if (client == NULL) {
        return;
    }
    aproxy_ring_free(&client->input);
    aproxy_buffer_free(&client->prewrite);
    aproxy_buffer_free(&client->record_scratch);
    aead_cleanup(&client->nfs_aead);
    aead_cleanup(&client->send_aead);
    aead_cleanup(&client->receive_aead);
    EVP_CIPHER_CTX_free(client->send_ctr);
    EVP_CIPHER_CTX_free(client->receive_ctr);
    OPENSSL_cleanse(client, sizeof(*client));
    free(client);
}

static int start_full_handshake(vless_encryption_client_t *client,
                                aproxy_buffer_t *wire_out,
                                size_t prefix_len)
{
    size_t padding_len = 0u;
    int rc = choose_padding(client->config, &padding_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    const size_t pfs_ciphertext_len =
        18u + VLESS_ENCRYPTION_PFS_PUBLIC_LEN + VLESS_ENCRYPTION_TAG_LEN;
    const size_t start = wire_out->len;
    if (prefix_len > SIZE_MAX - pfs_ciphertext_len - padding_len ||
        start > SIZE_MAX - prefix_len - pfs_ciphertext_len - padding_len) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    rc = aproxy_buffer_reserve(
        wire_out, start + prefix_len + pfs_ciphertext_len + padding_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *hello = wire_out->data + start;
    memcpy(hello, client->iv, sizeof(client->iv));
    rc = build_relays(client, hello + sizeof(client->iv),
                      client->config->relays_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = aead_init(&client->nfs_aead, client->iv, sizeof(client->iv),
                   client->nfs_key, sizeof(client->nfs_key), client->use_aes);
    if (rc != APROXY_OK) {
        return rc;
    }

    uint8_t *position = hello + prefix_len;
    uint8_t encoded_length[2];
    encode_length(encoded_length,
                  VLESS_ENCRYPTION_PFS_PUBLIC_LEN +
                      VLESS_ENCRYPTION_TAG_LEN);
    size_t sealed_len = 0u;
    rc = aead_seal_to(&client->nfs_aead, position, 18u, &sealed_len,
                      encoded_length, sizeof(encoded_length), NULL, 0u, NULL);
    if (rc != APROXY_OK || sealed_len != 18u) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    position += sealed_len;

    MLKEM768_generate_key(client->pfs_public, NULL,
                          &client->pfs_mlkem_private);
    X25519_keypair(client->pfs_public + MLKEM768_PUBLIC_KEY_BYTES,
                   client->pfs_x25519_private);
    rc = aead_seal_to(
        &client->nfs_aead, position,
        VLESS_ENCRYPTION_PFS_PUBLIC_LEN + VLESS_ENCRYPTION_TAG_LEN,
        &sealed_len, client->pfs_public,
        VLESS_ENCRYPTION_PFS_PUBLIC_LEN, NULL, 0u, NULL);
    if (rc != APROXY_OK ||
        sealed_len !=
            VLESS_ENCRYPTION_PFS_PUBLIC_LEN + VLESS_ENCRYPTION_TAG_LEN) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    position += sealed_len;

    encode_length(encoded_length, padding_len - 18u);
    rc = aead_seal_to(&client->nfs_aead, position, 18u, &sealed_len,
                      encoded_length, sizeof(encoded_length), NULL, 0u, NULL);
    if (rc != APROXY_OK || sealed_len != 18u) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    position += sealed_len;
    const size_t padding_plaintext_len = padding_len - 34u;
    memset(position, 0, padding_plaintext_len);
    rc = aead_seal_to(&client->nfs_aead, position,
                      padding_plaintext_len + VLESS_ENCRYPTION_TAG_LEN,
                      &sealed_len, position, padding_plaintext_len, NULL, 0u,
                      NULL);
    if (rc != APROXY_OK ||
        sealed_len != padding_plaintext_len + VLESS_ENCRYPTION_TAG_LEN) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    position += sealed_len;
    wire_out->len = (size_t)(position - wire_out->data);
    client->phase = ENCRYPTION_PHASE_WAIT_SERVER_PFS;
    return APROXY_OK;
}

static int start_resumed_handshake(vless_encryption_client_t *client,
                                   size_t prefix_len)
{
    aproxy_buffer_clear(&client->prewrite);
    int rc = aproxy_buffer_reserve(&client->prewrite, prefix_len + 50u);
    if (rc != APROXY_OK) {
        return rc;
    }
    memcpy(client->prewrite.data, client->iv, sizeof(client->iv));
    rc = build_relays(client,
                      client->prewrite.data + sizeof(client->iv),
                      client->config->relays_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = aead_init(&client->nfs_aead, client->iv, sizeof(client->iv),
                   client->nfs_key, sizeof(client->nfs_key), client->use_aes);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *position = client->prewrite.data + prefix_len;
    uint8_t encoded_length[2];
    encode_length(encoded_length, 32u);
    size_t sealed_len = 0u;
    rc = aead_seal_to(&client->nfs_aead, position, 18u, &sealed_len,
                      encoded_length, sizeof(encoded_length), NULL, 0u, NULL);
    if (rc != APROXY_OK || sealed_len != 18u) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    position += sealed_len;
    rc = aead_seal_to(&client->nfs_aead, position, 32u, &sealed_len,
                      client->ticket, sizeof(client->ticket), NULL, 0u, NULL);
    if (rc != APROXY_OK || sealed_len != 32u) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    const uint8_t *encrypted_ticket = position;
    position += sealed_len;
    client->prewrite.len = (size_t)(position - client->prewrite.data);

    memcpy(client->united_key + 64u, client->nfs_key,
           sizeof(client->nfs_key));
    rc = aead_init(&client->send_aead, encrypted_ticket, 32u,
                   client->united_key, sizeof(client->united_key),
                   client->use_aes);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (client->config->mode == VLESS_ENCRYPTION_MODE_RANDOM) {
        rc = ctr_new(client->united_key, sizeof(client->united_key),
                     client->iv, &client->send_ctr);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    client->resumed = 1;
    client->send_ready = 1;
    client->phase = ENCRYPTION_PHASE_WAIT_SERVER_RANDOM;
    return APROXY_OK;
}

int vless_encryption_client_start(vless_encryption_client_t *client,
                                  aproxy_buffer_t *wire_out)
{
    if (client == NULL || wire_out == NULL ||
        client->phase != ENCRYPTION_PHASE_NEW) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (RAND_bytes(client->iv, sizeof(client->iv)) != 1) {
        return APROXY_ERR_CRYPTO;
    }
    const size_t prefix_len = sizeof(client->iv) + client->config->relays_len;
    if (client->config->rtt == VLESS_ENCRYPTION_0RTT &&
        config_load_ticket(client->config, client->united_key,
                           client->ticket)) {
        return start_resumed_handshake(client, prefix_len);
    }
    return start_full_handshake(client, wire_out, prefix_len);
}

int vless_encryption_client_send_ready(
    const vless_encryption_client_t *client)
{
    return client != NULL && client->send_ready;
}

int vless_encryption_client_receive_ready(
    const vless_encryption_client_t *client)
{
    return client != NULL && client->receive_ready;
}

static int process_server_pfs(vless_encryption_client_t *client)
{
    const size_t encrypted_len = VLESS_ENCRYPTION_SERVER_PFS_LEN +
                                 VLESS_ENCRYPTION_TAG_LEN;
    if (aproxy_ring_size(&client->input) < encrypted_len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    int rc = aproxy_buffer_reserve(&client->record_scratch, encrypted_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    client->record_scratch.len = encrypted_len;
    if (aproxy_ring_read(&client->input, client->record_scratch.data,
                         encrypted_len) != encrypted_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    static const uint8_t max_nonce[12] = {
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
        0xffu, 0xffu, 0xffu, 0xffu, 0xffu, 0xffu,
    };
    size_t plaintext_len = 0u;
    rc = aead_open_to(&client->nfs_aead, client->record_scratch.data,
                      encrypted_len, &plaintext_len,
                      client->record_scratch.data, encrypted_len, NULL, 0u,
                      max_nonce);
    if (rc != APROXY_OK || plaintext_len != VLESS_ENCRYPTION_SERVER_PFS_LEN) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    uint8_t mlkem_secret[MLKEM_SHARED_SECRET_BYTES];
    if (!MLKEM768_decap(mlkem_secret, client->record_scratch.data,
                        MLKEM768_CIPHERTEXT_BYTES,
                        &client->pfs_mlkem_private)) {
        return APROXY_ERR_CRYPTO;
    }
    uint8_t x25519_secret[X25519_SHARED_KEY_LEN];
    if (!X25519(x25519_secret, client->pfs_x25519_private,
                client->record_scratch.data + MLKEM768_CIPHERTEXT_BYTES)) {
        OPENSSL_cleanse(mlkem_secret, sizeof(mlkem_secret));
        return APROXY_ERR_CRYPTO;
    }
    memcpy(client->united_key, mlkem_secret, sizeof(mlkem_secret));
    memcpy(client->united_key + sizeof(mlkem_secret), x25519_secret,
           sizeof(x25519_secret));
    memcpy(client->united_key + 64u, client->nfs_key,
           sizeof(client->nfs_key));
    OPENSSL_cleanse(mlkem_secret, sizeof(mlkem_secret));
    OPENSSL_cleanse(x25519_secret, sizeof(x25519_secret));
    OPENSSL_cleanse(&client->pfs_mlkem_private,
                    sizeof(client->pfs_mlkem_private));
    OPENSSL_cleanse(client->pfs_x25519_private,
                    sizeof(client->pfs_x25519_private));

    rc = aead_init(&client->send_aead, client->pfs_public,
                   sizeof(client->pfs_public), client->united_key,
                   sizeof(client->united_key), client->use_aes);
    if (rc == APROXY_OK) {
        rc = aead_init(&client->receive_aead,
                       client->record_scratch.data,
                       VLESS_ENCRYPTION_SERVER_PFS_LEN, client->united_key,
                       sizeof(client->united_key), client->use_aes);
    }
    if (rc == APROXY_OK) {
        client->phase = ENCRYPTION_PHASE_WAIT_TICKET;
    }
    return rc;
}

static int process_ticket(vless_encryption_client_t *client)
{
    if (aproxy_ring_size(&client->input) < 32u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    uint8_t encrypted[32];
    if (aproxy_ring_read(&client->input, encrypted, sizeof(encrypted)) !=
        sizeof(encrypted)) {
        return APROXY_ERR_INVALID_FRAME;
    }
    size_t plaintext_len = 0u;
    int rc = aead_open_to(&client->receive_aead, client->ticket,
                          sizeof(client->ticket), &plaintext_len, encrypted,
                          sizeof(encrypted), NULL, 0u, NULL);
    if (rc != APROXY_OK || plaintext_len != sizeof(client->ticket)) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    config_store_ticket(client->config, client->united_key, client->ticket,
                        decode_length(client->ticket));
    client->phase = ENCRYPTION_PHASE_WAIT_PADDING_LENGTH;
    return APROXY_OK;
}

static int process_padding_length(vless_encryption_client_t *client)
{
    if (aproxy_ring_size(&client->input) < 18u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    uint8_t encrypted[18];
    uint8_t plaintext[2];
    if (aproxy_ring_read(&client->input, encrypted, sizeof(encrypted)) !=
        sizeof(encrypted)) {
        return APROXY_ERR_INVALID_FRAME;
    }
    size_t plaintext_len = 0u;
    int rc = aead_open_to(&client->receive_aead, plaintext,
                          sizeof(plaintext), &plaintext_len, encrypted,
                          sizeof(encrypted), NULL, 0u, NULL);
    if (rc != APROXY_OK || plaintext_len != sizeof(plaintext)) {
        return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
    }
    client->peer_padding_len = decode_length(plaintext);
    if (client->peer_padding_len < VLESS_ENCRYPTION_TAG_LEN) {
        return APROXY_ERR_INVALID_FRAME;
    }
    client->phase = ENCRYPTION_PHASE_WAIT_PADDING;
    return APROXY_OK;
}

static int finish_full_handshake(vless_encryption_client_t *client)
{
    if (aproxy_ring_size(&client->input) < client->peer_padding_len) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    int rc = aproxy_buffer_reserve(&client->record_scratch,
                                   client->peer_padding_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    client->record_scratch.len = client->peer_padding_len;
    if (aproxy_ring_read(&client->input, client->record_scratch.data,
                         client->peer_padding_len) !=
        client->peer_padding_len) {
        return APROXY_ERR_INVALID_FRAME;
    }
    size_t plaintext_len = 0u;
    rc = aead_open_to(&client->receive_aead, client->record_scratch.data,
                      client->record_scratch.cap, &plaintext_len,
                      client->record_scratch.data, client->peer_padding_len,
                      NULL, 0u, NULL);
    if (rc != APROXY_OK) {
        return rc;
    }
    rc = prepare_random_ctrs(client, client->ticket);
    if (rc != APROXY_OK) {
        return rc;
    }
    client->peer_padding_len = 0u;
    client->send_ready = 1;
    client->receive_ready = 1;
    client->phase = ENCRYPTION_PHASE_RECORDS;
    return APROXY_OK;
}

static int finish_resumed_handshake(vless_encryption_client_t *client)
{
    if (aproxy_ring_size(&client->input) < 16u) {
        return APROXY_ERR_BUFFER_TOO_SMALL;
    }
    uint8_t server_random[16];
    if (aproxy_ring_read(&client->input, server_random,
                         sizeof(server_random)) != sizeof(server_random)) {
        return APROXY_ERR_INVALID_FRAME;
    }
    int rc = aead_init(&client->receive_aead, server_random,
                       sizeof(server_random), client->united_key,
                       sizeof(client->united_key), client->use_aes);
    if (rc == APROXY_OK &&
        client->config->mode == VLESS_ENCRYPTION_MODE_RANDOM) {
        rc = ctr_new(client->united_key, sizeof(client->united_key),
                     server_random, &client->receive_ctr);
    }
    if (rc != APROXY_OK) {
        return rc;
    }
    client->receive_ready = 1;
    client->phase = ENCRYPTION_PHASE_RECORDS;
    return APROXY_OK;
}

static int process_records(vless_encryption_client_t *client,
                           aproxy_buffer_t *plaintext_out,
                           int one_record)
{
    for (;;) {
        if (!client->record_header_ready) {
            if (aproxy_ring_size(&client->input) <
                VLESS_ENCRYPTION_HEADER_LEN) {
                return APROXY_OK;
            }
            if (aproxy_ring_read(&client->input, client->record_header,
                                 sizeof(client->record_header)) !=
                sizeof(client->record_header)) {
                return APROXY_ERR_INVALID_FRAME;
            }
            if (client->config->mode == VLESS_ENCRYPTION_MODE_RANDOM &&
                ctr_xor(client->receive_ctr, client->record_header,
                        sizeof(client->record_header)) != APROXY_OK) {
                return APROXY_ERR_CRYPTO;
            }
            int rc = decode_record_header(client->record_header,
                                          &client->record_ciphertext_len);
            if (rc != APROXY_OK) {
                if (client->resumed) {
                    config_invalidate_ticket(client->config);
                }
                return rc;
            }
            client->record_header_ready = 1;
        }
        if (aproxy_ring_size(&client->input) <
            client->record_ciphertext_len) {
            return APROXY_OK;
        }
        int rc = aproxy_buffer_reserve(&client->record_scratch,
                                       client->record_ciphertext_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        client->record_scratch.len = client->record_ciphertext_len;
        if (aproxy_ring_read(&client->input, client->record_scratch.data,
                             client->record_ciphertext_len) !=
            client->record_ciphertext_len) {
            return APROXY_ERR_INVALID_FRAME;
        }
        aproxy_buffer_t rekey_context;
        aproxy_buffer_init(&rekey_context);
        const int rekey = nonce_is_max(client->receive_aead.nonce);
        if (rekey) {
            rc = aproxy_buffer_append(&rekey_context, client->record_header,
                                      sizeof(client->record_header));
            if (rc == APROXY_OK) {
                rc = aproxy_buffer_append(&rekey_context,
                                          client->record_scratch.data,
                                          client->record_scratch.len);
            }
            if (rc != APROXY_OK) {
                aproxy_buffer_free(&rekey_context);
                return rc;
            }
        }
        const size_t plaintext_len =
            client->record_ciphertext_len - VLESS_ENCRYPTION_TAG_LEN;
        const size_t output_start = plaintext_out->len;
        rc = aproxy_buffer_reserve(plaintext_out,
                                   output_start + plaintext_len);
        if (rc != APROXY_OK) {
            aproxy_buffer_free(&rekey_context);
            return rc;
        }
        size_t opened_len = 0u;
        rc = aead_open_to(
            &client->receive_aead, plaintext_out->data + output_start,
            plaintext_len, &opened_len, client->record_scratch.data,
            client->record_scratch.len, client->record_header,
            sizeof(client->record_header), NULL);
        if (rc != APROXY_OK || opened_len != plaintext_len) {
            aproxy_buffer_free(&rekey_context);
            return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
        }
        plaintext_out->len += opened_len;
        if (rekey) {
            rc = aead_init(&client->receive_aead, rekey_context.data,
                           rekey_context.len, client->united_key,
                           sizeof(client->united_key), client->use_aes);
            if (rc != APROXY_OK) {
                aproxy_buffer_free(&rekey_context);
                return rc;
            }
        }
        aproxy_buffer_free(&rekey_context);
        client->record_header_ready = 0;
        client->record_ciphertext_len = 0u;
        if (one_record) {
            return APROXY_OK;
        }
    }
}

static int feed_internal(vless_encryption_client_t *client,
                         const uint8_t *wire,
                         size_t wire_len,
                         aproxy_buffer_t *plaintext_out,
                         int *became_ready,
                         int one_record)
{
    if (client == NULL || plaintext_out == NULL ||
        (wire == NULL && wire_len > 0u) ||
        client->phase == ENCRYPTION_PHASE_NEW ||
        client->phase == ENCRYPTION_PHASE_FAILED) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (became_ready != NULL) {
        *became_ready = 0;
    }
    if (wire_len > VLESS_ENCRYPTION_INPUT_LIMIT -
                       aproxy_ring_size(&client->input)) {
        client->phase = ENCRYPTION_PHASE_FAILED;
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    int rc = aproxy_ring_write(&client->input, wire, wire_len);
    if (rc != APROXY_OK) {
        client->phase = ENCRYPTION_PHASE_FAILED;
        return rc;
    }
    const int was_send_ready = client->send_ready;
    for (;;) {
        switch (client->phase) {
        case ENCRYPTION_PHASE_WAIT_SERVER_PFS:
            rc = process_server_pfs(client);
            break;
        case ENCRYPTION_PHASE_WAIT_TICKET:
            rc = process_ticket(client);
            break;
        case ENCRYPTION_PHASE_WAIT_PADDING_LENGTH:
            rc = process_padding_length(client);
            break;
        case ENCRYPTION_PHASE_WAIT_PADDING:
            rc = finish_full_handshake(client);
            break;
        case ENCRYPTION_PHASE_WAIT_SERVER_RANDOM:
            rc = finish_resumed_handshake(client);
            break;
        case ENCRYPTION_PHASE_RECORDS:
            rc = process_records(client, plaintext_out, one_record);
            if (became_ready != NULL && !was_send_ready &&
                client->send_ready) {
                *became_ready = 1;
            }
            return rc;
        default:
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        if (rc == APROXY_ERR_BUFFER_TOO_SMALL) {
            return APROXY_OK;
        }
        if (rc != APROXY_OK) {
            client->phase = ENCRYPTION_PHASE_FAILED;
            return rc;
        }
        if (became_ready != NULL && !was_send_ready && client->send_ready) {
            *became_ready = 1;
        }
    }
}

int vless_encryption_client_feed(vless_encryption_client_t *client,
                                 const uint8_t *wire,
                                 size_t wire_len,
                                 aproxy_buffer_t *plaintext_out,
                                 int *became_ready)
{
    return feed_internal(client, wire, wire_len, plaintext_out,
                         became_ready, 0);
}

int vless_encryption_client_feed_once(vless_encryption_client_t *client,
                                      const uint8_t *wire,
                                      size_t wire_len,
                                      aproxy_buffer_t *plaintext_out,
                                      int *became_ready)
{
    return feed_internal(client, wire, wire_len, plaintext_out,
                         became_ready, 1);
}

int vless_encryption_client_take_buffered(
    vless_encryption_client_t *client,
    aproxy_buffer_t *output)
{
    if (client == NULL || output == NULL || !client->receive_ready ||
        client->phase == ENCRYPTION_PHASE_FAILED) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    aproxy_const_span_t spans[2];
    const size_t count = aproxy_ring_read_spans(&client->input, spans);
    for (size_t i = 0u; i < count; i++) {
        const int rc = aproxy_buffer_append(output, spans[i].data,
                                            spans[i].len);
        if (rc != APROXY_OK) {
            return rc;
        }
    }
    aproxy_ring_clear(&client->input);
    client->record_header_ready = 0;
    client->record_ciphertext_len = 0u;
    return APROXY_OK;
}

static int append_prewrite(vless_encryption_client_t *client,
                           aproxy_buffer_t *wire_out)
{
    if (client->prewrite_sent || client->prewrite.len == 0u) {
        return APROXY_OK;
    }
    const int rc = aproxy_buffer_append(wire_out, client->prewrite.data,
                                        client->prewrite.len);
    if (rc == APROXY_OK) {
        client->prewrite_sent = 1;
        aproxy_buffer_clear(&client->prewrite);
    }
    return rc;
}

int vless_encryption_client_seal(vless_encryption_client_t *client,
                                 const uint8_t *plaintext,
                                 size_t plaintext_len,
                                 aproxy_buffer_t *wire_out)
{
    if (client == NULL || wire_out == NULL ||
        (plaintext == NULL && plaintext_len > 0u) || !client->send_ready ||
        client->phase == ENCRYPTION_PHASE_FAILED) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (plaintext_len == 0u) {
        return APROXY_OK;
    }
    int rc = append_prewrite(client, wire_out);
    if (rc != APROXY_OK) {
        return rc;
    }
    size_t offset = 0u;
    while (offset < plaintext_len) {
        size_t chunk_len = plaintext_len - offset;
        if (chunk_len > VLESS_ENCRYPTION_RECORD_PLAINTEXT_MAX) {
            chunk_len = VLESS_ENCRYPTION_RECORD_PLAINTEXT_MAX;
        }
        const size_t start = wire_out->len;
        const size_t ciphertext_len = chunk_len + VLESS_ENCRYPTION_TAG_LEN;
        if (start > SIZE_MAX - VLESS_ENCRYPTION_HEADER_LEN - ciphertext_len) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        rc = aproxy_buffer_reserve(
            wire_out, start + VLESS_ENCRYPTION_HEADER_LEN + ciphertext_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        uint8_t *header = wire_out->data + start;
        encode_record_header(header, ciphertext_len);
        const int rekey = nonce_is_max(client->send_aead.nonce);
        size_t sealed_len = 0u;
        rc = aead_seal_to(&client->send_aead,
                          header + VLESS_ENCRYPTION_HEADER_LEN,
                          ciphertext_len, &sealed_len, plaintext + offset,
                          chunk_len, header, VLESS_ENCRYPTION_HEADER_LEN, NULL);
        if (rc != APROXY_OK || sealed_len != ciphertext_len) {
            return rc == APROXY_OK ? APROXY_ERR_CRYPTO : rc;
        }
        if (rekey) {
            rc = aead_init(&client->send_aead, header,
                           VLESS_ENCRYPTION_HEADER_LEN + ciphertext_len,
                           client->united_key, sizeof(client->united_key),
                           client->use_aes);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
        if (client->config->mode == VLESS_ENCRYPTION_MODE_RANDOM) {
            rc = ctr_xor(client->send_ctr, header,
                         VLESS_ENCRYPTION_HEADER_LEN);
            if (rc != APROXY_OK) {
                return rc;
            }
        }
        wire_out->len += VLESS_ENCRYPTION_HEADER_LEN + ciphertext_len;
        offset += chunk_len;
    }
    return APROXY_OK;
}
