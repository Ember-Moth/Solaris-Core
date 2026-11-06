#include "adapters/outbound/shadowsocks/packet.h"
#include "codec/address/socks.h"
#include <openssl/aes.h>
#include <openssl/crypto.h>
#include <string.h>

#define SS_UDP_MAX 65000u
#define SS_WINDOW 1024u
typedef struct ss_window {
    uint8_t session[8]; uint64_t highest, last_seen, bits[SS_WINDOW / 64u]; int used;
} ss_window_t;
struct solaris_ss_packet {
    solaris_ss_parameters_t parameters;
    solaris_budget_t *budget;
    uint64_t (*now_ns)(void *);
    void *clock_context;
    uint8_t session[8]; uint64_t packet_id;
    ss_window_t windows[2];
    int exhausted;
};
solaris_status_t solaris_ss_packet_create(solaris_budget_t *budget, const solaris_ss_parameters_t *parameters,
    uint64_t (*now_ns)(void *), void *context, solaris_ss_packet_t **out)
{
    if (out == NULL || parameters == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (now_ns == NULL || (!parameters->key.modern && !solaris_replay_is_persistent(parameters->replay))) return SOLARIS_EINVAL;
    solaris_ss_packet_t *codec = solaris_memory_allocate(budget, sizeof(*codec));
    if (codec == NULL) return SOLARIS_ENOMEM;
    memset(codec, 0, sizeof(*codec)); codec->parameters = *parameters; codec->budget = budget;
    codec->now_ns = now_ns; codec->clock_context = context; solaris_replay_retain(parameters->replay);
    solaris_status_t rc = parameters->key.modern ? solaris_ss_random(&parameters->source, codec->session, 8u) : SOLARIS_OK;
    if (rc != SOLARIS_OK) { solaris_ss_packet_destroy(codec); return rc; }
    *out = codec; return SOLARIS_OK;
}
void solaris_ss_packet_destroy(solaris_ss_packet_t *codec)
{
    if (codec == NULL) return;
    solaris_replay_release(codec->parameters.replay); OPENSSL_cleanse(codec, sizeof(*codec)); solaris_memory_free(codec);
}
static ss_window_t *window_for(solaris_ss_packet_t *udp, const uint8_t session[8], uint64_t packet)
{
    uint64_t now = udp->now_ns(udp->clock_context); ss_window_t *candidate = NULL;
    for (size_t i = 0u; i < 2u; ++i) {
        ss_window_t *window = &udp->windows[i];
        if (window->used && memcmp(window->session, session, 8u) == 0) {
            if (packet <= window->highest && (window->highest - packet >= SS_WINDOW ||
                (window->bits[(packet % SS_WINDOW) / 64u] & (UINT64_C(1) << (packet % 64u))) != 0u)) return NULL;
            return window;
        }
        if (!window->used || (now >= window->last_seen && now - window->last_seen >= UINT64_C(60000000000)))
            if (candidate == NULL || !window->used || window->last_seen < candidate->last_seen) candidate = window;
    }
    if (candidate != NULL) {
        memset(candidate, 0, sizeof(*candidate)); candidate->used = 1;
        memcpy(candidate->session, session, 8u); candidate->highest = packet;
    }
    return candidate;
}
static void window_commit(solaris_ss_packet_t *udp, ss_window_t *window, uint64_t packet)
{
    if (packet > window->highest) {
        if (packet - window->highest >= SS_WINDOW) memset(window->bits, 0, sizeof(window->bits));
        else for (uint64_t n = window->highest + 1u; n != packet; ++n)
            window->bits[(n % SS_WINDOW) / 64u] &= ~(UINT64_C(1) << (n % 64u));
        window->bits[(packet % SS_WINDOW) / 64u] &= ~(UINT64_C(1) << (packet % 64u));
        window->highest = packet;
    }
    window->bits[(packet % SS_WINDOW) / 64u] |= UINT64_C(1) << (packet % 64u);
    window->last_seen = udp->now_ns(udp->clock_context);
}
solaris_status_t solaris_ss_packet_decode(solaris_ss_packet_t *udp, const uint8_t *wire, size_t size,
    solaris_address_t *source, solaris_buffer_t **out)
{
    *out = NULL;
    const solaris_ss_key_t *key = &udp->parameters.key;
    size_t prefix = key->modern ? 16u : key->length;
    if (size < prefix + 16u + 7u) return SOLARIS_EIO;
    uint8_t header[16], nonce[12] = {0}; EVP_AEAD_CTX cipher; EVP_AEAD_CTX_zero(&cipher);
    solaris_status_t rc;
    if (key->modern) {
        AES_KEY aes; if (AES_set_decrypt_key(key->bytes, (unsigned int)(key->length * 8u), &aes) != 0) return SOLARIS_EIO;
        AES_decrypt(wire, header, &aes); OPENSSL_cleanse(&aes, sizeof(aes));
        memcpy(nonce, header + 4u, 12u); rc = solaris_ss_aead(key, header, 8u, &cipher);
    } else rc = solaris_ss_aead(key, wire, key->length, &cipher);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_buffer_allocate(udp->budget, size - prefix - 16u, out);
    if (rc != SOLARIS_OK) { EVP_AEAD_CTX_cleanup(&cipher); return rc; }
    uint8_t *plain = solaris_buffer_mutable_data(*out); size_t length = 0u;
    int ok = EVP_AEAD_CTX_open(&cipher, plain, &length, size - prefix - 16u, nonce, 12u, wire + prefix, size - prefix, NULL, 0u);
    EVP_AEAD_CTX_cleanup(&cipher); if (!ok) return SOLARIS_EACCESS;
    size_t offset = 0u;
    if (key->modern) {
        if (length < 19u || plain[0] != 1u ||
            !solaris_ss_time_valid(&udp->parameters.source, solaris_ss_read64(plain + 1u)) ||
            CRYPTO_memcmp(plain + 9u, udp->session, 8u) != 0 || CRYPTO_memcmp(header, udp->session, 8u) == 0) return SOLARIS_EACCESS;
        size_t padding = ((size_t)plain[17] << 8) | plain[18];
        if (padding > length - 19u) return SOLARIS_EIO;
        offset = 19u + padding;
    }
    size_t address_length;
    rc = solaris_socks_address_read(plain + offset, length - offset, source, &address_length);
    if (rc != SOLARIS_OK) return SOLARIS_EIO;
    offset += address_length;
    if (length - offset > SS_UDP_MAX) return SOLARIS_EMSGSIZE;
    if (key->modern) {
        uint64_t packet = solaris_ss_read64(header + 8u); ss_window_t *window = window_for(udp, header, packet);
        if (window == NULL) return SOLARIS_EACCESS;
        window_commit(udp, window, packet);
    } else if ((rc = solaris_ss_replay(&udp->parameters, wire)) != SOLARIS_OK) return rc;
    memmove(plain, plain + offset, length - offset);
    return solaris_buffer_set_length(*out, length - offset);
}
solaris_status_t solaris_ss_packet_encode(solaris_ss_packet_t *udp, const solaris_address_t *destination,
    const solaris_slice_t *data, solaris_buffer_t **out)
{
    *out = NULL;
    if (data->length > SS_UDP_MAX) return SOLARIS_EMSGSIZE;
    uint8_t address[260]; size_t address_size;
    solaris_status_t rc = solaris_socks_address_write(destination, address, sizeof(address), &address_size);
    if (rc != SOLARIS_OK) return rc;
    const solaris_ss_key_t *key = &udp->parameters.key;
    size_t prefix = key->modern ? 16u : key->length;
    size_t header_size = key->modern ? 11u : 0u, size = prefix + header_size + address_size + data->length + 16u;
    rc = solaris_buffer_allocate(udp->budget, size, out);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *bytes = solaris_buffer_mutable_data(*out), nonce[12] = {0};
    EVP_AEAD_CTX cipher; EVP_AEAD_CTX_zero(&cipher);
    if (key->modern) {
        if (udp->exhausted) return SOLARIS_EOVERFLOW;
        memcpy(bytes, udp->session, 8u); solaris_ss_write64(bytes + 8u, udp->packet_id);
        if (udp->packet_id == UINT64_MAX) udp->exhausted = 1; else udp->packet_id++;
        memcpy(nonce, bytes + 4u, 12u); rc = solaris_ss_aead(key, bytes, 8u, &cipher);
        bytes[prefix] = 0u; solaris_ss_write64(bytes + prefix + 1u, solaris_ss_time(&udp->parameters.source));
        bytes[prefix + 9u] = bytes[prefix + 10u] = 0u;
        AES_KEY aes;
        if (rc == SOLARIS_OK && AES_set_encrypt_key(key->bytes, (unsigned int)(key->length * 8u), &aes) == 0) {
            AES_encrypt(bytes, bytes, &aes); OPENSSL_cleanse(&aes, sizeof(aes));
        } else { EVP_AEAD_CTX_cleanup(&cipher); return SOLARIS_EIO; }
    } else {
        rc = solaris_ss_random(&udp->parameters.source, bytes, key->length);
        if (rc == SOLARIS_OK) rc = solaris_ss_replay(&udp->parameters, bytes);
        if (rc == SOLARIS_OK) rc = solaris_ss_aead(key, bytes, key->length, &cipher);
    }
    if (rc != SOLARIS_OK) { EVP_AEAD_CTX_cleanup(&cipher); return rc; }
    memcpy(bytes + prefix + header_size, address, address_size);
    memcpy(bytes + prefix + header_size + address_size, solaris_buffer_data(data->buffer) + data->offset, data->length);
    size_t written = 0u;
    int ok = EVP_AEAD_CTX_seal(&cipher, bytes + prefix, &written, size - prefix, nonce, 12u,
        bytes + prefix, size - prefix - 16u, NULL, 0u);
    EVP_AEAD_CTX_cleanup(&cipher);
    return ok && written == size - prefix ? solaris_buffer_set_length(*out, size) : SOLARIS_EIO;
}
