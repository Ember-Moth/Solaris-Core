#ifndef SOLARIS_SHADOWSOCKS_INTERNAL_H
#define SOLARIS_SHADOWSOCKS_INTERNAL_H

#include "contracts/module/module.h"
#include "transport/stream/filter.h"
#include <openssl/aead.h>

#define SOLARIS_SS_MAX_IDENTITIES 8u
typedef struct solaris_ss_key {
    uint8_t bytes[32];
    /* SIP023 wire order; bytes is always the final user's AEAD key. */
    uint8_t identities[SOLARIS_SS_MAX_IDENTITIES][32];
    size_t identity_count;
    size_t length;
    int modern, chacha;
} solaris_ss_key_t;
typedef struct solaris_ss_parameters {
    solaris_ss_key_t key;
    solaris_address_t destination;
    solaris_replay_store_t *replay;
    solaris_crypto_source_t source;
} solaris_ss_parameters_t;

solaris_status_t solaris_ss_key_parse(const char *method, const char *password, solaris_ss_key_t *key);
solaris_status_t solaris_ss_random(const solaris_crypto_source_t *source, uint8_t *out, size_t size);
uint64_t solaris_ss_time(const solaris_crypto_source_t *source);
int solaris_ss_time_valid(const solaris_crypto_source_t *source, uint64_t stamp);
solaris_status_t solaris_ss_aead(const solaris_ss_key_t *key, const uint8_t *salt, size_t size, EVP_AEAD_CTX *out);
solaris_status_t solaris_ss_identity_headers(const solaris_ss_key_t *key, const uint8_t *salt,
    const uint8_t *packet_header, uint8_t *out);
solaris_status_t solaris_ss_replay(const solaris_ss_parameters_t *parameters, const uint8_t *salt);
uint64_t solaris_ss_read64(const uint8_t *bytes);
void solaris_ss_write64(uint8_t *bytes, uint64_t value);
extern const solaris_stream_codec_ops_t solaris_ss_stream_codec;
solaris_status_t solaris_ss_udp_open(solaris_executor_t *owner, const solaris_dialer_options_t *options,
    const solaris_address_t *server, const solaris_ss_parameters_t *parameters,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out);

#endif
