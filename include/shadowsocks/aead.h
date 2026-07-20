#ifndef SHADOWSOCKS_AEAD_H
#define SHADOWSOCKS_AEAD_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"
#include "aproxy/error.h"

#define SHADOWSOCKS_AEAD_MAX_KEY_LEN 32u
#define SHADOWSOCKS_AEAD_MAX_SALT_LEN 32u
#define SHADOWSOCKS_AEAD_TAG_LEN 16u
#define SHADOWSOCKS_2022_PACKET_NONCE_LEN 24u
#define SHADOWSOCKS_2022_REPLAY_BLOCKS 128u
#define SHADOWSOCKS_2022_MAX_PACKET_OVERHEAD \
    (SHADOWSOCKS_2022_PACKET_NONCE_LEN + 16u + SHADOWSOCKS_AEAD_TAG_LEN)
#define SHADOWSOCKS_AEAD_MAX_PACKET_OVERHEAD \
    (SHADOWSOCKS_AEAD_MAX_SALT_LEN + SHADOWSOCKS_AEAD_TAG_LEN)

typedef enum shadowsocks_aead_method {
    SHADOWSOCKS_AEAD_AES_128_GCM = 1,
    SHADOWSOCKS_AEAD_AES_192_GCM,
    SHADOWSOCKS_AEAD_AES_256_GCM,
    SHADOWSOCKS_AEAD_CHACHA20_IETF_POLY1305,
    SHADOWSOCKS_AEAD_XCHACHA20_IETF_POLY1305,
    SHADOWSOCKS_AEAD_2022_BLAKE3_AES_128_GCM,
    SHADOWSOCKS_AEAD_2022_BLAKE3_AES_256_GCM,
    SHADOWSOCKS_AEAD_2022_BLAKE3_CHACHA20_POLY1305
} shadowsocks_aead_method_t;

typedef struct shadowsocks_2022_psk_list {
    uint8_t *keys;
    size_t count;
    size_t key_len;
} shadowsocks_2022_psk_list_t;

typedef struct shadowsocks_2022_replay_window {
    uint64_t last;
    uint64_t blocks[SHADOWSOCKS_2022_REPLAY_BLOCKS];
} shadowsocks_2022_replay_window_t;

int shadowsocks_aead_method_from_name(const char *name,
                                      shadowsocks_aead_method_t *out);

size_t shadowsocks_aead_key_len(shadowsocks_aead_method_t method);

int shadowsocks_aead_method_is_2022(shadowsocks_aead_method_t method);

int shadowsocks_aead_key_from_password(shadowsocks_aead_method_t method,
                                       const char *password,
                                       uint8_t *out_key,
                                       size_t out_capacity,
                                       size_t *out_len);

int shadowsocks_2022_key_from_password(shadowsocks_aead_method_t method,
                                       const char *password,
                                       uint8_t *out_key,
                                       size_t out_capacity,
                                       size_t *out_len);

int shadowsocks_2022_psk_list_parse(shadowsocks_aead_method_t method,
                                    const char *password,
                                    shadowsocks_2022_psk_list_t *out);

void shadowsocks_2022_psk_list_free(shadowsocks_2022_psk_list_t *list);

const uint8_t *shadowsocks_2022_psk_at(
    const shadowsocks_2022_psk_list_t *list,
    size_t index);

int shadowsocks_2022_tcp_eih_write(
    shadowsocks_aead_method_t method,
    const shadowsocks_2022_psk_list_t *psks,
    const uint8_t *salt,
    size_t salt_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int shadowsocks_aead_udp_seal(shadowsocks_aead_method_t method,
                              const uint8_t *key,
                              size_t key_len,
                              const uint8_t *salt,
                              const aproxy_addr_t *destination,
                              const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out,
                              size_t out_capacity,
                              size_t *out_len);

int shadowsocks_aead_udp_open(shadowsocks_aead_method_t method,
                              const uint8_t *key,
                              size_t key_len,
                              const uint8_t *packet,
                              size_t packet_len,
                              aproxy_addr_t *source,
                              uint8_t *payload_out,
                              size_t payload_capacity,
                              size_t *payload_len);

int shadowsocks_2022_udp_session_new(shadowsocks_aead_method_t method,
                                     const uint8_t *key,
                                     size_t key_len,
                                     uint64_t *session_id,
                                     uint64_t *packet_id,
                                     uint8_t *session_key,
                                     size_t session_key_capacity);

int shadowsocks_2022_udp_seal(shadowsocks_aead_method_t method,
                              const uint8_t *key,
                              size_t key_len,
                              uint64_t session_id,
                              uint64_t packet_id,
                              const uint8_t *session_key,
                              const aproxy_addr_t *destination,
                              const uint8_t *payload,
                              size_t payload_len,
                              uint8_t *out,
                              size_t out_capacity,
                              size_t *out_len);

int shadowsocks_2022_udp_seal_multi(
    shadowsocks_aead_method_t method,
    const shadowsocks_2022_psk_list_t *psks,
    uint64_t session_id,
    uint64_t packet_id,
    const uint8_t *session_key,
    const aproxy_addr_t *destination,
    const uint8_t *payload,
    size_t payload_len,
    uint8_t *out,
    size_t out_capacity,
    size_t *out_len);

int shadowsocks_2022_udp_open(shadowsocks_aead_method_t method,
                              const uint8_t *key,
                              size_t key_len,
                              const uint8_t *packet,
                              size_t packet_len,
                              uint64_t expected_client_session_id,
                              uint64_t *remote_session_id,
                              uint8_t *remote_session_key,
                              size_t remote_session_key_capacity,
                              aproxy_addr_t *source,
                              uint8_t *payload_out,
                              size_t payload_capacity,
                              size_t *payload_len);

int shadowsocks_2022_udp_open_ex(
    shadowsocks_aead_method_t method,
    const uint8_t *key,
    size_t key_len,
    const uint8_t *packet,
    size_t packet_len,
    uint64_t expected_client_session_id,
    uint64_t *remote_session_id,
    uint64_t *remote_packet_id,
    uint8_t *remote_session_key,
    size_t remote_session_key_capacity,
    aproxy_addr_t *source,
    uint8_t *payload_out,
    size_t payload_capacity,
    size_t *payload_len);

void shadowsocks_2022_replay_reset(
    shadowsocks_2022_replay_window_t *window);

int shadowsocks_2022_replay_check(
    const shadowsocks_2022_replay_window_t *window,
    uint64_t packet_id);

void shadowsocks_2022_replay_add(
    shadowsocks_2022_replay_window_t *window,
    uint64_t packet_id);

#endif
