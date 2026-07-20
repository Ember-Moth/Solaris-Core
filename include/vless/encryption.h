#ifndef VLESS_ENCRYPTION_H
#define VLESS_ENCRYPTION_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/buffer.h"
#include "aproxy/error.h"

#define VLESS_ENCRYPTION_METHOD "mlkem768x25519plus"
#define VLESS_ENCRYPTION_MAX_KEYS 8u
#define VLESS_ENCRYPTION_RECORD_PLAINTEXT_MAX 8192u

typedef enum vless_encryption_mode {
    VLESS_ENCRYPTION_MODE_NATIVE = 0,
    VLESS_ENCRYPTION_MODE_XORPUB = 1,
    VLESS_ENCRYPTION_MODE_RANDOM = 2,
} vless_encryption_mode_t;

typedef enum vless_encryption_rtt {
    VLESS_ENCRYPTION_1RTT = 0,
    VLESS_ENCRYPTION_0RTT = 1,
} vless_encryption_rtt_t;

typedef struct vless_encryption_client_config
    vless_encryption_client_config_t;
typedef struct vless_encryption_client vless_encryption_client_t;

/* Parses the complete mlkem768x25519plus client configuration string. */
int vless_encryption_client_config_parse(
    const char *raw,
    vless_encryption_client_config_t **out);

void vless_encryption_client_config_free(
    vless_encryption_client_config_t *config);

vless_encryption_mode_t vless_encryption_client_config_mode(
    const vless_encryption_client_config_t *config);

vless_encryption_rtt_t vless_encryption_client_config_rtt(
    const vless_encryption_client_config_t *config);

size_t vless_encryption_client_config_key_count(
    const vless_encryption_client_config_t *config);

int vless_encryption_client_new(
    vless_encryption_client_config_t *config,
    vless_encryption_client_t **out);

void vless_encryption_client_free(vless_encryption_client_t *client);

/*
 * Starts a fresh handshake and appends bytes that must be sent immediately.
 * A resumed 0-RTT session delays its preface until the first seal operation.
 */
int vless_encryption_client_start(vless_encryption_client_t *client,
                                  aproxy_buffer_t *wire_out);

/* True once application bytes may be encrypted and sent. */
int vless_encryption_client_send_ready(
    const vless_encryption_client_t *client);

/* True once the peer handshake is authenticated and records can be read. */
int vless_encryption_client_receive_ready(
    const vless_encryption_client_t *client);

/*
 * Feeds an arbitrary wire fragment. Decrypted records are appended to
 * plaintext_out. became_ready is set when a 1-RTT handshake completes.
 */
int vless_encryption_client_feed(vless_encryption_client_t *client,
                                 const uint8_t *wire,
                                 size_t wire_len,
                                 aproxy_buffer_t *plaintext_out,
                                 int *became_ready);

/* Like feed, but emits at most one application record per call. */
int vless_encryption_client_feed_once(vless_encryption_client_t *client,
                                      const uint8_t *wire,
                                      size_t wire_len,
                                      aproxy_buffer_t *plaintext_out,
                                      int *became_ready);

/* Extracts bytes buffered after a negotiated direct-read transition. */
int vless_encryption_client_take_buffered(
    vless_encryption_client_t *client,
    aproxy_buffer_t *output);

/* Encrypts application bytes into one or more fake-TLS records. */
int vless_encryption_client_seal(vless_encryption_client_t *client,
                                 const uint8_t *plaintext,
                                 size_t plaintext_len,
                                 aproxy_buffer_t *wire_out);

#endif
