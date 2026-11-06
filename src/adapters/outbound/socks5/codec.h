#ifndef SOLARIS_SOCKS5_CODEC_H
#define SOLARIS_SOCKS5_CODEC_H
#include "contracts/io/channel.h"

#define SOLARIS_SOCKS5_UDP_MAX 65000u
typedef struct solaris_socks5_credentials {
    uint8_t username[256], password[256];
    uint8_t username_length, password_length;
} solaris_socks5_credentials_t;
enum { SOLARIS_SOCKS5_GREETING, SOLARIS_SOCKS5_METHOD, SOLARIS_SOCKS5_AUTH_SEND,
    SOLARIS_SOCKS5_AUTH_REPLY, SOLARIS_SOCKS5_REQUEST, SOLARIS_SOCKS5_REPLY, SOLARIS_SOCKS5_READY };
typedef struct solaris_socks5_handshake {
    solaris_socks5_credentials_t credentials;
    solaris_address_t target, bound;
    uint8_t command, stage, reply_code;
} solaris_socks5_handshake_t;

void solaris_socks5_clear(void *memory, size_t size);
solaris_status_t solaris_socks5_handshake_init(solaris_socks5_handshake_t *state,
    const solaris_socks5_credentials_t *credentials, uint8_t command, const solaris_address_t *target);
int solaris_socks5_handshake_wants_write(const solaris_socks5_handshake_t *state);
solaris_status_t solaris_socks5_handshake_write(solaris_socks5_handshake_t *state,
    solaris_budget_t *budget, solaris_buffer_t **out);
solaris_status_t solaris_socks5_handshake_read(solaris_socks5_handshake_t *state,
    const uint8_t *data, size_t size, size_t *consumed);
solaris_status_t solaris_socks5_packet_encode(solaris_budget_t *budget, const solaris_address_t *target,
    const solaris_slice_t *payload, solaris_buffer_t **out);
solaris_status_t solaris_socks5_packet_decode(solaris_budget_t *budget, const uint8_t *data, size_t size,
    solaris_address_t *source, solaris_buffer_t **out);
#endif
