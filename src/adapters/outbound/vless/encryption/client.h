#ifndef SOLARIS_VLESS_ENCRYPTION_CLIENT_H
#define SOLARIS_VLESS_ENCRYPTION_CLIENT_H

#include "adapters/outbound/vless/encryption/config.h"
#include "contracts/runtime/crypto.h"
#include "transport/stream/filter.h"

typedef struct solaris_vless_encryption_client solaris_vless_encryption_client_t;
/* One client belongs to one worker. References extend its lifetime beyond
 * module retirement; ticket access and codec operations run on that owner.
 * Clock/entropy contexts are borrowed until the final channel is destroyed. */
solaris_status_t solaris_vless_encryption_client_create(const solaris_vless_encryption_config_t *config,
    solaris_budget_t *budget, const solaris_crypto_source_t *crypto,
    void *clock_context, uint64_t (*now_ns)(void *), solaris_vless_encryption_client_t **out);
void solaris_vless_encryption_client_retain(solaris_vless_encryption_client_t *client);
void solaris_vless_encryption_client_release(solaris_vless_encryption_client_t *client);

/* Parameters is a borrowed client pointer. create retains it. A full handshake
 * gates open on authenticated padding. A resumed connection admits writes after
 * its preface and authenticates the peer's first record; rejected application
 * data is never replayed automatically. */
extern const solaris_stream_codec_ops_t solaris_vless_encryption_codec;

#endif
