#ifndef SOLARIS_ANYTLS_INTERNAL_H
#define SOLARIS_ANYTLS_INTERNAL_H
#include "transport/session/pool.h"
#include "contracts/runtime/crypto.h"
#include "contracts/runtime/diagnostic.h"
#define SOLARIS_ANYTLS_POLICY_ROWS 32u
#define SOLARIS_ANYTLS_POLICY_PARTS 16u
typedef struct solaris_anytls_range { uint16_t low, high; int check; } solaris_anytls_range_t;
typedef struct solaris_anytls_policy {
    uint32_t stop;
    uint8_t counts[SOLARIS_ANYTLS_POLICY_ROWS];
    solaris_anytls_range_t rows[SOLARIS_ANYTLS_POLICY_ROWS][SOLARIS_ANYTLS_POLICY_PARTS];
    char md5[33];
} solaris_anytls_policy_t;
typedef struct solaris_anytls_parameters {
    uint8_t password_hash[32];
    solaris_crypto_source_t crypto;
    solaris_diagnostic_sink_t diagnostic;
    solaris_anytls_policy_t policy;
} solaris_anytls_parameters_t;
solaris_status_t solaris_anytls_policy_parse(const uint8_t *text, size_t length, solaris_anytls_policy_t *out);
solaris_status_t solaris_anytls_policy_default(solaris_anytls_policy_t *out);
solaris_status_t solaris_anytls_pad(const solaris_anytls_parameters_t *parameters,
    const solaris_anytls_policy_t *policy, uint32_t packet, solaris_budget_t *budget,
    const uint8_t *data, size_t length, solaris_session_batch_t *out);
solaris_status_t solaris_anytls_padding0(const solaris_anytls_parameters_t *parameters,
    const solaris_anytls_policy_t *policy, size_t *length);
extern const solaris_session_codec_t solaris_anytls_session_codec;
#endif
