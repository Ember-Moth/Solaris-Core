#ifndef ANYTLS_OUTBOUND_H
#define ANYTLS_OUTBOUND_H

#include <stdint.h>

#include "anytls/client.h"
#include "aproxy/outbound.h"

typedef struct anytls_outbound_config {
    const char *tag;
    anytls_client_config_t client;
    /* AnyTLS always carries UDP over UoT; zero selects version 2. */
    uint8_t uot_version;
    int64_t idle_session_check_interval_ms;
    int64_t idle_session_timeout_ms;
    int min_idle_sessions;
    int max_idle_sessions;
} anytls_outbound_config_t;

int anytls_outbound_new(const anytls_outbound_config_t *config,
                        aproxy_outbound_t **out);

#endif
