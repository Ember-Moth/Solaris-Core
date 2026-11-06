#include "config/outbound/dialer.h"
#include <limits.h>
#include <string.h>

enum { BIND = 1u, TIMEOUT = 2u, BYTES = 4u, REQUESTS = 8u, CHUNK = 16u };

solaris_status_t solaris_dialer_config_compile(const solaris_config_view_t *view,
                                                solaris_dialer_config_t *out, solaris_error_t *error)
{
    if (out == NULL || view == NULL || view->kind != SOLARIS_CONFIG_MAP) return SOLARIS_EINVAL;
    memset(out, 0, sizeof(*out));
    solaris_dialer_options_init(&out->values);
    char address[256];
    solaris_status_t rc = solaris_config_string(view, "bind-address", 0, address, sizeof(address), error);
    if (rc != SOLARIS_OK) return rc;
    uint64_t value;
    rc = solaris_config_uint(view, "bind-port", 0u, 0u, 65535u, &value, error);
    if (rc != SOLARIS_OK) return rc;
    if (address[0] != '\0') {
        rc = solaris_address_parse(address, (uint16_t)value, &out->values.local_bind);
        if (rc != SOLARIS_OK || out->values.local_bind.family == SOLARIS_ADDRESS_DOMAIN)
            return solaris_config_error(solaris_config_get(view, "bind-address"), "bind-address", "expected a numeric local address", error);
        out->present |= BIND;
    } else if (solaris_config_get(view, "bind-port") != NULL) {
        return solaris_config_error(solaris_config_get(view, "bind-port"), "bind-port", "requires bind-address", error);
    }
    rc = solaris_config_uint(view, "open-timeout-ms", out->values.open_timeout_ms, 1u,
                              UINT64_MAX / UINT64_C(1000000), &value, error);
    if (rc != SOLARIS_OK) return rc;
    out->values.open_timeout_ms = value;
    if (solaris_config_get(view, "open-timeout-ms") != NULL) out->present |= TIMEOUT;
    rc = solaris_config_uint(view, "pending-bytes", out->values.pending_byte_limit, 1u, UINT_MAX, &value, error);
    if (rc != SOLARIS_OK) return rc;
    out->values.pending_byte_limit = (size_t)value;
    if (solaris_config_get(view, "pending-bytes") != NULL) out->present |= BYTES;
    rc = solaris_config_uint(view, "pending-requests", out->values.pending_request_limit, 1u, 65536u, &value, error);
    if (rc != SOLARIS_OK) return rc;
    out->values.pending_request_limit = (size_t)value;
    if (solaris_config_get(view, "pending-requests") != NULL) out->present |= REQUESTS;
    rc = solaris_config_uint(view, "read-chunk-size", out->values.read_chunk_size, 1u, 65536u, &value, error);
    if (rc != SOLARIS_OK) return rc;
    out->values.read_chunk_size = (size_t)value;
    if (solaris_config_get(view, "read-chunk-size") != NULL) out->present |= CHUNK;
    return SOLARIS_OK;
}

solaris_status_t solaris_dialer_config_apply(const solaris_dialer_config_t *config,
                                              const solaris_dialer_options_t *base,
                                              solaris_dialer_options_t *out)
{
    if (config == NULL || out == NULL) return SOLARIS_EINVAL;
    solaris_status_t rc = solaris_dialer_options_normalize(base, out);
    if (rc != SOLARIS_OK) return rc;
    if (config->present & BIND) out->local_bind = config->values.local_bind;
    if (config->present & TIMEOUT) out->open_timeout_ms = config->values.open_timeout_ms;
    if (config->present & BYTES) out->pending_byte_limit = config->values.pending_byte_limit;
    if (config->present & REQUESTS) out->pending_request_limit = config->values.pending_request_limit;
    if (config->present & CHUNK) out->read_chunk_size = config->values.read_chunk_size;
    return SOLARIS_OK;
}
