#ifndef SOLARIS_CONFIG_DIALER_H
#define SOLARIS_CONFIG_DIALER_H

#include "contracts/module/config.h"
#include "transport/socket/socket.h"

#define SOLARIS_DIALER_CONFIG_FIELDS "bind-address", "bind-port", "open-timeout-ms", \
    "pending-bytes", "pending-requests", "read-chunk-size"

typedef struct solaris_dialer_config {
    solaris_dialer_options_t values;
    uint32_t present;
} solaris_dialer_config_t;

solaris_status_t solaris_dialer_config_compile(const solaris_config_view_t *view,
                                                solaris_dialer_config_t *out, solaris_error_t *error);
solaris_status_t solaris_dialer_config_apply(const solaris_dialer_config_t *config,
                                              const solaris_dialer_options_t *base,
                                              solaris_dialer_options_t *out);

#endif
