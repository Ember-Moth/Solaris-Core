#ifndef SOLARIS_SOCKET_INTERNAL_H
#define SOLARIS_SOCKET_INTERNAL_H

#include "transport/socket/socket.h"
#include "runtime/executor/uv.h"

solaris_status_t solaris_socket_options(const solaris_dialer_options_t *input,
                                        solaris_dialer_options_t *output);
solaris_status_t solaris_socket_prepare(const solaris_dialer_options_t *options,
                                        uv_handle_t *handle, uint32_t family, uint32_t kind);
solaris_status_t solaris_socket_status(int status);

#endif
