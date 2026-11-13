#ifndef SOLARIS_SOCKET_INTERNAL_H
#define SOLARIS_SOCKET_INTERNAL_H

#include "transport/socket/socket.h"
#include "runtime/executor/uv.h"
#include "transport/socket/preparation.h"

solaris_status_t solaris_socket_options(const solaris_dialer_options_t *input,
                                        solaris_dialer_options_t *output);
solaris_status_t solaris_socket_prepare(const solaris_dialer_options_t *options,
                                        uv_handle_t *handle, uint32_t family, uint32_t kind);
solaris_status_t solaris_socket_prepare_async(const solaris_dialer_options_t *options,
    solaris_executor_t *owner, uv_handle_t *handle, uint32_t family, uint32_t kind,
    uint64_t deadline_ns, solaris_scope_t *parent, solaris_io_done_fn done,
    void *context, solaris_socket_token_t **out);
solaris_status_t solaris_socket_status(int status);

#endif
