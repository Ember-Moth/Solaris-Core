#include "transport/socket/internal.h"
#include <limits.h>
#include <string.h>

void solaris_dialer_options_init(solaris_dialer_options_t *options)
{
    memset(options, 0, sizeof(*options));
    options->pending_byte_limit = 256u * 1024u;
    options->pending_request_limit = 64u;
    options->read_chunk_size = 16384u;
    options->open_timeout_ms = 10000u;
    options->lookup_view.role = SOLARIS_DNS_DIRECT_TARGET;
}

solaris_status_t solaris_socket_options(const solaris_dialer_options_t *input,
                                        solaris_dialer_options_t *output)
{
    solaris_dialer_options_init(output);
    if (input == NULL) return SOLARIS_OK;
    solaris_dialer_options_t defaults = *output;
    *output = *input;
    if (output->pending_byte_limit == 0u) output->pending_byte_limit = defaults.pending_byte_limit;
    if (output->pending_request_limit == 0u) output->pending_request_limit = defaults.pending_request_limit;
    if (output->read_chunk_size == 0u) output->read_chunk_size = defaults.read_chunk_size;
    if (output->open_timeout_ms == 0u) output->open_timeout_ms = defaults.open_timeout_ms;
    if (output->lookup_view.role == 0u) output->lookup_view.role = SOLARIS_DNS_DIRECT_TARGET;
    if ((output->local_bind.family != 0u && output->local_bind.family != SOLARIS_ADDRESS_IPV4 &&
         output->local_bind.family != SOLARIS_ADDRESS_IPV6) ||
        output->pending_byte_limit > UINT_MAX || output->pending_request_limit > 65536u ||
        output->read_chunk_size > 65536u || output->open_timeout_ms > UINT64_MAX / UINT64_C(1000000) ||
        (output->lookup.start == NULL) != (output->lookup.cancel == NULL) ||
        (output->async_policy.start == NULL) != (output->async_policy.cancel == NULL) ||
        (output->async_policy.retain == NULL) != (output->async_policy.release == NULL) ||
        output->lookup_view.role > SOLARIS_DNS_CLIENT_QUERY ||
        (output->require_lookup != 0 && output->require_lookup != 1) ||
        output->network_view_present > 1u || (output->allowed_families & ~3u)) return SOLARIS_EINVAL;
    return SOLARIS_OK;
}

solaris_status_t solaris_dialer_options_normalize(const solaris_dialer_options_t *input,
                                                  solaris_dialer_options_t *output)
{
    if (output == NULL) return SOLARIS_EINVAL;
    return solaris_socket_options(input, output);
}

solaris_status_t solaris_socket_prepare(const solaris_dialer_options_t *options,
                                        uv_handle_t *handle, uint32_t family, uint32_t kind)
{
    if (options->prepare_socket == NULL) return SOLARIS_OK;
    uv_os_fd_t descriptor;
    const int rc = uv_fileno(handle, &descriptor);
    if (rc != 0) return solaris_socket_status(rc);
    return options->prepare_socket(options->policy_context, (uintptr_t)descriptor, family, kind);
}

solaris_status_t solaris_socket_prepare_async(const solaris_dialer_options_t *options,
    solaris_executor_t *owner, uv_handle_t *handle, uint32_t family, uint32_t kind,
    uint64_t deadline_ns, solaris_scope_t *parent, solaris_io_done_fn done,
    void *context, solaris_socket_token_t **out)
{
    *out = NULL;
    uv_os_fd_t descriptor;
    int rc = uv_fileno(handle, &descriptor);
    if (rc != 0) return solaris_socket_status(rc);
    solaris_socket_preparation_options_t prepare = {.owner = owner, .parent_scope = parent,
        .policy = options->async_policy, .handle = (uintptr_t)descriptor, .family = family,
        .kind = kind == SOLARIS_SOCKET_TCP ? SOLARIS_SOCKET_POLICY_TCP : SOLARIS_SOCKET_POLICY_UDP,
        .deadline_ns = deadline_ns};
    return solaris_socket_preparation_start(&prepare, done, context, out);
}

solaris_status_t solaris_socket_status(int status)
{
    if (status == 0) return SOLARIS_OK;
    if (status == UV_ECANCELED) return SOLARIS_ECANCELLED;
    if (status == UV_ENOMEM || status == UV_ENOBUFS) return SOLARIS_ENOMEM;
    if (status == UV_EAGAIN) return SOLARIS_EAGAIN;
    if (status == UV_ETIMEDOUT) return SOLARIS_ETIMEDOUT;
    if (status == UV_EACCES || status == UV_EPERM) return SOLARIS_EACCESS;
    if (status == UV_EMSGSIZE) return SOLARIS_EMSGSIZE;
    return SOLARIS_EIO;
}
