#include "aproxy/socket_protect.h"

#include "aproxy/error.h"

int aproxy_socket_protector_submit(
    const aproxy_socket_protector_t *protector,
    const uv_handle_t *handle,
    aproxy_socket_protect_result_cb result,
    void *result_context)
{
    if (protector == NULL || protector->submit == NULL || handle == NULL ||
        result == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    uv_os_fd_t descriptor;
    const int rc = uv_fileno(handle, &descriptor);
    if (rc != 0) {
        return rc;
    }
    const intptr_t socket_handle = (intptr_t)descriptor;
    if (socket_handle < 0) {
        return APROXY_ERR_UNSUPPORTED;
    }
    return protector->submit(protector->context, socket_handle, result,
                             result_context);
}
