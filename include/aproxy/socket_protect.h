#ifndef APROXY_SOCKET_PROTECT_H
#define APROXY_SOCKET_PROTECT_H

#include <stdint.h>
#include <uv.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*aproxy_socket_protect_result_cb)(void *context, int status);

/*
 * The submit callback borrows both the native socket handle and result
 * context until it reports exactly one result. Results must be dispatched on
 * the socket's libuv owner thread and never inline from submit(). Unix passes
 * a file descriptor; Windows passes its pointer-width SOCKET value.
 */
typedef int (*aproxy_socket_protect_submit_cb)(
    void *context,
    intptr_t socket_handle,
    aproxy_socket_protect_result_cb result,
    void *result_context);

typedef struct aproxy_socket_protector {
    void *context;
    aproxy_socket_protect_submit_cb submit;
} aproxy_socket_protector_t;

int aproxy_socket_protector_submit(
    const aproxy_socket_protector_t *protector,
    const uv_handle_t *handle,
    aproxy_socket_protect_result_cb result,
    void *result_context);

#ifdef __cplusplus
}
#endif

#endif
