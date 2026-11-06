#ifndef SOLARIS_TUN_DEVICE_H
#define SOLARIS_TUN_DEVICE_H

#include "contracts/inbound/tun_stack.h"

typedef struct solaris_tun_device solaris_tun_device_t;
enum { SOLARIS_TUN_FRAMING_IP = 0, SOLARIS_TUN_FRAMING_DARWIN = 1 };
enum { SOLARIS_TUN_DEVICE_FD = 1, SOLARIS_TUN_DEVICE_NATIVE = 2, SOLARIS_TUN_DEVICE_WINTUN = 3 };
typedef struct solaris_tun_device_options {
    solaris_executor_t *owner;
    uint32_t kind, framing;
    /* FD is duplicated; caller retains its fd. Since dup shares file status
     * flags, adopted fd must already be nonblocking. Native device is owned. */
    intptr_t fd;
    const char *name;
    /* Explicit trusted absolute DLL path, never a CWD/PATH search. */
    const char *wintun_library;
    size_t mtu, queue_packet_limit, queue_byte_limit;
    void *context;
    void (*on_packet)(void *context, const uint8_t *packet, size_t length);
    void (*on_writable)(void *context);
    void (*on_close)(void *context, solaris_status_t status);
} solaris_tun_device_options_t;
/* Activate on owner; does not install addresses/routes/DNS or change proxy.
 * macOS native uses utun; iOS uses host-provided NetworkExtension fd or packet
 * callbacks at the inbound layer. Linux native uses IFF_TUN|IFF_NO_PI.
 * No callbacks after rejected open. Success on_close is the release barrier. */
solaris_status_t solaris_tun_device_open(const solaris_tun_device_options_t *options,
                                        solaris_tun_device_t **out);
solaris_status_t solaris_tun_device_write(solaris_tun_device_t *device,
                                         const uint8_t *packet, size_t length);
void solaris_tun_device_close(solaris_tun_device_t *device);
const char *solaris_tun_device_name(const solaris_tun_device_t *device);
#endif
