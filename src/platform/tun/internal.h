#ifndef SOLARIS_TUN_DEVICE_INTERNAL_H
#define SOLARIS_TUN_DEVICE_INTERNAL_H
#include "contracts/inbound/tun_device.h"
#include "runtime/executor/uv.h"

typedef struct solaris_tun_packet {
    struct solaris_tun_packet *next;
    size_t length;
    uint8_t data[];
} solaris_tun_packet_t;
typedef struct solaris_tun_device_ops {
    void (*schedule)(solaris_tun_device_t *device);
    void (*cancel)(solaris_tun_device_t *device);
    void (*dispose)(solaris_tun_device_t *device);
} solaris_tun_device_ops_t;
struct solaris_tun_device {
    const solaris_tun_device_ops_t *ops;
    solaris_tun_device_options_t options;
    solaris_scope_t scope;
    solaris_tun_packet_t *head, *tail;
    size_t pending_packets, pending_bytes;
    char name[128];
    solaris_status_t status;
    int accepted, closing, writable;
};
solaris_status_t solaris_tun_device_normalize(const solaris_tun_device_options_t *options, solaris_tun_device_options_t *out);
solaris_status_t solaris_tun_device_init(solaris_tun_device_t *device,
    const solaris_tun_device_options_t *options, const solaris_tun_device_ops_t *ops, const char *name);
void solaris_tun_device_fail(solaris_tun_device_t *device, solaris_status_t status);
void solaris_tun_device_pop(solaris_tun_device_t *device);
void solaris_tun_device_writable(solaris_tun_device_t *device);
int solaris_tun_device_packet(const uint8_t *packet, size_t length);
solaris_status_t solaris_tun_posix_open(const solaris_tun_device_options_t *options, solaris_tun_device_t **out);
solaris_status_t solaris_tun_wintun_open(const solaris_tun_device_options_t *options, solaris_tun_device_t **out);

/* Internal driver boundary, also used by the deterministic ring test peer.
 * receive returns a borrowed packet until release; allocate reserves exactly
 * length bytes until send. EAGAIN means empty/full ring. wait blocks only on
 * the dedicated worker; interrupt permanently wakes it. All other callbacks
 * run on owner, and close runs after the wait worker has exited. A validated
 * API context transfers to open_api even if activation subsequently fails. */
typedef struct solaris_wintun_api {
    void *context;
    uint8_t *(*receive)(void *context, size_t *length, solaris_status_t *status);
    void (*release)(void *context, uint8_t *packet);
    uint8_t *(*allocate)(void *context, size_t length, solaris_status_t *status);
    void (*send)(void *context, uint8_t *packet);
    solaris_status_t (*wait)(void *context);
    void (*interrupt)(void *context);
    void (*close)(void *context);
} solaris_wintun_api_t;
solaris_status_t solaris_tun_wintun_open_api(const solaris_tun_device_options_t *options,
    const solaris_wintun_api_t *api, solaris_tun_device_t **out);
#endif
