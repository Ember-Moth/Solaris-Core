#ifndef SOLARIS_TUN_INBOUND_H
#define SOLARIS_TUN_INBOUND_H
#include "contracts/inbound/tun_device.h"
#include "contracts/flow/plan.h"

typedef struct solaris_tun solaris_tun_t;
enum { SOLARIS_TUN_STACK_LWIP = 1, SOLARIS_TUN_STACK_SYSTEM = 2 };
typedef struct solaris_tun_snapshot {
    uint64_t packets_in, packets_out, bytes_in, bytes_out;
    uint64_t malformed, unsupported, congested, udp_failed, tcp_failed;
    size_t active_tcp;
    uint32_t closing;
} solaris_tun_snapshot_t;
typedef struct solaris_tun_options {
    solaris_executor_t *owner;
    uint32_t stack;
    uint64_t inbound_id, generation;
    solaris_address_t address4, peer4, address6, peer6;
    size_t mtu, tcp_flow_limit, udp_association_limit, udp_mapping_limit;
    size_t pending_byte_limit, pending_packet_limit;
    uint64_t idle_timeout_ms, open_timeout_ms;
    int include_all_networks;
    /* kind=0 uses host packet I/O. Dispatch input to owner; before close, stop
     * producers and drain/revoke queued host input. Such tasks must resolve a
     * live handle/generation on owner, never use a stale captured tun pointer.
     * Native devices call input directly on owner. Configuring interface MTU,
     * addresses/routes/DNS and protecting outbound sockets is host-owned. */
    solaris_tun_device_options_t device;
    void *context;
    solaris_tun_emit_fn emit;
    solaris_status_t (*select)(void *context, solaris_executor_t *owner, uint8_t protocol,
        const solaris_address_t *source, const solaris_address_t *destination, solaris_dial_plan_t *out);
    void (*on_close)(void *context, const solaris_tun_snapshot_t *snapshot, solaris_status_t status);
} solaris_tun_options_t;
void solaris_tun_options_init(solaris_tun_options_t *options);
/* Owner-only activation; consumes no input until it returns success. No
 * user callbacks on rejected creation. A successful on_close is the barrier
 * for every device, stack, flow, UDP reply, and accepted write callback. */
solaris_status_t solaris_tun_create(const solaris_tun_options_t *options, solaris_tun_t **out);
/* Input/emit callback reentrancy returns EBUSY; defer new packets on owner.
 * close remains permitted from emit/select callbacks. */
solaris_status_t solaris_tun_input(solaris_tun_t *tun, const uint8_t *packet, size_t length);
solaris_status_t solaris_tun_snapshot(solaris_tun_t *tun, solaris_tun_snapshot_t *out);
/* Owner-only borrowed device name, valid until on_close. NULL for host I/O. */
const char *solaris_tun_name(const solaris_tun_t *tun);
solaris_status_t solaris_tun_close(solaris_tun_t *tun);
#endif
