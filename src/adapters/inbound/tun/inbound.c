#include "contracts/inbound/tun.h"
#include "contracts/flow/tcp.h"
#include "contracts/flow/udp.h"
#include "codec/ip/packet.h"
#include "solaris_builtin_modules.h"
#include <assert.h>
#include <string.h>

typedef struct tcp_entry {
    struct tcp_entry *next;
    struct solaris_tun *tun;
    solaris_tcp_relay_t *relay;
} tcp_entry_t;
struct solaris_tun {
    solaris_scope_t scope;
    solaris_tun_options_t options;
    solaris_tun_stack_t *stack;
    solaris_tun_device_t *device;
    solaris_udp_dispatcher_t *udp;
    solaris_udp_reply_endpoint_t reply;
    tcp_entry_t *tcp;
    solaris_tun_snapshot_t stats;
    solaris_status_t status;
    uint32_t fragment_id;
    int accepted, input_active, emitting;
};
static void close_with_status(solaris_tun_t *tun, solaris_status_t status)
{
    if (tun->scope.cancelled) return;
    tun->status = status;
    solaris_scope_cancel(&tun->scope);
}
static void cancel(void *context)
{
    solaris_tun_t *tun = context;
    tun->stats.closing = 1;
    if (tun->device) solaris_tun_device_close(tun->device);
    if (tun->stack) tun->stack->ops->close(tun->stack->state);
    if (tun->udp) (void)solaris_udp_dispatcher_close(tun->udp);
    for (tcp_entry_t *entry = tun->tcp; entry; entry = entry->next) solaris_tcp_relay_close(entry->relay);
}
static void finished(void *context)
{
    solaris_tun_t *tun = context;
    assert(!tun->device && !tun->stack && !tun->tcp);
    if (tun->udp) {
        solaris_status_t rc = solaris_udp_dispatcher_destroy(tun->udp);
        assert(rc == SOLARIS_OK); (void)rc;
    }
    if (tun->accepted) tun->options.on_close(tun->options.context, &tun->stats, tun->status);
    solaris_memory_free(tun);
}
static solaris_status_t emit(void *context, const uint8_t *packet, size_t length)
{
    solaris_tun_t *tun = context;
    if (tun->scope.cancelled) return SOLARIS_ECLOSED;
    if (length > tun->options.mtu) return SOLARIS_EMSGSIZE;
    if (!tun->device && !tun->options.emit) return SOLARIS_EAGAIN;
    tun->emitting++;
    solaris_status_t rc = tun->device ? solaris_tun_device_write(tun->device, packet, length) :
        tun->options.emit(tun->options.context, packet, length);
    tun->emitting--;
    if (rc == SOLARIS_OK) { tun->stats.packets_out++; tun->stats.bytes_out += length; }
    else if (rc == SOLARIS_EAGAIN || rc == SOLARIS_ENOMEM) tun->stats.congested++;
    return rc;
}
static void tcp_closed(void *context, solaris_status_t status)
{
    tcp_entry_t *entry = context;
    solaris_tun_t *tun = entry->tun;
    tcp_entry_t **cursor = &tun->tcp;
    while (*cursor && *cursor != entry) cursor = &(*cursor)->next;
    assert(*cursor == entry); *cursor = entry->next;
    tun->stats.active_tcp--;
    if (status != SOLARIS_OK && status != SOLARIS_ECANCELLED) tun->stats.tcp_failed++;
    solaris_memory_free(entry);
    solaris_scope_release(&tun->scope);
}
static solaris_status_t accept_tcp(void *context, const solaris_address_t *source,
    const solaris_address_t *destination, solaris_stream_callbacks_t *callbacks, void **stream_context)
{
    solaris_tun_t *tun = context;
    if (tun->scope.cancelled) return SOLARIS_ECLOSED;
    if (tun->stats.active_tcp >= tun->options.tcp_flow_limit) return SOLARIS_EAGAIN;
    tcp_entry_t *entry = solaris_memory_allocate(solaris_executor_budget(tun->scope.owner), sizeof(*entry));
    if (!entry) return SOLARIS_ENOMEM;
    memset(entry, 0, sizeof(*entry)); entry->tun = tun;
    solaris_dial_plan_t plan; memset(&plan, 0, sizeof(plan));
    solaris_status_t rc = tun->options.select(tun->options.context, tun->scope.owner, SOLARIS_IP_TCP,
        source, destination, &plan);
    if (rc == SOLARIS_OK && tun->scope.cancelled) rc = SOLARIS_ECLOSED;
    if (rc == SOLARIS_OK) {
        solaris_tcp_relay_options_t options = { tun->scope.owner, *destination,
            tun->options.pending_byte_limit, entry, tcp_closed };
        rc = solaris_tcp_relay_prepare(&options, &plan, callbacks, stream_context, &entry->relay);
    }
    if (rc != SOLARIS_OK) {
        (void)solaris_dial_plan_release(&plan); solaris_memory_free(entry); return rc;
    }
    entry->next = tun->tcp; tun->tcp = entry; tun->stats.active_tcp++;
    solaris_scope_retain(&tun->scope);
    return SOLARIS_OK;
}
static solaris_status_t udp_select(void *context, solaris_executor_t *owner,
    const solaris_udp_key_t *key, const solaris_address_t *destination, solaris_udp_plan_t *out)
{
    solaris_tun_t *tun = context;
    if (tun->scope.cancelled) return SOLARIS_ECLOSED;
    return tun->options.select(tun->options.context, owner, SOLARIS_IP_UDP, &key->source, destination, out);
}
static void retain(void *context) { solaris_scope_retain(&((solaris_tun_t *)context)->scope); }
static void release(void *context) { solaris_scope_release(&((solaris_tun_t *)context)->scope); }
static void put16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8u); p[1] = (uint8_t)n; }
static void put32(uint8_t *p, uint32_t n)
{ p[0] = (uint8_t)(n >> 24u); p[1] = (uint8_t)(n >> 16u); p[2] = (uint8_t)(n >> 8u); p[3] = (uint8_t)n; }
/* UDP replies originate here, so they may be fragmented to the host's MTU.
 * Partial emission is a dropped datagram, never a replay or an oversized TUN
 * write. Input fragmentation is rejected explicitly by the parser. */
static solaris_status_t emit_udp(solaris_tun_t *tun, const solaris_buffer_t *buffer)
{
    size_t length = solaris_buffer_length(buffer);
    const uint8_t *packet = solaris_buffer_data(buffer);
    if (length <= tun->options.mtu) return emit(tun, packet, length);
    int v4 = (packet[0] >> 4u) == 4u;
    size_t header = v4 ? 20u : 40u, fragment_header = v4 ? 20u : 48u;
    size_t chunk = ((tun->options.mtu - fragment_header) / 8u) * 8u;
    solaris_buffer_t *fragment;
    solaris_status_t rc = solaris_buffer_allocate(solaris_executor_budget(tun->scope.owner), tun->options.mtu, &fragment);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *p = solaris_buffer_mutable_data(fragment);
    uint32_t id = ++tun->fragment_id;
    for (size_t offset = 0; offset < length - header;) {
        size_t n = length - header - offset;
        if (n > chunk) n = chunk;
        int more = offset + n < length - header;
        memcpy(p, packet, header);
        if (v4) {
            put16(p + 2, (uint16_t)(n + fragment_header)); put16(p + 4, (uint16_t)id);
            put16(p + 6, (uint16_t)((offset / 8u) | (more ? 0x2000u : 0u)));
            p[10] = p[11] = 0; put16(p + 10, solaris_ip_checksum(p, header));
        } else {
            p[6] = 44; put16(p + 4, (uint16_t)(n + 8u)); p[40] = SOLARIS_IP_UDP; p[41] = 0;
            put16(p + 42, (uint16_t)(offset | (more ? 1u : 0u))); put32(p + 44, id);
        }
        memcpy(p + fragment_header, packet + header + offset, n);
        rc = emit(tun, p, n + fragment_header);
        if (rc != SOLARIS_OK) break;
        offset += n;
    }
    solaris_buffer_release(fragment); return rc;
}
static solaris_status_t udp_reply(void *context, uint64_t generation, const solaris_udp_key_t *key,
    const solaris_address_t *peer, const solaris_buffer_t *payload)
{
    solaris_tun_t *tun = context;
    if (tun->scope.cancelled || generation != tun->options.generation) return SOLARIS_ECLOSED;
    solaris_buffer_t *packet;
    solaris_status_t rc = solaris_ip_udp(solaris_executor_budget(tun->scope.owner), peer, &key->source,
        solaris_buffer_data(payload), solaris_buffer_length(payload), &packet);
    if (rc != SOLARIS_OK) return rc;
    rc = emit_udp(tun, packet); solaris_buffer_release(packet); return rc;
}
static void udp_sent(void *context, solaris_status_t status)
{
    solaris_tun_t *tun = context;
    if (status != SOLARIS_OK) tun->stats.udp_failed++;
}
static void stack_closed(void *context, solaris_status_t status)
{
    solaris_tun_t *tun = context;
    tun->stack = NULL;
    if (!tun->scope.cancelled) close_with_status(tun, status);
    solaris_scope_release(&tun->scope);
}
static void device_closed(void *context, solaris_status_t status)
{
    solaris_tun_t *tun = context;
    tun->device = NULL;
    if (!tun->scope.cancelled) close_with_status(tun, status);
    solaris_scope_release(&tun->scope);
}
static void device_packet(void *context, const uint8_t *packet, size_t length)
{ (void)solaris_tun_input(context, packet, length); }
void solaris_tun_options_init(solaris_tun_options_t *options)
{
    if (!options) return;
    memset(options, 0, sizeof(*options));
    options->stack = SOLARIS_TUN_STACK_LWIP;
    options->mtu = 1500; options->tcp_flow_limit = 512; options->udp_association_limit = 512;
    options->udp_mapping_limit = 64; options->pending_byte_limit = 262144; options->pending_packet_limit = 64;
    options->idle_timeout_ms = 60000; options->open_timeout_ms = 10000;
}
solaris_status_t solaris_tun_create(const solaris_tun_options_t *options, solaris_tun_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!options || !options->owner || !options->select || !options->on_close ||
        (!options->device.kind && !options->emit) ||
        (options->stack != SOLARIS_TUN_STACK_LWIP && options->stack != SOLARIS_TUN_STACK_SYSTEM) ||
        options->mtu < 576u || options->mtu > 65535u ||
        (options->address6.family && options->mtu < 1280u) ||
        !options->tcp_flow_limit || options->tcp_flow_limit > 65535u ||
        !options->udp_association_limit || options->udp_association_limit > 65535u ||
        !options->udp_mapping_limit || !options->pending_packet_limit ||
        options->pending_byte_limit < 65536u || options->pending_byte_limit > 16777216u ||
        !options->idle_timeout_ms || options->idle_timeout_ms > 86400000u ||
        !options->open_timeout_ms || options->open_timeout_ms > 3600000u) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(options->owner)) return SOLARIS_ETHREAD;
    /* System listeners bind the host's configured interface addresses. A new
     * native device cannot be configured inside this one-stage constructor.
     * Open/configure it first, then use host packet I/O or a preconfigured fd. */
    if (options->stack == SOLARIS_TUN_STACK_SYSTEM && options->device.kind &&
        options->device.kind != SOLARIS_TUN_DEVICE_FD) return SOLARIS_ENOTSUP;
    solaris_tun_t *tun = solaris_memory_allocate(solaris_executor_budget(options->owner), sizeof(*tun));
    if (!tun) return SOLARIS_ENOMEM;
    memset(tun, 0, sizeof(*tun)); tun->options = *options; tun->status = SOLARIS_ECANCELLED;
    if (!tun->options.generation) tun->options.generation = solaris_executor_generation(options->owner);
    tun->reply = (solaris_udp_reply_endpoint_t){ tun, tun->options.generation, retain, release, udp_reply };
    solaris_status_t rc = solaris_scope_init(&tun->scope, options->owner, cancel, finished, tun);
    if (rc != SOLARIS_OK) { solaris_memory_free(tun); return rc; }
    solaris_executor_t *workers[] = { options->owner };
    solaris_udp_dispatcher_options_t udp; memset(&udp, 0, sizeof(udp));
    udp.workers = workers; udp.worker_count = 1; udp.budget = solaris_executor_budget(options->owner);
    udp.association_limit = options->udp_association_limit; udp.mapping_limit = options->udp_mapping_limit;
    udp.pending_byte_limit = options->pending_byte_limit; udp.pending_packet_limit = options->pending_packet_limit;
    udp.idle_timeout_ms = options->idle_timeout_ms; udp.open_timeout_ms = options->open_timeout_ms;
    udp.context = tun; udp.select = udp_select;
    rc = solaris_udp_dispatcher_create(&udp, &tun->udp);
    if (rc != SOLARIS_OK) goto fail;
    solaris_tun_stack_options_t stack; memset(&stack, 0, sizeof(stack));
    stack.owner = options->owner; stack.context = tun; stack.emit = emit; stack.accept = accept_tcp;
    stack.on_close = stack_closed; stack.address4 = options->address4; stack.peer4 = options->peer4;
    stack.address6 = options->address6; stack.peer6 = options->peer6; stack.mtu = options->mtu;
    stack.flow_limit = options->tcp_flow_limit; stack.pending_byte_limit = options->pending_byte_limit;
    stack.idle_timeout_ms = options->idle_timeout_ms; stack.include_all_networks = options->include_all_networks;
    solaris_scope_retain(&tun->scope);
    rc = SOLARIS_ENOTSUP;
#if SOLARIS_HAS_TUN_LWIP
    if (options->stack == SOLARIS_TUN_STACK_LWIP) rc = solaris_tun_lwip_create(&stack, &tun->stack);
#endif
#if SOLARIS_HAS_TUN_SYSTEM
    if (options->stack == SOLARIS_TUN_STACK_SYSTEM) rc = solaris_tun_system_create(&stack, &tun->stack);
#endif
    if (rc != SOLARIS_OK) { solaris_scope_release(&tun->scope); goto fail; }
    if (options->device.kind) {
        solaris_tun_device_options_t device = options->device;
        device.owner = options->owner; device.context = tun; device.mtu = options->mtu;
        device.queue_packet_limit = options->pending_packet_limit; device.queue_byte_limit = options->pending_byte_limit;
        device.on_packet = device_packet; device.on_writable = NULL; device.on_close = device_closed;
        solaris_scope_retain(&tun->scope);
        rc = solaris_tun_device_open(&device, &tun->device);
        if (rc != SOLARIS_OK) { solaris_scope_release(&tun->scope); goto fail; }
    }
    tun->accepted = 1; *out = tun; return SOLARIS_OK;
fail:
    close_with_status(tun, rc); return rc;
}
static solaris_status_t input_packet(solaris_tun_t *tun, const uint8_t *packet, size_t length)
{
    uint64_t congested = tun->stats.congested;
    tun->stats.packets_in++; tun->stats.bytes_in += length;
    if (length > tun->options.mtu) { tun->stats.unsupported++; return SOLARIS_EMSGSIZE; }
    solaris_ip_packet_t ip;
    solaris_status_t rc = solaris_ip_parse(packet, length, 1, &ip);
    if (rc != SOLARIS_OK) {
        if (rc == SOLARIS_ENOTSUP) tun->stats.unsupported++; else tun->stats.malformed++;
        return rc;
    }
    if ((ip.source.family == SOLARIS_ADDRESS_IPV4 && !tun->options.address4.family) ||
        (ip.source.family == SOLARIS_ADDRESS_IPV6 && !tun->options.address6.family)) {
        tun->stats.unsupported++;
        return SOLARIS_ENOTSUP;
    }
    if (ip.protocol == SOLARIS_IP_TCP) rc = tun->stack->ops->input(tun->stack->state, packet, length);
    else if (ip.protocol == SOLARIS_IP_UDP) {
        solaris_buffer_t *payload;
        rc = solaris_buffer_copy(solaris_executor_budget(tun->scope.owner), packet + ip.payload_offset,
            ip.payload_length, &payload);
        if (rc == SOLARIS_OK) {
            solaris_udp_key_t key; memset(&key, 0, sizeof(key));
            key.inbound_id = tun->options.inbound_id; key.inbound_generation = tun->options.generation;
            key.source = ip.source;
            solaris_slice_t slice = { payload, 0, ip.payload_length };
            rc = solaris_udp_submit(tun->udp, &key, &ip.destination, &slice, &tun->reply, udp_sent, tun, NULL);
            solaris_buffer_release(payload);
        }
    } else {
        /* Only the interface itself answers echo. A proxy must not fabricate
         * reachability for arbitrary remote destinations. */
        const solaris_address_t *local = ip.source.family == SOLARIS_ADDRESS_IPV4 ? &tun->options.address4 : &tun->options.address6;
        int echo = packet[ip.transport_offset] == (ip.protocol == SOLARIS_IP_ICMP ? 8u : 128u) &&
            packet[ip.transport_offset + 1] == 0 && memcmp(local->ip, ip.destination.ip, ip.source.family == 4u ? 4u : 16u) == 0;
        rc = SOLARIS_ENOTSUP;
        if (echo) {
            solaris_buffer_t *reply;
            rc = solaris_buffer_allocate(solaris_executor_budget(tun->scope.owner), length, &reply);
            if (rc == SOLARIS_OK) {
                uint8_t *p = solaris_buffer_mutable_data(reply); memcpy(p, packet, length);
                p[ip.transport_offset] = ip.protocol == SOLARIS_IP_ICMP ? 0u : 129u;
                rc = solaris_ip_rewrite(p, length, &ip.destination, &ip.source);
                if (rc == SOLARIS_OK) rc = emit(tun, p, length);
                solaris_buffer_release(reply);
            }
        }
    }
    if ((rc == SOLARIS_EAGAIN || rc == SOLARIS_ENOMEM) && tun->stats.congested == congested)
        tun->stats.congested++;
    else if (rc == SOLARIS_ENOTSUP) tun->stats.unsupported++;
    return rc;
}
solaris_status_t solaris_tun_input(solaris_tun_t *tun, const uint8_t *packet, size_t length)
{
    if (!tun || !packet) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(tun->scope.owner)) return SOLARIS_ETHREAD;
    if (tun->scope.cancelled) return SOLARIS_ECLOSED;
    if (tun->input_active || tun->emitting) return SOLARIS_EBUSY;
    tun->input_active = 1;
    solaris_status_t rc = input_packet(tun, packet, length);
    tun->input_active = 0;
    return rc;
}
solaris_status_t solaris_tun_snapshot(solaris_tun_t *tun, solaris_tun_snapshot_t *out)
{
    if (!tun || !out) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(tun->scope.owner)) return SOLARIS_ETHREAD;
    *out = tun->stats; return SOLARIS_OK;
}
solaris_status_t solaris_tun_close(solaris_tun_t *tun)
{
    if (!tun) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(tun->scope.owner)) return SOLARIS_ETHREAD;
    close_with_status(tun, SOLARIS_OK); return SOLARIS_OK;
}
const char *solaris_tun_name(const solaris_tun_t *tun)
{
    if (!tun || !solaris_executor_is_owner(tun->scope.owner) || !tun->device) return NULL;
    return solaris_tun_device_name(tun->device);
}
