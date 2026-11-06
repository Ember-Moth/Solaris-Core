#include "stack/tun/system/stack.h"
#include "codec/ip/packet.h"
#include "transport/socket/tcp.h"
#include <assert.h>
#include <limits.h>
#include <string.h>

#define SYSTEM_PORT_MIN 1024u
#define SYSTEM_PORT_COUNT (65536u - SYSTEM_PORT_MIN)
#define SYSTEM_QUARANTINE_NS UINT64_C(120000000000)
enum { ENTRY_FREE, ENTRY_PENDING, ENTRY_ACCEPTED, ENTRY_CLOSING, ENTRY_DRAINING };
typedef struct system_stack system_stack_t;
typedef struct system_port { uint64_t available_ns; uint32_t owner; } system_port_t;
typedef struct system_family {
    system_stack_t *stack;
    solaris_tcp_listener_t *listener;
    solaris_address_t local, peer;
    system_port_t *ports;
    uint16_t next_port;
} system_family_t;
typedef struct system_child system_child_t;
typedef struct system_entry {
    system_stack_t *stack;
    system_family_t *family;
    solaris_address_t source, destination;
    system_child_t *child;
    uint64_t expires_ns, generation;
    uint32_t initial_sequence;
    uint16_t port;
    uint8_t state;
} system_entry_t;
struct system_child {
    system_child_t *previous, *next;
    system_stack_t *stack;
    system_entry_t *entry;
    solaris_stream_t *stream;
    solaris_stream_callbacks_t callbacks;
    void *context;
    uint64_t generation;
    solaris_status_t close_status;
};
struct system_stack {
    solaris_tun_stack_t stack;
    solaris_scope_t scope;
    solaris_tun_stack_options_t options;
    solaris_tun_system_services_t services;
    system_child_t *children;
    system_family_t ipv4, ipv6;
    system_entry_t *entries;
    solaris_deadline_t *timer;
    uint8_t *scratch;
    uint64_t generation;
    solaris_status_t status;
    int accepted, close_requested, processing;
};
static int same_ip(const solaris_address_t *a, const solaris_address_t *b)
{ return a->family == b->family && memcmp(a->ip, b->ip, a->family == SOLARIS_ADDRESS_IPV4 ? 4u : 16u) == 0; }
static uint64_t later(uint64_t now, uint64_t duration)
{ return duration > UINT64_MAX - now ? UINT64_MAX : now + duration; }
static uint64_t now_ns(system_stack_t *stack) { return solaris_executor_now_ns(stack->scope.owner); }
static void touch(system_entry_t *entry, uint64_t now)
{ entry->expires_ns = later(now, entry->stack->options.idle_timeout_ms * UINT64_C(1000000)); }
static void release_entry(system_entry_t *entry)
{
    assert(entry->child == NULL);
    system_port_t *port = &entry->family->ports[entry->port];
    assert(port->owner != 0u);
    port->owner = 0u; port->available_ns = later(now_ns(entry->stack), SYSTEM_QUARANTINE_NS);
    entry->state = ENTRY_FREE;
}
static void expire_entry(system_entry_t *entry, solaris_status_t status)
{
    if (entry->state == ENTRY_FREE || entry->state == ENTRY_CLOSING) return;
    if (entry->child != NULL) {
        entry->state = ENTRY_CLOSING; entry->child->close_status = status;
        if (entry->child->stream != NULL) (void)solaris_stream_close(entry->child->stream);
    } else release_entry(entry);
}
static void sweep(system_stack_t *stack, uint64_t now)
{
    for (size_t i = 0u; i < stack->options.flow_limit; ++i) {
        system_entry_t *entry = &stack->entries[i];
        if ((entry->state == ENTRY_PENDING || entry->state == ENTRY_ACCEPTED || entry->state == ENTRY_DRAINING) &&
            now >= entry->expires_ns)
            expire_entry(entry, SOLARIS_ETIMEDOUT);
    }
}
static void close_status(system_stack_t *stack, solaris_status_t status)
{
    if (stack->scope.cancelled) return;
    stack->close_requested = 1; stack->status = status; solaris_scope_cancel(&stack->scope);
}
static void cancelled(void *context)
{
    system_stack_t *stack = context;
    if (!stack->close_requested) stack->status = SOLARIS_ECANCELLED;
    if (stack->timer != NULL) solaris_deadline_cancel(stack->timer);
    if (stack->ipv4.listener != NULL) solaris_tcp_listener_close(stack->ipv4.listener);
    if (stack->ipv6.listener != NULL) solaris_tcp_listener_close(stack->ipv6.listener);
    for (size_t i = 0u; i < stack->options.flow_limit; ++i)
        expire_entry(&stack->entries[i], stack->status);
    for (system_child_t *child = stack->children; child != NULL; child = child->next)
        if (child->stream != NULL) (void)solaris_stream_close(child->stream);
}
static void destroyed(void *context)
{
    system_stack_t *stack = context;
    assert(stack->ipv4.listener == NULL && stack->ipv6.listener == NULL && stack->timer == NULL && stack->children == NULL);
    if (stack->accepted) stack->options.on_close(stack->options.context, stack->status);
    solaris_memory_free(stack->ipv4.ports); solaris_memory_free(stack->ipv6.ports);
    solaris_memory_free(stack->entries); solaris_memory_free(stack->scratch); solaris_memory_free(stack);
}
static solaris_status_t schedule_timer(system_stack_t *stack);
static void timer(void *context, solaris_status_t status)
{
    system_stack_t *stack = context; stack->timer = NULL;
    if (status == SOLARIS_OK && !stack->scope.cancelled) {
        sweep(stack, now_ns(stack));
        solaris_status_t rc = schedule_timer(stack);
        if (rc != SOLARIS_OK) close_status(stack, rc);
    }
    solaris_scope_release(&stack->scope);
}
static solaris_status_t schedule_timer(system_stack_t *stack)
{
    uint64_t delay = stack->options.idle_timeout_ms;
    if (delay > 1000u) delay = 1000u;
    solaris_scope_retain(&stack->scope);
    solaris_status_t rc = solaris_deadline_start(stack->scope.owner, delay, timer, stack, &stack->timer);
    if (rc != SOLARIS_OK) solaris_scope_release(&stack->scope);
    return rc;
}
static void child_unlink(system_child_t *child)
{
    system_stack_t *stack = child->stack;
    if (child->previous != NULL) child->previous->next = child->next;
    else stack->children = child->next;
    if (child->next != NULL) child->next->previous = child->previous;
    solaris_memory_free(child); solaris_scope_release(&stack->scope);
}
static int child_active(const system_child_t *child)
{ return !child->stack->scope.cancelled && child->entry != NULL && child->entry->state == ENTRY_ACCEPTED; }
static void child_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    system_child_t *child = context; assert(child->stream == stream);
    if (child->stack->scope.cancelled) status = child->stack->status == SOLARIS_OK ? SOLARIS_ECANCELLED : child->stack->status;
    else if (child->close_status != SOLARIS_OK) status = child->close_status;
    if (child->callbacks.on_open != NULL) child->callbacks.on_open(child->context, stream, status);
}
static void child_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    system_child_t *child = context; assert(child->stream == stream);
    if (!child_active(child)) return;
    touch(child->entry, now_ns(child->stack));
    if (child->callbacks.on_data != NULL) child->callbacks.on_data(child->context, stream, buffer);
}
static void child_eof(void *context, solaris_stream_t *stream)
{
    system_child_t *child = context; assert(child->stream == stream);
    if (child_active(child) && child->callbacks.on_eof != NULL) child->callbacks.on_eof(child->context, stream);
}
static void child_writable(void *context, solaris_stream_t *stream)
{
    system_child_t *child = context; assert(child->stream == stream);
    if (child_active(child) && child->callbacks.on_writable != NULL) child->callbacks.on_writable(child->context, stream);
}
static void child_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    system_child_t *child = context; assert(child->stream == stream);
    if (child->close_status != SOLARIS_OK) status = child->close_status;
    child->stream = NULL;
    if (child->entry != NULL) {
        system_entry_t *entry = child->entry;
        solaris_io_snapshot_t snapshot;
        int graceful = status == SOLARIS_OK && !child->stack->scope.cancelled &&
            solaris_stream_get_snapshot(stream, &snapshot) == SOLARIS_OK &&
            snapshot.read_eof && snapshot.write_shutdown;
        entry->child = NULL; child->entry = NULL;
        if (graceful) {
            /* Closing the userspace handle does not finish the OS TCP PCB.
             * Preserve both NAT directions for late ACKs and FIN/data retries.
             * A fixed bound prevents stray packets keeping the slot forever. */
            entry->state = ENTRY_DRAINING;
            entry->expires_ns = later(now_ns(child->stack), SYSTEM_QUARANTINE_NS);
        } else release_entry(entry);
    }
    if (child->callbacks.on_close != NULL) child->callbacks.on_close(child->context, stream, status);
    child_unlink(child);
}
static const solaris_stream_callbacks_t child_callbacks = {child_opened, child_data, child_eof, child_writable, child_closed};
static solaris_status_t accepted(void *context, const solaris_address_t *peer, const solaris_address_t *local,
    solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks, void **stream_context)
{
    system_family_t *family = context; system_stack_t *stack = family->stack;
    if (stack->scope.cancelled || !same_ip(peer, &family->peer) || !solaris_address_equal(local, &family->local) ||
        peer->port < SYSTEM_PORT_MIN) return SOLARIS_EACCESS;
    uint32_t owner = family->ports[peer->port].owner;
    if (owner == 0u) return SOLARIS_EACCESS;
    assert(owner <= stack->options.flow_limit);
    system_entry_t *entry = &stack->entries[owner - 1u];
    uint64_t now = now_ns(stack);
    if (entry->state != ENTRY_PENDING || entry->family != family || entry->port != peer->port) return SOLARIS_EACCESS;
    if (now >= entry->expires_ns) { expire_entry(entry, SOLARIS_ETIMEDOUT); return SOLARIS_EACCESS; }
    system_child_t *child = solaris_memory_allocate(solaris_executor_budget(stack->scope.owner), sizeof(*child));
    if (child == NULL) return SOLARIS_ENOMEM;
    memset(child, 0, sizeof(*child)); child->stack = stack; child->generation = entry->generation;
    child->next = stack->children; if (child->next != NULL) child->next->previous = child;
    stack->children = child; solaris_scope_retain(&stack->scope);
    /* Copy addresses: accept may close the stack or retire/reuse this slot. */
    solaris_address_t source = entry->source, destination = entry->destination;
    solaris_status_t rc = stack->options.accept(stack->options.context, &source, &destination,
        &child->callbacks, &child->context);
    if (rc != SOLARIS_OK) { child_unlink(child); return rc; }
    /* Success transfers callback/context ownership even if accept reentered
     * close or replaced the mapping. Such a child still gets open then close. */
    child->stream = stream;
    if (!stack->scope.cancelled && entry->state == ENTRY_PENDING && entry->generation == child->generation) {
        child->entry = entry; entry->child = child; entry->state = ENTRY_ACCEPTED; touch(entry, now_ns(stack));
    } else {
        child->close_status = SOLARIS_ECANCELLED; (void)solaris_stream_close(stream);
    }
    *callbacks = child_callbacks; *stream_context = child; return SOLARIS_OK;
}
static void listener_closed(void *context, solaris_status_t status)
{
    system_family_t *family = context; system_stack_t *stack = family->stack; family->listener = NULL;
    if (!stack->scope.cancelled) close_status(stack, status == SOLARIS_OK ? SOLARIS_EIO : status);
    solaris_scope_release(&stack->scope);
}
static solaris_status_t create_family(system_stack_t *stack, system_family_t *family,
    const solaris_address_t *local, const solaris_address_t *peer)
{
    family->stack = stack;
    if (local->family == 0u) return SOLARIS_OK;
    family->local = *local; family->local.port = 0u; family->peer = *peer; family->peer.port = 0u;
    family->next_port = 32768u;
    family->ports = solaris_memory_allocate(solaris_executor_budget(stack->scope.owner), 65536u * sizeof(*family->ports));
    if (family->ports == NULL) return SOLARIS_ENOMEM;
    memset(family->ports, 0, 65536u * sizeof(*family->ports));
    solaris_dialer_options_t options = {.pending_byte_limit = stack->options.pending_byte_limit, .pending_request_limit = 64u};
    solaris_status_t rc = stack->services.listen != NULL ?
        stack->services.listen(stack->services.context, stack->scope.owner, &family->local, &options,
            accepted, listener_closed, family, &family->listener, &family->local) :
        solaris_tcp_listener_open(stack->scope.owner, &family->local, &options,
            accepted, listener_closed, family, &family->listener, &family->local);
    if (rc == SOLARIS_OK) solaris_scope_retain(&stack->scope);
    return rc;
}
static int unicast(const solaris_address_t *address)
{
    if (address->scope_id != 0u) return 0;
    if (address->family == SOLARIS_ADDRESS_IPV4)
        return address->ip[0] != 0u && address->ip[0] < 224u &&
            !(address->ip[0] == 255u && address->ip[1] == 255u && address->ip[2] == 255u && address->ip[3] == 255u);
    if (address->family == SOLARIS_ADDRESS_IPV6) {
        int nonzero = 0; for (size_t i = 0u; i < 16u; ++i) nonzero |= address->ip[i] != 0u;
        return nonzero && address->ip[0] != 255u;
    }
    return 0;
}
static int valid_pair(const solaris_address_t *local, const solaris_address_t *peer, uint32_t family)
{
    if (local->family == 0u) return peer->family == 0u;
    return local->family == family && peer->family == family && unicast(local) && unicast(peer) && !same_ip(local, peer);
}
static system_entry_t *find_entry(system_stack_t *stack, const solaris_ip_packet_t *packet)
{
    for (size_t i = 0u; i < stack->options.flow_limit; ++i) {
        system_entry_t *entry = &stack->entries[i];
        if ((entry->state == ENTRY_PENDING || entry->state == ENTRY_ACCEPTED || entry->state == ENTRY_DRAINING) &&
            solaris_address_equal(&entry->source, &packet->source) && solaris_address_equal(&entry->destination, &packet->destination))
            return entry;
    }
    return NULL;
}
static solaris_status_t allocate_entry(system_stack_t *stack, system_family_t *family,
    const solaris_ip_packet_t *packet, uint32_t sequence, uint64_t now, system_entry_t **out)
{
    system_entry_t *entry = NULL; size_t slot;
    for (slot = 0u; slot < stack->options.flow_limit; ++slot)
        if (stack->entries[slot].state == ENTRY_FREE) { entry = &stack->entries[slot]; break; }
    if (entry == NULL) return SOLARIS_EAGAIN;
    if (stack->generation == UINT64_MAX) return SOLARIS_EOVERFLOW;
    for (size_t count = 0u; count < SYSTEM_PORT_COUNT; ++count) {
        uint16_t port = family->next_port;
        family->next_port = port == UINT16_MAX ? SYSTEM_PORT_MIN : (uint16_t)(port + 1u);
        system_port_t *candidate = &family->ports[port];
        if (candidate->owner != 0u || now < candidate->available_ns) continue;
        memset(entry, 0, sizeof(*entry)); entry->stack = stack; entry->family = family;
        entry->source = packet->source; entry->destination = packet->destination; entry->port = port;
        entry->generation = ++stack->generation; entry->initial_sequence = sequence; entry->state = ENTRY_PENDING;
        candidate->owner = (uint32_t)slot + 1u; touch(entry, now); *out = entry; return SOLARIS_OK;
    }
    return SOLARIS_EAGAIN;
}
static solaris_status_t input(void *context, const uint8_t *bytes, size_t size)
{
    system_stack_t *stack = context;
    if (!solaris_executor_is_owner(stack->scope.owner)) return SOLARIS_ETHREAD;
    if (stack->scope.cancelled || !solaris_executor_accepting(stack->scope.owner)) return SOLARIS_ECLOSED;
    if (stack->processing) return SOLARIS_EBUSY;
    if (size > stack->options.mtu) return SOLARIS_EMSGSIZE;
    solaris_ip_packet_t packet; solaris_status_t rc = solaris_ip_parse(bytes, size, 1, &packet);
    if (rc != SOLARIS_OK) return rc;
    if (packet.protocol != SOLARIS_IP_TCP) return SOLARIS_ENOTSUP;
    if (packet.source.port == 0u || packet.destination.port == 0u || packet.hop_limit == 0u ||
        !unicast(&packet.source) || !unicast(&packet.destination)) return SOLARIS_EINVAL;
    system_family_t *family = packet.source.family == SOLARIS_ADDRESS_IPV4 ? &stack->ipv4 : &stack->ipv6;
    if (family->listener == NULL) return SOLARIS_ENOTSUP;
    uint64_t now = now_ns(stack); sweep(stack, now);
    system_entry_t *entry = NULL; solaris_address_t source, destination; int created = 0;
    int reverse = solaris_address_equal(&packet.source, &family->local);
    if (reverse) {
        if (!same_ip(&packet.destination, &family->peer)) return SOLARIS_EACCESS;
        uint32_t owner = family->ports[packet.destination.port].owner;
        if (owner == 0u) return SOLARIS_EACCESS;
        entry = &stack->entries[owner - 1u];
        if (entry->state != ENTRY_PENDING && entry->state != ENTRY_ACCEPTED && entry->state != ENTRY_DRAINING)
            return SOLARIS_EACCESS;
        source = entry->destination; destination = entry->source;
    } else {
        if (same_ip(&packet.source, &family->peer) || same_ip(&packet.destination, &family->peer) ||
            solaris_address_equal(&packet.destination, &family->local)) return SOLARIS_EACCESS;
        entry = find_entry(stack, &packet);
        const uint8_t *tcp = bytes + packet.transport_offset;
        uint32_t sequence = ((uint32_t)tcp[4] << 24u) | ((uint32_t)tcp[5] << 16u) | ((uint32_t)tcp[6] << 8u) | tcp[7];
        int syn = (packet.tcp_flags & 0x17u) == 2u;
        if (entry == NULL) {
            if (!syn) return SOLARIS_EACCESS;
            rc = allocate_entry(stack, family, &packet, sequence, now, &entry);
            if (rc != SOLARIS_OK) return rc;
            created = 1;
        } else if (syn && (entry->state == ENTRY_DRAINING || sequence != entry->initial_sequence)) return SOLARIS_EBUSY;
        source = family->peer; source.port = entry->port; destination = family->local;
    }
    memcpy(stack->scratch, bytes, size);
    rc = solaris_ip_rewrite(stack->scratch, size, &source, &destination);
    if (rc == SOLARIS_OK) {
        stack->processing = 1; rc = stack->options.emit(stack->options.context, stack->scratch, size); stack->processing = 0;
    }
    if (created && rc != SOLARIS_OK && entry->state == ENTRY_PENDING) {
        /* Rejected emit owns nothing, so no kernel connection can exist. */
        family->ports[entry->port].owner = 0u; entry->state = ENTRY_FREE;
    } else if (rc == SOLARIS_OK && entry->state != ENTRY_FREE) {
        if (entry->state != ENTRY_DRAINING) touch(entry, now);
        /* Forward RST like any TCP segment. Its sequence validity belongs to
         * the OS TCP endpoint; an unverified flag must not close the stream
         * or discard a pending/draining NAT mapping. */
    }
    return rc;
}
static void close_stack(void *context)
{
    system_stack_t *stack = context; assert(solaris_executor_is_owner(stack->scope.owner)); close_status(stack, SOLARIS_OK);
}
static const solaris_tun_stack_ops_t operations = {input, close_stack};
solaris_status_t solaris_tun_system_create_with_services(const solaris_tun_stack_options_t *options,
    const solaris_tun_system_services_t *services, solaris_tun_stack_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (options == NULL || options->owner == NULL || options->emit == NULL || options->accept == NULL || options->on_close == NULL)
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(options->owner)) return SOLARIS_ETHREAD;
    if (options->include_all_networks) return SOLARIS_ENOTSUP;
    if (!valid_pair(&options->address4, &options->peer4, SOLARIS_ADDRESS_IPV4) ||
        !valid_pair(&options->address6, &options->peer6, SOLARIS_ADDRESS_IPV6) ||
        (options->address4.family == 0u && options->address6.family == 0u)) return SOLARIS_EINVAL;
    solaris_tun_stack_options_t selected = *options;
    if (selected.flow_limit == 0u) selected.flow_limit = 1024u;
    if (selected.mtu == 0u) selected.mtu = 1500u;
    if (selected.pending_byte_limit == 0u) selected.pending_byte_limit = 256u * 1024u;
    if (selected.idle_timeout_ms == 0u) selected.idle_timeout_ms = 60000u;
    if (selected.flow_limit > SYSTEM_PORT_COUNT || selected.mtu > UINT16_MAX || selected.mtu < 576u ||
        (selected.address6.family != 0u && selected.mtu < 1280u) || selected.pending_byte_limit > UINT_MAX ||
        selected.idle_timeout_ms > UINT64_MAX / UINT64_C(1000000)) return SOLARIS_EINVAL;
    solaris_budget_t *budget = solaris_executor_budget(options->owner);
    system_stack_t *stack = solaris_memory_allocate(budget, sizeof(*stack));
    if (stack == NULL) return SOLARIS_ENOMEM;
    memset(stack, 0, sizeof(*stack)); stack->options = selected;
    if (services != NULL) stack->services = *services;
    stack->stack = (solaris_tun_stack_t){&operations, stack};
    stack->entries = solaris_memory_allocate(budget, selected.flow_limit * sizeof(*stack->entries));
    stack->scratch = solaris_memory_allocate(budget, selected.mtu);
    if (stack->entries == NULL || stack->scratch == NULL) { destroyed(stack); return SOLARIS_ENOMEM; }
    memset(stack->entries, 0, selected.flow_limit * sizeof(*stack->entries));
    solaris_status_t rc = solaris_scope_init(&stack->scope, options->owner, cancelled, destroyed, stack);
    if (rc != SOLARIS_OK) { destroyed(stack); return rc; }
    rc = create_family(stack, &stack->ipv4, &selected.address4, &selected.peer4);
    if (rc == SOLARIS_OK) rc = create_family(stack, &stack->ipv6, &selected.address6, &selected.peer6);
    if (rc == SOLARIS_OK) rc = schedule_timer(stack);
    if (rc != SOLARIS_OK) { close_status(stack, rc); return rc; }
    stack->accepted = 1; *out = &stack->stack; return SOLARIS_OK;
}

solaris_status_t solaris_tun_system_create(const solaris_tun_stack_options_t *options, solaris_tun_stack_t **out)
{ return solaris_tun_system_create_with_services(options, NULL, out); }
