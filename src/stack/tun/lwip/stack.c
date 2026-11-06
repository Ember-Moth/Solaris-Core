#include "contracts/inbound/tun_stack.h"
#include "codec/ip/packet.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/ip.h"
#include "lwip/tcp.h"
#include "lwip/priv/tcp_priv.h"
#include <assert.h>
#include <stdatomic.h>
#include <string.h>
#include <uv.h>

/* Upstream NO_SYS has process-global PCB/netif state. Exactly one admitted
 * stack owns all calls, including timers, until its final close barrier. */
typedef struct lwip_stack lwip_stack_t;
typedef struct lwip_flow lwip_flow_t;
typedef struct flow_read { struct flow_read *next; solaris_buffer_t *buffer; } flow_read_t;
typedef struct flow_write {
    struct flow_write *next;
    solaris_slice_t slice;
    size_t offset;
    solaris_io_done_fn done;
    void *context;
    int shutdown;
} flow_write_t;
struct lwip_flow {
    solaris_stream_t stream;
    solaris_scope_t scope;
    solaris_deferred_t pump;
    lwip_flow_t *next;
    lwip_stack_t *stack;
    solaris_address_t source, destination;
    solaris_stream_callbacks_t callbacks;
    void *context;
    flow_read_t *read_head, *read_tail;
    flow_write_t *write_head, *write_tail;
    solaris_io_snapshot_t stats;
    uint64_t last_activity;
    size_t read_bytes;
    uint16_t port;
    solaris_status_t close_status;
    int established, accepted, opened, reading, peer_eof, eof_delivered;
    int shutdown_requested, closing, writable_requested, graceful, close_delivered;
};
struct lwip_stack {
    solaris_tun_stack_t public;
    solaris_tun_stack_options_t options;
    solaris_scope_t scope;
    solaris_deferred_t cleanup;
    solaris_deadline_t *timer;
    struct netif netif;
    struct tcp_pcb *listener;
    lwip_flow_t *flows;
    size_t flow_count;
    uint16_t next_port;
    solaris_status_t close_status;
    int accepted, closing, entropy_failed, netif_added, emitting;
};
static atomic_flag admitted = ATOMIC_FLAG_INIT;
static lwip_stack_t *active;
static void flow_schedule(lwip_flow_t *flow);
static void flow_close(lwip_flow_t *flow, solaris_status_t status);
static void stack_close_status(lwip_stack_t *stack, solaris_status_t status);

void *solaris_lwip_allocate(size_t size)
{
    assert(active != NULL && solaris_executor_is_owner(active->options.owner));
    return solaris_memory_allocate(solaris_executor_budget(active->options.owner), size);
}
void *solaris_lwip_callocate(size_t count, size_t size)
{
    if (count != 0u && size > SIZE_MAX / count) return NULL;
    void *out = solaris_lwip_allocate(count * size);
    if (out != NULL) memset(out, 0, count * size);
    return out;
}
void solaris_lwip_deallocate(void *pointer) { solaris_memory_free(pointer); }
uint32_t solaris_lwip_random(void)
{
    uint32_t value = 0u;
    assert(active != NULL && solaris_executor_is_owner(active->options.owner));
    if (uv_random(NULL, NULL, &value, sizeof(value), 0u, NULL) != 0) active->entropy_failed = 1;
    return value;
}
u32_t solaris_lwip_now(void)
{
    assert(active != NULL && solaris_executor_is_owner(active->options.owner));
    return (u32_t)(solaris_executor_now_ns(active->options.owner) / UINT64_C(1000000));
}
void solaris_lwip_timer_needed(void) { /* The owner runs tcp_tmr every 250 ms. */ }
static int pcb_matches(const struct tcp_pcb *pcb, const lwip_flow_t *flow)
{
    return pcb->remote_port == flow->port && pcb->local_port == 443u &&
        (IP_IS_V6(&pcb->remote_ip) != 0) == (flow->source.family == SOLARIS_ADDRESS_IPV6);
}
static struct tcp_pcb *flow_pcb(const lwip_flow_t *flow)
{
    for (struct tcp_pcb *pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next)
        if (pcb_matches(pcb, flow)) return pcb;
    return NULL;
}
static struct tcp_pcb *flow_any_pcb(const lwip_flow_t *flow)
{
    struct tcp_pcb *pcb = flow_pcb(flow);
    if (pcb == NULL) for (pcb = tcp_tw_pcbs; pcb != NULL; pcb = pcb->next) if (pcb_matches(pcb, flow)) break;
    return pcb;
}
static void flow_abort(lwip_flow_t *flow)
{
    struct tcp_pcb *pcb = flow_any_pcb(flow);
    if (pcb != NULL) { tcp_arg(pcb, NULL); tcp_err(pcb, NULL); tcp_abort(pcb); }
}
static void internal_address(uint32_t family, int peer, uint16_t port, solaris_address_t *out)
{
    memset(out, 0, sizeof(*out)); out->family = family; out->port = port;
    if (family == SOLARIS_ADDRESS_IPV4) { out->ip[0] = 198u; out->ip[1] = 18u; out->ip[3] = peer ? 2u : 1u; }
    else { out->ip[0] = 0xfdu; out->ip[15] = peer ? 2u : 1u; }
}
static err_t emit_packet(struct netif *netif, struct pbuf *p)
{
    lwip_stack_t *stack = netif->state;
    if (stack->closing || stack->entropy_failed) return ERR_IF;
    solaris_buffer_t *buffer = NULL;
    if (solaris_buffer_allocate(solaris_executor_budget(stack->options.owner), p->tot_len, &buffer) != SOLARIS_OK) return ERR_MEM;
    uint8_t *bytes = solaris_buffer_mutable_data(buffer);
    pbuf_copy_partial(p, bytes, p->tot_len, 0u);
    solaris_ip_packet_t parsed = {0};
    solaris_status_t rc = solaris_ip_parse(bytes, p->tot_len, 0, &parsed);
    lwip_flow_t *flow = stack->flows;
    while (flow != NULL && (flow->port != parsed.destination.port || flow->source.family != parsed.destination.family)) flow = flow->next;
    if (rc == SOLARIS_OK && parsed.protocol == SOLARIS_IP_TCP && flow != NULL) {
        rc = solaris_ip_rewrite(bytes, p->tot_len, &flow->destination, &flow->source);
        if (rc == SOLARIS_OK) {
            stack->emitting = 1;
            rc = stack->options.emit(stack->options.context, bytes, p->tot_len);
            stack->emitting = 0;
        }
    } else rc = SOLARIS_EINVAL;
    solaris_buffer_release(buffer);
    return rc == SOLARIS_OK ? ERR_OK : rc == SOLARIS_EAGAIN || rc == SOLARIS_ENOMEM ? ERR_MEM : ERR_IF;
}
static err_t output4(struct netif *netif, struct pbuf *p, const ip4_addr_t *destination)
{ (void)destination; return emit_packet(netif, p); }
static err_t output6(struct netif *netif, struct pbuf *p, const ip6_addr_t *destination)
{ (void)destination; return emit_packet(netif, p); }
static err_t init_netif(struct netif *netif)
{
    lwip_stack_t *stack = netif->state;
    netif->name[0] = 's'; netif->name[1] = 'l'; netif->mtu = (u16_t)stack->options.mtu;
    netif->output = output4; netif->output_ip6 = output6;
    netif->flags = NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;
    return ERR_OK;
}
static void flow_done(void *context)
{
    lwip_flow_t *flow = context; lwip_stack_t *stack = flow->stack;
    lwip_flow_t **link = &stack->flows;
    while (*link != flow) link = &(*link)->next;
    *link = flow->next; stack->flow_count--;
    assert(flow->write_head == NULL && flow->read_head == NULL);
    if (flow->accepted && !flow->close_delivered) flow->callbacks.on_close(flow->context, &flow->stream, flow->close_status);
    solaris_memory_free(flow); solaris_scope_release(&stack->scope);
}
static void flow_cancel(void *context)
{
    lwip_flow_t *flow = context;
    if (!flow->closing) { flow->closing = 1; flow->close_status = SOLARIS_ECANCELLED; }
    flow->graceful = 0; flow_schedule(flow);
}
static void flow_close(lwip_flow_t *flow, solaris_status_t status)
{
    if (flow->closing && !flow->graceful) return;
    flow->closing = 1; flow->graceful = 0; flow->close_status = status;
    solaris_scope_cancel(&flow->scope);
}
static void complete_write(lwip_flow_t *flow, solaris_status_t status)
{
    flow_write_t *request = flow->write_head;
    flow->write_head = request->next; if (flow->write_head == NULL) flow->write_tail = NULL;
    flow->stats.pending_requests--; flow->stats.pending_bytes -= request->slice.length;
    solaris_buffer_release(request->slice.buffer);
    solaris_io_done_fn done = request->done; void *context = request->context;
    solaris_memory_free(request); done(context, status);
}
static void flow_pump(void *context)
{
    lwip_flow_t *flow = context; lwip_stack_t *stack = flow->stack;
    if (stack->closing && (!flow->closing || flow->graceful)) flow_close(flow, SOLARIS_ECANCELLED);
    if (!flow->closing && flow->established && !flow->accepted) {
        solaris_status_t rc = stack->options.accept(stack->options.context, &flow->source, &flow->destination,
            &flow->callbacks, &flow->context);
        if (rc != SOLARIS_OK || flow->callbacks.on_open == NULL || flow->callbacks.on_data == NULL || flow->callbacks.on_close == NULL)
            flow_close(flow, rc == SOLARIS_OK ? SOLARIS_EINVAL : rc);
        else { flow->accepted = 1; flow_schedule(flow); }
        solaris_scope_release(&flow->scope); return;
    }
    if (flow->accepted && !flow->opened) {
        flow->opened = 1;
        flow->callbacks.on_open(flow->context, &flow->stream, flow->closing ?
            (flow->close_status == SOLARIS_OK ? SOLARIS_ECANCELLED : flow->close_status) : SOLARIS_OK);
    }
    if (flow->graceful) {
        /* The application has observed both half-closes. tcp_close transfers
         * the remaining ACK/retransmission work to lwIP; the tuple remains
         * alive independently of the expired stream handle through TIME_WAIT. */
        struct tcp_pcb *pcb = flow_pcb(flow);
        err_t err = pcb != NULL ? tcp_close(pcb) : ERR_OK;
        if (err == ERR_OK && !flow->close_delivered) {
            flow->close_delivered = 1;
            flow->callbacks.on_close(flow->context, &flow->stream, SOLARIS_OK);
        } else if (err != ERR_OK && err != ERR_MEM) flow_close(flow, SOLARIS_EIO);
        if (flow->graceful && flow_any_pcb(flow) == NULL) flow_close(flow, SOLARIS_OK);
        solaris_scope_release(&flow->scope); return;
    }
    if (flow->closing) {
        flow_abort(flow);
        while (flow->write_head != NULL) complete_write(flow, SOLARIS_ECANCELLED);
        while (flow->read_head != NULL) {
            flow_read_t *read = flow->read_head; flow->read_head = read->next;
            solaris_buffer_release(read->buffer); solaris_memory_free(read);
        }
        flow->read_tail = NULL; flow->read_bytes = 0u;
        solaris_scope_release(&flow->scope); return;
    }
    while (flow->reading && flow->read_head != NULL && !flow->closing && !stack->closing) {
        flow_read_t *read = flow->read_head; flow->read_head = read->next;
        if (flow->read_head == NULL) flow->read_tail = NULL;
        size_t length = solaris_buffer_length(read->buffer); flow->read_bytes -= length;
        struct tcp_pcb *pcb = flow_pcb(flow); if (pcb != NULL) tcp_recved(pcb, (u16_t)length);
        flow->stats.bytes_read += length;
        flow->callbacks.on_data(flow->context, &flow->stream, read->buffer);
        solaris_buffer_release(read->buffer); solaris_memory_free(read);
    }
    if (flow->reading && flow->peer_eof && !flow->eof_delivered && flow->read_head == NULL && !flow->closing && !stack->closing) {
        flow->eof_delivered = 1; flow->stats.read_eof = 1u;
        if (flow->callbacks.on_eof != NULL) flow->callbacks.on_eof(flow->context, &flow->stream);
    }
    while (flow->write_head != NULL && !flow->closing && !stack->closing) {
        flow_write_t *request = flow->write_head; struct tcp_pcb *pcb = flow_pcb(flow);
        if (pcb == NULL) { complete_write(flow, SOLARIS_ECLOSED); continue; }
        if (request->shutdown) {
            err_t err = tcp_shutdown(pcb, 0, 1);
            if (err == ERR_MEM) break;
            if (err != ERR_OK) { flow_close(flow, SOLARIS_EIO); break; }
            flow->stats.write_shutdown = 1u; (void)tcp_output(pcb); complete_write(flow, SOLARIS_OK);
        } else {
            size_t length = request->slice.length - request->offset;
            if (length > tcp_sndbuf(pcb)) length = tcp_sndbuf(pcb);
            if (length > UINT16_MAX) length = UINT16_MAX;
            if (length == 0u && request->offset != request->slice.length) break;
            if (length != 0u) {
                err_t err = tcp_write(pcb, solaris_buffer_data(request->slice.buffer) + request->slice.offset + request->offset,
                    (u16_t)length, TCP_WRITE_FLAG_COPY);
                if (err == ERR_MEM) break;
                if (err != ERR_OK) { flow_close(flow, SOLARIS_EIO); break; }
                request->offset += length; flow->stats.bytes_written += length;
                (void)tcp_output(pcb);
            }
            if (request->offset != request->slice.length) break;
            complete_write(flow, SOLARIS_OK);
        }
    }
    if (!flow->closing && !stack->closing && flow->writable_requested && flow->stats.pending_bytes < stack->options.pending_byte_limit) {
        flow->writable_requested = 0;
        if (flow->callbacks.on_writable != NULL) flow->callbacks.on_writable(flow->context, &flow->stream);
    }
    if (stack->entropy_failed) stack_close_status(stack, SOLARIS_EIO);
    if (stack->closing && (!flow->closing || flow->graceful)) flow_close(flow, SOLARIS_ECANCELLED);
    solaris_scope_release(&flow->scope);
}
static void flow_schedule(lwip_flow_t *flow)
{
    if (flow->pump.queued) return;
    solaris_scope_retain(&flow->scope);
    solaris_status_t rc = solaris_executor_defer(flow->scope.owner, &flow->pump);
    assert(rc == SOLARIS_OK); (void)rc;
}
static solaris_status_t write_stream(void *state, const solaris_slice_t *slice, solaris_io_done_fn done, void *context)
{
    lwip_flow_t *flow = state;
    if (flow->closing || flow->stack->closing || flow->shutdown_requested) return SOLARIS_ECLOSED;
    size_t limit = flow->stack->options.pending_byte_limit;
    if (slice->length > limit) return SOLARIS_EMSGSIZE;
    if (flow->stats.pending_bytes > limit - slice->length || flow->stats.pending_requests >= 256u) {
        flow->writable_requested = 1; return SOLARIS_EAGAIN;
    }
    flow_write_t *request = solaris_memory_allocate(solaris_executor_budget(flow->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request)); request->slice = *slice; request->done = done; request->context = context;
    solaris_buffer_retain(slice->buffer);
    if (flow->write_tail != NULL) flow->write_tail->next = request; else flow->write_head = request;
    flow->write_tail = request; flow->stats.pending_bytes += slice->length; flow->stats.pending_requests++;
    flow->last_activity = solaris_executor_now_ns(flow->scope.owner); flow_schedule(flow); return SOLARIS_OK;
}
static solaris_status_t shutdown_stream(void *state, solaris_io_done_fn done, void *context)
{
    lwip_flow_t *flow = state;
    if (flow->closing || flow->stack->closing || flow->shutdown_requested) return SOLARIS_ECLOSED;
    flow_write_t *request = solaris_memory_allocate(solaris_executor_budget(flow->scope.owner), sizeof(*request));
    if (request == NULL) return SOLARIS_ENOMEM;
    memset(request, 0, sizeof(*request)); request->done = done; request->context = context; request->shutdown = 1;
    if (flow->write_tail != NULL) flow->write_tail->next = request; else flow->write_head = request;
    flow->write_tail = request; flow->stats.pending_requests++; flow->shutdown_requested = 1;
    flow_schedule(flow); return SOLARIS_OK;
}
static solaris_status_t reading_stream(void *state, int enabled)
{
    lwip_flow_t *flow = state; if (flow->closing || flow->stack->closing) return SOLARIS_ECLOSED;
    flow->reading = enabled; if (enabled) flow_schedule(flow); return SOLARIS_OK;
}
static solaris_status_t close_stream(void *state)
{
    lwip_flow_t *flow = state;
    if (flow->closing) return SOLARIS_OK;
    if (!flow->stack->closing && flow->eof_delivered && flow->stats.write_shutdown &&
        flow->write_head == NULL && flow->read_head == NULL) {
        flow->closing = 1; flow->graceful = 1; flow_schedule(flow);
    } else flow_close(flow, SOLARIS_OK);
    return SOLARIS_OK;
}
static solaris_status_t snapshot_stream(void *state, solaris_io_snapshot_t *out) { *out = ((lwip_flow_t *)state)->stats; return SOLARIS_OK; }
static const solaris_stream_ops_t stream_ops = {
    .write = write_stream, .shutdown_write = shutdown_stream, .set_reading = reading_stream,
    .close = close_stream, .snapshot = snapshot_stream
};
static err_t receive_tcp(void *context, struct tcp_pcb *pcb, struct pbuf *p, err_t status)
{
    lwip_flow_t *flow = context; (void)pcb;
    if (p == NULL) { flow->peer_eof = 1; flow_schedule(flow); return ERR_OK; }
    if (status != ERR_OK || flow->closing) { pbuf_free(p); return ERR_OK; }
    if (p->tot_len > flow->stack->options.pending_byte_limit - flow->read_bytes) return ERR_MEM;
    flow_read_t *read = solaris_memory_allocate(solaris_executor_budget(flow->scope.owner), sizeof(*read));
    if (read == NULL) return ERR_MEM;
    solaris_status_t rc = solaris_buffer_allocate(solaris_executor_budget(flow->scope.owner), p->tot_len, &read->buffer);
    if (rc != SOLARIS_OK) { solaris_memory_free(read); return ERR_MEM; }
    pbuf_copy_partial(p, solaris_buffer_mutable_data(read->buffer), p->tot_len, 0u);
    (void)solaris_buffer_set_length(read->buffer, p->tot_len); read->next = NULL;
    if (flow->read_tail != NULL) flow->read_tail->next = read; else flow->read_head = read;
    flow->read_tail = read; flow->read_bytes += p->tot_len; pbuf_free(p);
    flow_schedule(flow); return ERR_OK;
}
static err_t sent_tcp(void *context, struct tcp_pcb *pcb, u16_t length)
{ (void)pcb; (void)length; flow_schedule(context); return ERR_OK; }
static err_t poll_tcp(void *context, struct tcp_pcb *pcb)
{ (void)pcb; flow_schedule(context); return ERR_OK; }
static void error_tcp(void *context, err_t status)
{
    if (context == NULL) return;
    lwip_flow_t *flow = context;
    if (status == ERR_CLSD) { flow->peer_eof = 1; flow_schedule(flow); }
    else flow_close(flow, status == ERR_RST ? SOLARIS_ECLOSED : SOLARIS_EIO);
}
static err_t accept_tcp(void *context, struct tcp_pcb *pcb, err_t status)
{
    lwip_stack_t *stack = context; lwip_flow_t *flow = stack->flows;
    while (flow != NULL && !pcb_matches(pcb, flow)) flow = flow->next;
    if (status != ERR_OK || flow == NULL || flow->closing || stack->closing) { tcp_abort(pcb); return ERR_ABRT; }
    flow->established = 1; tcp_arg(pcb, flow); tcp_recv(pcb, receive_tcp); tcp_sent(pcb, sent_tcp);
    tcp_err(pcb, error_tcp); tcp_poll(pcb, poll_tcp, 2u); tcp_nagle_disable(pcb); flow_schedule(flow); return ERR_OK;
}
static void cleanup_stack(void *context)
{
    lwip_stack_t *stack = context;
    for (lwip_flow_t *flow = stack->flows; flow != NULL; flow = flow->next) flow_close(flow, SOLARIS_ECANCELLED);
    if (stack->listener != NULL) { tcp_arg(stack->listener, NULL); (void)tcp_close(stack->listener); stack->listener = NULL; }
    while (tcp_active_pcbs != NULL) tcp_abort(tcp_active_pcbs);
    while (tcp_tw_pcbs != NULL) tcp_abort(tcp_tw_pcbs);
    while (tcp_bound_pcbs != NULL) tcp_abort(tcp_bound_pcbs);
    if (stack->netif_added) { netif_remove(&stack->netif); stack->netif_added = 0; }
    solaris_scope_release(&stack->scope);
}
static void cancel_stack(void *context)
{
    lwip_stack_t *stack = context;
    if (!stack->closing) { stack->closing = 1; stack->close_status = SOLARIS_ECANCELLED; }
    if (stack->timer != NULL) solaris_deadline_cancel(stack->timer);
    if (!stack->cleanup.queued) {
        solaris_scope_retain(&stack->scope);
        solaris_status_t rc = solaris_executor_defer(stack->scope.owner, &stack->cleanup); assert(rc == SOLARIS_OK); (void)rc;
    }
}
static void done_stack(void *context)
{
    lwip_stack_t *stack = context;
    assert(stack->flows == NULL && stack->timer == NULL && tcp_active_pcbs == NULL && tcp_tw_pcbs == NULL);
    active = NULL; atomic_flag_clear_explicit(&admitted, memory_order_release);
    if (stack->accepted) stack->options.on_close(stack->options.context, stack->close_status);
    solaris_memory_free(stack);
}
static void stack_close_status(lwip_stack_t *stack, solaris_status_t status)
{
    if (stack->closing) return;
    stack->closing = 1; stack->close_status = status; solaris_scope_cancel(&stack->scope);
}
static void close_stack(void *state)
{
    lwip_stack_t *stack = state;
    if (solaris_executor_is_owner(stack->options.owner)) stack_close_status(stack, SOLARIS_OK);
}
static void timer_tick(void *context, solaris_status_t status)
{
    lwip_stack_t *stack = context; stack->timer = NULL;
    if (status == SOLARIS_OK && !stack->closing) {
        tcp_tmr();
        uint64_t now = solaris_executor_now_ns(stack->options.owner);
        for (lwip_flow_t *flow = stack->flows; flow != NULL; flow = flow->next) {
            if (flow->graceful) {
                if (flow_any_pcb(flow) == NULL) flow_close(flow, SOLARIS_OK);
                else if (!flow->close_delivered) flow_schedule(flow);
            } else if (now >= flow->last_activity && now - flow->last_activity >= stack->options.idle_timeout_ms * UINT64_C(1000000))
                flow_close(flow, SOLARIS_ETIMEDOUT);
        }
        if (stack->entropy_failed) stack_close_status(stack, SOLARIS_EIO);
        if (!stack->closing) {
            solaris_status_t rc = solaris_deadline_start(stack->options.owner, 250u, timer_tick, stack, &stack->timer);
            if (rc == SOLARIS_OK) solaris_scope_retain(&stack->scope); else stack_close_status(stack, rc);
        }
    }
    solaris_scope_release(&stack->scope);
}
static solaris_status_t input_stack(void *state, const uint8_t *packet, size_t length)
{
    lwip_stack_t *stack = state;
    if (!solaris_executor_is_owner(stack->options.owner)) return SOLARIS_ETHREAD;
    if (stack->closing) return SOLARIS_ECLOSED;
    if (stack->emitting) return SOLARIS_EBUSY;
    if (length > stack->options.mtu || length > UINT16_MAX) return SOLARIS_EMSGSIZE;
    solaris_ip_packet_t parsed; solaris_status_t rc = solaris_ip_parse(packet, length, 1, &parsed);
    if (rc != SOLARIS_OK) return rc;
    if (parsed.protocol != SOLARIS_IP_TCP ||
        (parsed.source.family == SOLARIS_ADDRESS_IPV4 ? stack->options.address4.family == 0u : stack->options.address6.family == 0u)) return SOLARIS_ENOTSUP;
    int created = 0; lwip_flow_t *flow = stack->flows;
    while (flow != NULL && (!solaris_address_equal(&flow->source, &parsed.source) || !solaris_address_equal(&flow->destination, &parsed.destination))) flow = flow->next;
    if (flow == NULL) {
        if ((parsed.tcp_flags & 0x17u) != 0x02u) return SOLARIS_EINVAL;
        if (stack->flow_count >= stack->options.flow_limit) return SOLARIS_EAGAIN;
        flow = solaris_memory_allocate(solaris_executor_budget(stack->options.owner), sizeof(*flow));
        if (flow == NULL) return SOLARIS_ENOMEM;
        memset(flow, 0, sizeof(*flow)); flow->stack = stack; flow->source = parsed.source; flow->destination = parsed.destination;
        flow->stream = (solaris_stream_t){&stream_ops, flow, stack->options.owner}; flow->pump.run = flow_pump; flow->pump.context = flow;
        flow->stats.max_message_bytes = stack->options.pending_byte_limit;
        rc = solaris_scope_init(&flow->scope, stack->options.owner, flow_cancel, flow_done, flow);
        if (rc != SOLARIS_OK) { solaris_memory_free(flow); return rc; }
        for (;;) {
            if (++stack->next_port < 1024u) stack->next_port = 1024u;
            lwip_flow_t *other = stack->flows; while (other != NULL && other->port != stack->next_port) other = other->next;
            if (other == NULL) { flow->port = stack->next_port; break; }
        }
        flow->next = stack->flows; stack->flows = flow; stack->flow_count++; solaris_scope_retain(&stack->scope); created = 1;
    }
    if (flow->closing && !flow->graceful) return SOLARIS_ECLOSED;
    /* A closed stream still owns its TCP tombstone until lwIP finishes. */
    if (flow->graceful && (parsed.tcp_flags & 0x02u) != 0u) return SOLARIS_EAGAIN;
    flow->last_activity = solaris_executor_now_ns(stack->options.owner);
    struct pbuf *p = pbuf_alloc(PBUF_RAW, (u16_t)length, PBUF_RAM);
    if (p == NULL) { if (created) flow_close(flow, SOLARIS_ENOMEM); return SOLARIS_ENOMEM; }
    assert(p->len == p->tot_len); memcpy(p->payload, packet, length);
    solaris_address_t source, destination;
    internal_address(parsed.source.family, 1, flow->port, &source); internal_address(parsed.source.family, 0, 443u, &destination);
    rc = solaris_ip_rewrite(p->payload, length, &source, &destination);
    if (rc != SOLARIS_OK) { pbuf_free(p); return rc; }
    err_t err = ip_input(p, &stack->netif);
    if (err != ERR_OK) pbuf_free(p);
    if (stack->entropy_failed) { stack_close_status(stack, SOLARIS_EIO); return SOLARIS_EIO; }
    return err == ERR_OK ? SOLARIS_OK : SOLARIS_EIO;
}
static const solaris_tun_stack_ops_t stack_ops = {.input = input_stack, .close = close_stack};
solaris_status_t solaris_tun_lwip_create(const solaris_tun_stack_options_t *options, solaris_tun_stack_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (options == NULL || options->owner == NULL || options->emit == NULL || options->accept == NULL || options->on_close == NULL ||
        (options->address4.family != 0u && options->address4.family != SOLARIS_ADDRESS_IPV4) ||
        (options->address6.family != 0u && options->address6.family != SOLARIS_ADDRESS_IPV6) ||
        (options->address4.family == 0u && options->address6.family == 0u)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(options->owner)) return SOLARIS_ETHREAD;
    lwip_stack_t *stack = solaris_memory_allocate(solaris_executor_budget(options->owner), sizeof(*stack));
    if (stack == NULL) return SOLARIS_ENOMEM;
    memset(stack, 0, sizeof(*stack)); stack->options = *options;
    if (stack->options.mtu == 0u) stack->options.mtu = 1500u;
    if (stack->options.flow_limit == 0u) stack->options.flow_limit = 1024u;
    if (stack->options.pending_byte_limit == 0u) stack->options.pending_byte_limit = 65536u;
    if (stack->options.idle_timeout_ms == 0u) stack->options.idle_timeout_ms = 120000u;
    if (stack->options.mtu < 1280u || stack->options.mtu > UINT16_MAX || stack->options.flow_limit > 60000u ||
        stack->options.pending_byte_limit < TCP_WND || stack->options.pending_byte_limit > 16u * 1024u * 1024u ||
        stack->options.idle_timeout_ms > UINT64_MAX / UINT64_C(1000000)) { solaris_memory_free(stack); return SOLARIS_EINVAL; }
    if (atomic_flag_test_and_set_explicit(&admitted, memory_order_acquire)) { solaris_memory_free(stack); return SOLARIS_EBUSY; }
    active = stack; stack->public = (solaris_tun_stack_t){&stack_ops, stack}; stack->cleanup.run = cleanup_stack; stack->cleanup.context = stack;
    solaris_status_t rc = solaris_scope_init(&stack->scope, options->owner, cancel_stack, done_stack, stack);
    if (rc != SOLARIS_OK) { active = NULL; atomic_flag_clear_explicit(&admitted, memory_order_release); solaris_memory_free(stack); return rc; }
    lwip_init();
    ip4_addr_t address4, mask, gateway; IP4_ADDR(&address4, 198u, 18u, 0u, 1u); IP4_ADDR(&mask, 255u, 255u, 255u, 252u); ip4_addr_set_zero(&gateway);
    if (netif_add(&stack->netif, &address4, &mask, &gateway, stack, init_netif, ip_input) == NULL) { stack_close_status(stack, SOLARIS_ENOMEM); return SOLARIS_ENOMEM; }
    stack->netif_added = 1; netif_set_default(&stack->netif); netif_set_up(&stack->netif); netif_set_link_up(&stack->netif);
    ip6_addr_t address6; IP6_ADDR(&address6, PP_HTONL(0xfd000000u), 0u, 0u, PP_HTONL(1u));
    netif_ip6_addr_set(&stack->netif, 0, &address6); netif_ip6_addr_set_state(&stack->netif, 0, IP6_ADDR_PREFERRED);
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (pcb == NULL) { stack_close_status(stack, SOLARIS_ENOMEM); return SOLARIS_ENOMEM; }
    err_t err = tcp_bind(pcb, IP_ANY_TYPE, 443u);
    if (err == ERR_OK) { stack->listener = tcp_listen_with_backlog(pcb, 255u); if (stack->listener == NULL) err = ERR_MEM; }
    if (err != ERR_OK) { tcp_abort(pcb); stack_close_status(stack, SOLARIS_ENOMEM); return SOLARIS_ENOMEM; }
    tcp_arg(stack->listener, stack); tcp_accept(stack->listener, accept_tcp);
    if (stack->entropy_failed) { stack_close_status(stack, SOLARIS_EIO); return SOLARIS_EIO; }
    rc = solaris_deadline_start(options->owner, 250u, timer_tick, stack, &stack->timer);
    if (rc != SOLARIS_OK) { stack_close_status(stack, rc); return rc; }
    solaris_scope_retain(&stack->scope); stack->accepted = 1; *out = &stack->public; return SOLARIS_OK;
}
