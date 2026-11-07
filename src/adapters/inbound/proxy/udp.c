#include "adapters/inbound/proxy/internal.h"
#include <string.h>

static proxy_connection_t *find_connection(solaris_proxy_inbound_t *in, const solaris_udp_key_t *key)
{
    for (proxy_connection_t *c = in->connections; c; c = c->next)
        if (c->id == key->client_id)
            return c;
    return NULL;
}
static solaris_status_t select_plan(void *context, solaris_executor_t *owner, const solaris_udp_key_t *key,
                                    const solaris_address_t *target, solaris_udp_plan_t *out)
{
    solaris_proxy_inbound_t *in = context;
    (void)owner;
    proxy_connection_t *c = find_connection(in, key);
    return c ? solaris_proxy_select(c, SOLARIS_INBOUND_UDP, target, out) : SOLARIS_ECLOSED;
}
static void association_closed(void *context, const solaris_udp_key_t *key, const solaris_udp_snapshot_t *snapshot,
                               solaris_status_t status)
{
    solaris_proxy_inbound_t *in = context;
    (void)status;
    proxy_connection_t *c = find_connection(in, key);
    if (c && c->association_id == snapshot->id) {
        c->associated = 0;
        c->association_id = 0;
    }
}
solaris_status_t solaris_proxy_udp_create(solaris_proxy_inbound_t *in)
{
    solaris_executor_t *owner = in->scope.owner;
    solaris_udp_dispatcher_options_t options = {.workers = &owner,
                                                .worker_count = 1,
                                                .budget = solaris_executor_budget(owner),
                                                .tracker = in->options.tracker,
                                                .association_limit = in->options.connection_limit,
                                                .mapping_limit = in->options.udp_mapping_limit,
                                                .pending_packet_limit = in->options.pending_packet_limit,
                                                .pending_byte_limit = in->options.pending_byte_limit,
                                                .idle_timeout_ms = in->options.idle_timeout_ms,
                                                .open_timeout_ms = in->options.handshake_timeout_ms,
                                                .context = in,
                                                .select = select_plan,
                                                .on_close = association_closed};
    return solaris_udp_dispatcher_create(&options, &in->udp);
}
static void retain(void *context)
{
    solaris_scope_retain(&((proxy_connection_t *)context)->scope);
}
static void release(void *context)
{
    solaris_scope_release(&((proxy_connection_t *)context)->scope);
}
static void sent(void *context, solaris_status_t status)
{
    proxy_connection_t *c = context;
    if (status != SOLARIS_OK)
        c->inbound->stats.udp_dropped++;
    solaris_scope_release(&c->scope);
}
static solaris_status_t reply(void *context, uint64_t generation, const solaris_udp_key_t *key,
                              const solaris_address_t *peer, const solaris_buffer_t *payload)
{
    proxy_connection_t *c = context;
    (void)key;
    if (c->scope.cancelled || !c->datagram || generation != c->id)
        return SOLARIS_ECLOSED;
    uint8_t header[262] = {0};
    size_t n;
    solaris_status_t rc = solaris_socks_address_write(peer, header + 3, sizeof(header) - 3, &n);
    if (rc != SOLARIS_OK)
        return rc;
    n += 3;
    size_t length = solaris_buffer_length(payload);
    if (length > 65507 - n)
        return SOLARIS_EMSGSIZE;
    solaris_buffer_t *packet;
    rc = solaris_buffer_allocate(solaris_executor_budget(c->scope.owner), n + length, &packet);
    if (rc != SOLARIS_OK)
        return rc;
    uint8_t *p = solaris_buffer_mutable_data(packet);
    memcpy(p, header, n);
    memcpy(p + n, solaris_buffer_data(payload), length);
    (void)solaris_buffer_set_length(packet, n + length);
    solaris_slice_t slice = {packet, 0, n + length};
    rc = solaris_datagram_send(c->datagram, &c->udp_peer, &slice, sent, c);
    if (rc == SOLARIS_OK) {
        solaris_scope_retain(&c->scope);
        c->activity_ns = solaris_executor_now_ns(c->scope.owner);
    }
    solaris_buffer_release(packet);
    return rc;
}
static void packet_received(void *context, solaris_datagram_t *datagram, const solaris_address_t *source,
                            const solaris_buffer_t *buffer)
{
    proxy_connection_t *c = context;
    (void)datagram;
    if (c->scope.cancelled)
        return;
    solaris_address_t expected = c->udp_peer;
    expected.port = source->port;
    const uint8_t *p = solaris_buffer_data(buffer);
    size_t size = solaris_buffer_length(buffer), used;
    solaris_address_t destination;
    if (c->state != PROXY_UDP || !solaris_address_equal(source, &expected) ||
        (c->udp_peer.port && c->udp_peer.port != source->port) || size < 4 || p[0] || p[1] || p[2] ||
        solaris_socks_address_read(p + 3, size - 3, &destination, &used) != SOLARIS_OK) {
        c->inbound->stats.udp_dropped++;
        return;
    }
    if (destination.family == SOLARIS_ADDRESS_DOMAIN) {
        solaris_address_t normalized;
        if (solaris_address_parse(destination.host, destination.port, &normalized) != SOLARIS_OK) {
            c->inbound->stats.udp_dropped++;
            return;
        }
        destination = normalized;
    }
    if (!c->udp_peer.port)
        c->udp_peer.port = source->port;
    c->activity_ns = solaris_executor_now_ns(c->scope.owner);
    c->udp_key = (solaris_udp_key_t){.inbound_id = c->inbound->options.inbound_id,
                                     .inbound_generation = solaris_executor_generation(c->scope.owner),
                                     .client_id = c->id,
                                     .source = c->udp_peer};
    solaris_udp_reply_endpoint_t endpoint = {
        .context = c, .generation = c->id, .retain = retain, .release = release, .send = reply};
    solaris_slice_t slice = {buffer, used + 3, size - used - 3};
    solaris_status_t rc;
    uint64_t association_id = 0;
    if (c->inbound->options.route) {
        solaris_route_options_t route = {0};
        if (!c->associated) {
            rc = solaris_proxy_route_options(c, SOLARIS_INBOUND_UDP, &destination, &route);
            if (rc != SOLARIS_OK) {
                c->inbound->stats.udp_dropped++;
                if (rc == SOLARIS_EACCESS || rc == SOLARIS_ECLOSED)
                    solaris_proxy_cancel(c, rc);
                return;
            }
        }
        rc = solaris_udp_submit_routed(c->inbound->udp, &c->udp_key, &destination, &slice, &endpoint, sent, c,
                                       &association_id, c->associated ? NULL : &route);
        solaris_proxy_route_options_release(&route);
    } else
        rc =
            solaris_udp_submit(c->inbound->udp, &c->udp_key, &destination, &slice, &endpoint, sent, c, &association_id);
    if (rc == SOLARIS_OK) {
        c->associated = 1;
        c->association_id = association_id;
        solaris_scope_retain(&c->scope);
    } else
        c->inbound->stats.udp_dropped++;
}
static void datagram_opened(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{
    proxy_connection_t *c = context;
    if (c->scope.cancelled)
        return;
    solaris_address_t bound;
    if (status == SOLARIS_OK)
        status = solaris_datagram_local_address(datagram, &bound);
    if (status != SOLARIS_OK)
        solaris_proxy_socks_reply(c, 1, NULL, PROXY_ERROR);
    else
        solaris_proxy_socks_reply(c, 0, &bound, PROXY_UDP);
}
static void datagram_closed(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{
    proxy_connection_t *c = context;
    (void)datagram;
    c->datagram = NULL;
    if (!c->draining)
        solaris_proxy_cancel(c, status);
    solaris_scope_release(&c->scope);
}
static const solaris_datagram_callbacks_t callbacks = {datagram_opened, packet_received, NULL, datagram_closed};
void solaris_proxy_udp_open(proxy_connection_t *c)
{
    solaris_dialer_options_t options;
    solaris_dialer_options_init(&options);
    options.local_bind = c->local;
    options.local_bind.port = 0;
    options.pending_byte_limit = c->inbound->options.pending_byte_limit;
    options.pending_request_limit = c->inbound->options.pending_packet_limit;
    c->state = PROXY_UDP_OPEN;
    solaris_status_t rc =
        solaris_dialer_open_datagram(c->scope.owner, &options, c->local.family, &callbacks, c, &c->datagram);
    if (rc == SOLARIS_OK)
        solaris_scope_retain(&c->scope);
    else
        solaris_proxy_socks_reply(c, 1, NULL, PROXY_ERROR);
}
void solaris_proxy_udp_cancel(proxy_connection_t *c)
{
    if (c->datagram)
        (void)solaris_datagram_close(c->datagram);
    if (c->associated)
        (void)solaris_udp_association_close(c->inbound->udp, &c->udp_key, c->association_id);
}
