#include "platform/tun/internal.h"
#include <string.h>

int solaris_tun_device_packet(const uint8_t *packet, size_t length)
{
    if (packet == NULL || length == 0u) return 0;
    unsigned int version = packet[0] >> 4;
    return (version == 4u && length >= 20u) || (version == 6u && length >= 40u);
}
static void cancelled(void *context)
{
    solaris_tun_device_t *d = context;
    if (!d->closing) { d->closing = 1; d->status = SOLARIS_ECANCELLED; }
    while (d->head != NULL) solaris_tun_device_pop(d);
    d->ops->cancel(d);
}
static void destroyed(void *context)
{
    solaris_tun_device_t *d = context;
    d->ops->dispose(d);
    if (d->accepted) d->options.on_close(d->options.context, d->status);
    solaris_memory_free(d);
}
solaris_status_t solaris_tun_device_normalize(const solaris_tun_device_options_t *options, solaris_tun_device_options_t *out)
{
    if (options == NULL || out == NULL || options->owner == NULL || options->on_packet == NULL || options->on_close == NULL ||
        options->kind < SOLARIS_TUN_DEVICE_FD || options->kind > SOLARIS_TUN_DEVICE_WINTUN ||
        options->framing > SOLARIS_TUN_FRAMING_DARWIN) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(options->owner)) return SOLARIS_ETHREAD;
    if (!solaris_executor_accepting(options->owner)) return SOLARIS_ECLOSED;
    *out = *options;
    if (out->mtu == 0u) out->mtu = 1500u;
    if (out->queue_packet_limit == 0u) out->queue_packet_limit = 64u;
    if (out->queue_byte_limit == 0u) out->queue_byte_limit = 1024u * 1024u;
    if (out->mtu < 40u || out->mtu > 65535u || out->queue_packet_limit > 65536u ||
        out->queue_byte_limit < out->mtu || out->queue_byte_limit > 64u * 1024u * 1024u ||
        (out->name != NULL && strlen(out->name) >= sizeof(((solaris_tun_device_t *)0)->name))) return SOLARIS_EINVAL;
    return SOLARIS_OK;
}
solaris_status_t solaris_tun_device_init(solaris_tun_device_t *d,
    const solaris_tun_device_options_t *options, const solaris_tun_device_ops_t *ops, const char *name)
{
    d->ops = ops; d->options = *options;
    if (name != NULL) memcpy(d->name, name, strlen(name) + 1u);
    d->options.name = d->name; d->options.wintun_library = NULL;
    return solaris_scope_init(&d->scope, options->owner, cancelled, destroyed, d);
}
void solaris_tun_device_fail(solaris_tun_device_t *d, solaris_status_t status)
{
    if (d->closing) return;
    d->closing = 1; d->status = status; solaris_scope_cancel(&d->scope);
}
void solaris_tun_device_pop(solaris_tun_device_t *d)
{
    solaris_tun_packet_t *p = d->head;
    d->head = p->next; if (d->head == NULL) d->tail = NULL;
    d->pending_packets--; d->pending_bytes -= p->length; solaris_memory_free(p);
}
void solaris_tun_device_writable(solaris_tun_device_t *d)
{
    if (d->closing || !d->writable || d->pending_packets >= d->options.queue_packet_limit || d->pending_bytes >= d->options.queue_byte_limit) return;
    d->writable = 0;
    if (d->options.on_writable != NULL) d->options.on_writable(d->options.context);
}
solaris_status_t solaris_tun_device_open(const solaris_tun_device_options_t *options, solaris_tun_device_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL; solaris_tun_device_options_t selected;
    solaris_status_t rc = solaris_tun_device_normalize(options, &selected);
    if (rc != SOLARIS_OK) return rc;
    return selected.kind == SOLARIS_TUN_DEVICE_WINTUN ? solaris_tun_wintun_open(&selected, out) : solaris_tun_posix_open(&selected, out);
}
solaris_status_t solaris_tun_device_write(solaris_tun_device_t *d, const uint8_t *packet, size_t length)
{
    if (d == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(d->options.owner)) return SOLARIS_ETHREAD;
    if (d->closing || !solaris_executor_accepting(d->options.owner)) return SOLARIS_ECLOSED;
    if (length > d->options.mtu) return SOLARIS_EMSGSIZE;
    if (!solaris_tun_device_packet(packet, length)) return SOLARIS_EINVAL;
    if (d->pending_packets >= d->options.queue_packet_limit || length > d->options.queue_byte_limit - d->pending_bytes) {
        d->writable = 1; return SOLARIS_EAGAIN;
    }
    solaris_tun_packet_t *p = solaris_memory_allocate(solaris_executor_budget(d->options.owner), sizeof(*p) + length);
    if (p == NULL) return SOLARIS_ENOMEM;
    p->next = NULL; p->length = length; memcpy(p->data, packet, length);
    if (d->tail != NULL) d->tail->next = p; else d->head = p;
    d->tail = p; d->pending_packets++; d->pending_bytes += length;
    d->ops->schedule(d); return SOLARIS_OK;
}
void solaris_tun_device_close(solaris_tun_device_t *d)
{ if (d != NULL && solaris_executor_is_owner(d->options.owner)) solaris_tun_device_fail(d, SOLARIS_OK); }
const char *solaris_tun_device_name(const solaris_tun_device_t *d) { return d == NULL ? NULL : d->name; }
