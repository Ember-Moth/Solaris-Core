#include "runtime/config/slots.h"
#include <assert.h>
#include <string.h>
#include <uv.h>

struct solaris_config_slots
{
    solaris_budget_t *budget;
    uv_mutex_t mutex;
    solaris_config_slot_t *head;
    solaris_config_slot_accept_fn accept;
    void *context;
    uint64_t serial;
    size_t count;
};
struct solaris_config_slot
{
    solaris_scope_t scope;
    solaris_scope_t *parent;
    solaris_config_slots_t *registry;
    solaris_config_slot_t *next;
    solaris_config_slot_key_t key;
    solaris_address_t bound;
    solaris_tcp_listener_t *listener;
    uint64_t id;
    size_t references;
    int closing, bound_ready;
};
static int key_valid(const solaris_config_slot_key_t *key)
{
    return key &&
           (key->address.family == SOLARIS_ADDRESS_IPV4 || key->address.family == SOLARIS_ADDRESS_IPV6) &&
           (key->address.port ? key->ephemeral_id == 0 : key->ephemeral_id != 0);
}
static int key_equal(const solaris_config_slot_key_t *a, const solaris_config_slot_key_t *b)
{
    return a->ephemeral_id == b->ephemeral_id && solaris_address_equal(&a->address, &b->address);
}
static solaris_config_slot_t *find_locked(solaris_config_slots_t *slots, const solaris_config_slot_key_t *key)
{
    for (solaris_config_slot_t *slot = slots->head; slot; slot = slot->next)
        if (key_equal(&slot->key, key) ||
            (key->address.port && slot->bound_ready && solaris_address_equal(&slot->bound, &key->address)))
            return slot;
    return NULL;
}
static int wildcard(const solaris_address_t *address)
{
    static const uint8_t zero[16] = {0};
    return (address->family == SOLARIS_ADDRESS_IPV4 && !memcmp(address->ip, zero, 4)) ||
           (address->family == SOLARIS_ADDRESS_IPV6 && !memcmp(address->ip, zero, 16));
}
static void slot_cancel(void *context)
{
    solaris_config_slot_t *slot = context;
    uv_mutex_lock(&slot->registry->mutex);
    slot->closing = 1;
    uv_mutex_unlock(&slot->registry->mutex);
    if (slot->listener)
        solaris_tcp_listener_close(slot->listener);
}
static void slot_done(void *context)
{
    solaris_config_slot_t *slot = context;
    solaris_config_slots_t *slots = slot->registry;
    solaris_scope_t *parent = slot->parent;
    assert(!slot->listener && !slot->references);
    uv_mutex_lock(&slots->mutex);
    solaris_config_slot_t **link = &slots->head;
    while (*link && *link != slot)
        link = &(*link)->next;
    assert(*link == slot && slots->count);
    *link = slot->next;
    slots->count--;
    uv_mutex_unlock(&slots->mutex);
    solaris_memory_free(slot);
    if (parent)
        solaris_scope_release(parent);
}
static void listener_closed(void *context, solaris_status_t status)
{
    solaris_config_slot_t *slot = context;
    (void)status;
    slot->listener = NULL;
    solaris_scope_cancel(&slot->scope);
}
static solaris_status_t accepted(void *context, const solaris_address_t *peer, const solaris_address_t *local,
                                 solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks,
                                 void **stream_context)
{
    solaris_config_slot_t *slot = context;
    if (slot->scope.cancelled)
        return SOLARIS_ECLOSED;
    return slot->registry->accept(slot->registry->context, slot, slot->scope.owner, peer, local, stream,
                                  callbacks, stream_context);
}
solaris_status_t solaris_config_slots_create(solaris_budget_t *budget, solaris_config_slot_accept_fn accept,
                                             void *context, solaris_config_slots_t **out)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!budget || !accept)
        return SOLARIS_EINVAL;
    solaris_config_slots_t *slots = solaris_memory_allocate(budget, sizeof(*slots));
    if (!slots)
        return SOLARIS_ENOMEM;
    memset(slots, 0, sizeof(*slots));
    if (uv_mutex_init(&slots->mutex) != 0)
    {
        solaris_memory_free(slots);
        return SOLARIS_EIO;
    }
    slots->budget = budget;
    slots->accept = accept;
    slots->context = context;
    *out = slots;
    return SOLARIS_OK;
}
solaris_executor_t *solaris_config_slot_owner(solaris_config_slots_t *slots,
                                              const solaris_config_slot_key_t *key,
                                              solaris_executor_t *preferred)
{
    if (!slots || !key_valid(key))
        return NULL;
    uv_mutex_lock(&slots->mutex);
    solaris_config_slot_t *slot = find_locked(slots, key);
    solaris_executor_t *owner = slot ? slot->scope.owner : preferred;
    uv_mutex_unlock(&slots->mutex);
    return owner;
}
solaris_status_t solaris_config_slot_acquire(solaris_config_slots_t *slots, solaris_executor_t *owner,
                                             solaris_scope_t *parent, const solaris_config_slot_key_t *key,
                                             solaris_config_slot_t **out, solaris_address_t *bound)
{
    if (!out)
        return SOLARIS_EINVAL;
    *out = NULL;
    if (!slots || !owner || !bound || !key_valid(key))
        return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner))
        return SOLARIS_ETHREAD;
    if (parent && (parent->owner != owner || parent->cancelled || parent->finishing))
        return SOLARIS_EINVAL;
    uv_mutex_lock(&slots->mutex);
    solaris_config_slot_t *slot = find_locked(slots, key);
    if (slot)
    {
        solaris_status_t status = slot->closing                ? SOLARIS_EAGAIN
                                  : slot->scope.owner != owner ? SOLARIS_ETHREAD
                                                               : SOLARIS_OK;
        if (status == SOLARIS_OK)
        {
            slot->references++;
            solaris_scope_retain(&slot->scope);
            *out = slot;
            *bound = slot->bound;
        }
        uv_mutex_unlock(&slots->mutex);
        return status;
    }
    /* Sharing wildcard and specific-address listeners depends on OS reuse
     * behavior. Do not publish an ambiguous overlapping admission surface. */
    if (key->address.port)
        for (slot = slots->head; slot; slot = slot->next)
        {
            const solaris_address_t *other = slot->bound_ready ? &slot->bound : &slot->key.address;
            if (other->family == key->address.family && other->port == key->address.port &&
                (wildcard(other) || wildcard(&key->address)))
            {
                solaris_status_t status = slot->closing ? SOLARIS_EAGAIN : SOLARIS_ENOTSUP;
                uv_mutex_unlock(&slots->mutex);
                return status;
            }
        }
    if (slots->serial == UINT64_MAX)
    {
        uv_mutex_unlock(&slots->mutex);
        return SOLARIS_EOVERFLOW;
    }
    uv_mutex_unlock(&slots->mutex);
    slot = solaris_memory_allocate(slots->budget, sizeof(*slot));
    if (!slot)
        return SOLARIS_ENOMEM;
    memset(slot, 0, sizeof(*slot));
    slot->registry = slots;
    slot->key = *key;
    solaris_status_t status = solaris_scope_init(&slot->scope, owner, slot_cancel, slot_done, slot);
    if (status != SOLARIS_OK)
    {
        solaris_memory_free(slot);
        return status;
    }
    slot->parent = parent;
    if (parent)
        solaris_scope_retain(parent);
    uv_mutex_lock(&slots->mutex);
    /* The coordinator serializes prepare. Existing references may be released
     * concurrently, but no other prepare can insert this same key. */
    assert(!find_locked(slots, key));
    slot->id = ++slots->serial;
    slot->next = slots->head;
    slots->head = slot;
    slots->count++;
    uv_mutex_unlock(&slots->mutex);
    solaris_dialer_options_t options;
    solaris_dialer_options_init(&options);
    options.pending_byte_limit = 262144;
    options.read_chunk_size = 8192;
    solaris_address_t actual_bound;
    status = solaris_tcp_listener_open_scoped(owner, &slot->scope, &key->address, &options, accepted,
                                              listener_closed, slot, &slot->listener, &actual_bound);
    if (status != SOLARIS_OK)
    {
        solaris_scope_cancel(&slot->scope);
        return status;
    }
    slot->references = 1;
    solaris_scope_retain(&slot->scope);
    uv_mutex_lock(&slots->mutex);
    slot->bound = actual_bound;
    slot->bound_ready = 1;
    uv_mutex_unlock(&slots->mutex);
    slot->parent = NULL;
    if (parent)
        solaris_scope_release(parent);
    *out = slot;
    *bound = slot->bound;
    return SOLARIS_OK;
}
void solaris_config_slot_retain(solaris_config_slot_t *slot)
{
    assert(slot && solaris_executor_is_owner(slot->scope.owner) && slot->references);
    slot->references++;
    solaris_scope_retain(&slot->scope);
}
void solaris_config_slot_release(solaris_config_slot_t *slot, solaris_scope_t *parent)
{
    if (!slot)
        return;
    assert(solaris_executor_is_owner(slot->scope.owner) && slot->references);
    if (--slot->references == 0)
    {
        assert(!slot->parent);
        if (parent)
        {
            assert(parent->owner == slot->scope.owner && !parent->finishing);
            slot->parent = parent;
            solaris_scope_retain(parent);
        }
        solaris_scope_cancel(&slot->scope);
    }
    solaris_scope_release(&slot->scope);
}
uint64_t solaris_config_slot_id(const solaris_config_slot_t *slot)
{
    return slot ? slot->id : 0;
}
int solaris_config_slots_drained(solaris_config_slots_t *slots)
{
    if (!slots)
        return 1;
    uv_mutex_lock(&slots->mutex);
    int drained = !slots->count;
    uv_mutex_unlock(&slots->mutex);
    return drained;
}
solaris_status_t solaris_config_slots_destroy(solaris_config_slots_t *slots)
{
    if (!slots)
        return SOLARIS_OK;
    if (!solaris_config_slots_drained(slots))
        return SOLARIS_EBUSY;
    uv_mutex_destroy(&slots->mutex);
    solaris_memory_free(slots);
    return SOLARIS_OK;
}
