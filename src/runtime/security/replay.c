#include "contracts/runtime/replay.h"
#include <stdatomic.h>
#include <string.h>
#include <uv.h>

typedef struct replay_entry { uint8_t token[32]; uint64_t expires; int used; } replay_entry_t;
struct solaris_replay_store {
    atomic_size_t references;
    uv_mutex_t mutex;
    size_t capacity;
    uint64_t lifetime, (*now_ns)(void *);
    void *context;
    replay_entry_t entries[];
};
static uint64_t default_now(void *context) { (void)context; return uv_hrtime(); }
solaris_status_t solaris_replay_create(solaris_budget_t *budget, size_t capacity,
    uint64_t lifetime_ns, uint64_t (*now_ns)(void *), void *context, solaris_replay_store_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (capacity == 0u || capacity > (SIZE_MAX - sizeof(solaris_replay_store_t)) / sizeof(replay_entry_t))
        return SOLARIS_EINVAL;
    size_t size = sizeof(solaris_replay_store_t) + capacity * sizeof(replay_entry_t);
    solaris_replay_store_t *store = solaris_memory_allocate(budget, size);
    if (store == NULL) return SOLARIS_ENOMEM;
    memset(store, 0, size); atomic_init(&store->references, 1u);
    if (uv_mutex_init(&store->mutex) != 0) { solaris_memory_free(store); return SOLARIS_EIO; }
    store->capacity = capacity; store->lifetime = lifetime_ns;
    store->now_ns = now_ns == NULL ? default_now : now_ns; store->context = context;
    *out = store; return SOLARIS_OK;
}
void solaris_replay_retain(solaris_replay_store_t *store)
{ if (store != NULL) atomic_fetch_add_explicit(&store->references, 1u, memory_order_relaxed); }
int solaris_replay_is_persistent(const solaris_replay_store_t *store)
{ return store != NULL && store->lifetime == 0u; }
void solaris_replay_release(solaris_replay_store_t *store)
{
    if (store != NULL && atomic_fetch_sub_explicit(&store->references, 1u, memory_order_acq_rel) == 1u) {
        uv_mutex_destroy(&store->mutex); solaris_memory_free(store);
    }
}
solaris_status_t solaris_replay_insert(solaris_replay_store_t *store, const uint8_t token[32])
{
    if (store == NULL || token == NULL) return SOLARIS_EINVAL;
    uv_mutex_lock(&store->mutex);
    uint64_t now = store->now_ns(store->context), hash = 0u;
    for (size_t i = 0u; i < 8u; ++i) hash = (hash << 8) | token[i];
    size_t candidate = SIZE_MAX;
    for (size_t i = 0u; i < store->capacity; ++i) {
        size_t index = (size_t)((hash % store->capacity + i) % store->capacity);
        replay_entry_t *entry = &store->entries[index];
        if (!entry->used) { if (candidate == SIZE_MAX) candidate = index; break; }
        if (store->lifetime != 0u && entry->expires <= now) {
            if (candidate == SIZE_MAX) candidate = index;
        } else if (memcmp(entry->token, token, 32u) == 0) {
            uv_mutex_unlock(&store->mutex); return SOLARIS_EACCESS;
        }
    }
    if (candidate == SIZE_MAX) { uv_mutex_unlock(&store->mutex); return SOLARIS_EBUSY; }
    replay_entry_t *entry = &store->entries[candidate];
    entry->used = 1; memcpy(entry->token, token, 32u);
    entry->expires = store->lifetime > UINT64_MAX - now ? UINT64_MAX : now + store->lifetime;
    uv_mutex_unlock(&store->mutex); return SOLARIS_OK;
}
