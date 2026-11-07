#include "contracts/io/buffer.h"
#include "runtime/memory/alignment.h"
#include <assert.h>
#include <stdatomic.h>
#include <string.h>

struct solaris_budget {
    atomic_size_t references;
    atomic_size_t used;
    atomic_size_t peak;
    size_t limit;
    solaris_runtime_services_t services;
};

typedef union solaris_allocation {
    solaris_max_align_t alignment;
    struct {
        solaris_budget_t *budget;
        size_t charge;
    } info;
} solaris_allocation_t;

struct solaris_buffer {
    atomic_size_t references;
    atomic_uint published;
    size_t capacity;
    size_t length;
    uint8_t bytes[];
};

solaris_status_t solaris_budget_create(size_t limit,
                                       const solaris_runtime_services_t *services,
                                       solaris_budget_t **out)
{
    if (out == NULL || limit == 0u) return SOLARIS_EINVAL;
    *out = NULL;
    solaris_runtime_services_t selected;
    if (services != NULL) selected = *services;
    else solaris_runtime_services_init(&selected);
    if (selected.allocate == NULL || selected.deallocate == NULL) return SOLARIS_EINVAL;
    solaris_budget_t *budget = selected.allocate(selected.context, sizeof(*budget));
    if (budget == NULL) return SOLARIS_ENOMEM;
    atomic_init(&budget->references, 1u);
    atomic_init(&budget->used, 0u);
    atomic_init(&budget->peak, 0u);
    budget->limit = limit;
    budget->services = selected;
    *out = budget;
    return SOLARIS_OK;
}

void solaris_budget_retain(solaris_budget_t *budget)
{
    if (budget != NULL) {
        (void)atomic_fetch_add_explicit(&budget->references, 1u, memory_order_relaxed);
    }
}

void solaris_budget_release(solaris_budget_t *budget)
{
    if (budget != NULL &&
        atomic_fetch_sub_explicit(&budget->references, 1u, memory_order_acq_rel) == 1u) {
        assert(atomic_load_explicit(&budget->used, memory_order_relaxed) == 0u);
        solaris_runtime_services_t services = budget->services;
        services.deallocate(services.context, budget);
    }
}

size_t solaris_budget_used(const solaris_budget_t *budget)
{
    return atomic_load_explicit(&budget->used, memory_order_acquire);
}

size_t solaris_budget_peak(const solaris_budget_t *budget)
{
    return atomic_load_explicit(&budget->peak, memory_order_relaxed);
}

void *solaris_memory_allocate(solaris_budget_t *budget, size_t size)
{
    if (budget == NULL || size > SIZE_MAX - sizeof(solaris_allocation_t)) return NULL;
    const size_t charge = sizeof(solaris_allocation_t) + size;
    size_t used = atomic_load_explicit(&budget->used, memory_order_relaxed);
    for (;;) {
        if (charge > budget->limit || used > budget->limit - charge) return NULL;
        if (atomic_compare_exchange_weak_explicit(&budget->used, &used, used + charge,
                                                 memory_order_acq_rel, memory_order_relaxed)) break;
    }
    const size_t reserved = used + charge;
    size_t peak = atomic_load_explicit(&budget->peak, memory_order_relaxed);
    while (peak < reserved &&
           !atomic_compare_exchange_weak_explicit(&budget->peak, &peak, reserved,
                                                  memory_order_relaxed, memory_order_relaxed)) {}
    solaris_allocation_t *allocation = budget->services.allocate(budget->services.context, charge);
    if (allocation == NULL) {
        (void)atomic_fetch_sub_explicit(&budget->used, charge, memory_order_release);
        return NULL;
    }
    solaris_budget_retain(budget);
    allocation->info.budget = budget;
    allocation->info.charge = charge;
    return allocation + 1;
}

void solaris_memory_free(void *pointer)
{
    if (pointer == NULL) return;
    solaris_allocation_t *allocation = (solaris_allocation_t *)pointer - 1;
    solaris_budget_t *budget = allocation->info.budget;
    const size_t charge = allocation->info.charge;
    budget->services.deallocate(budget->services.context, allocation);
    (void)atomic_fetch_sub_explicit(&budget->used, charge, memory_order_release);
    solaris_budget_release(budget);
}

solaris_status_t solaris_buffer_allocate(solaris_budget_t *budget, size_t capacity,
                                         solaris_buffer_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (capacity > SIZE_MAX - sizeof(solaris_buffer_t)) return SOLARIS_EOVERFLOW;
    solaris_buffer_t *buffer = solaris_memory_allocate(budget, sizeof(*buffer) + capacity);
    if (buffer == NULL) return SOLARIS_ENOMEM;
    atomic_init(&buffer->references, 1u);
    atomic_init(&buffer->published, 0u);
    buffer->capacity = capacity;
    buffer->length = 0u;
    *out = buffer;
    return SOLARIS_OK;
}

solaris_status_t solaris_buffer_copy(solaris_budget_t *budget, const void *bytes,
                                     size_t length, solaris_buffer_t **out)
{
    if (out != NULL) *out = NULL;
    if (bytes == NULL && length != 0u) return SOLARIS_EINVAL;
    solaris_status_t rc = solaris_buffer_allocate(budget, length, out);
    if (rc != SOLARIS_OK) return rc;
    if (length != 0u) memcpy((*out)->bytes, bytes, length);
    (*out)->length = length;
    solaris_buffer_publish(*out);
    return SOLARIS_OK;
}

void solaris_buffer_publish(solaris_buffer_t *buffer)
{
    atomic_store_explicit(&buffer->published, 1u, memory_order_release);
}

void solaris_buffer_retain(const solaris_buffer_t *buffer)
{
    if (buffer == NULL) return;
    solaris_buffer_t *mutable = (solaris_buffer_t *)buffer;
    solaris_buffer_publish(mutable);
    (void)atomic_fetch_add_explicit(&mutable->references, 1u, memory_order_relaxed);
}

void solaris_buffer_release(const solaris_buffer_t *buffer)
{
    solaris_buffer_t *mutable = (solaris_buffer_t *)buffer;
    if (buffer != NULL &&
        atomic_fetch_sub_explicit(&mutable->references, 1u, memory_order_acq_rel) == 1u) {
        solaris_memory_free(mutable);
    }
}

const uint8_t *solaris_buffer_data(const solaris_buffer_t *buffer) { return buffer->bytes; }
size_t solaris_buffer_length(const solaris_buffer_t *buffer) { return buffer->length; }
size_t solaris_buffer_capacity(const solaris_buffer_t *buffer) { return buffer->capacity; }

uint8_t *solaris_buffer_mutable_data(solaris_buffer_t *buffer)
{
    return atomic_load_explicit(&buffer->references, memory_order_acquire) == 1u &&
           !atomic_load_explicit(&buffer->published, memory_order_acquire) ? buffer->bytes : NULL;
}

solaris_status_t solaris_buffer_set_length(solaris_buffer_t *buffer, size_t length)
{
    if (buffer == NULL || length > buffer->capacity) return SOLARIS_EINVAL;
    if (atomic_load_explicit(&buffer->references, memory_order_acquire) != 1u ||
        atomic_load_explicit(&buffer->published, memory_order_acquire)) return SOLARIS_EBUSY;
    buffer->length = length;
    return SOLARIS_OK;
}

int solaris_slice_valid(const solaris_slice_t *slice)
{
    return slice != NULL && slice->buffer != NULL &&
           slice->offset <= slice->buffer->length &&
           slice->length <= slice->buffer->length - slice->offset;
}
