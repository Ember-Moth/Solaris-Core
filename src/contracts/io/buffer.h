#ifndef SOLARIS_BUFFER_H
#define SOLARIS_BUFFER_H

#include <stddef.h>
#include <stdint.h>
#include <solaris/error.h>
#include "runtime/services/services.h"

typedef struct solaris_budget solaris_budget_t;
typedef struct solaris_buffer solaris_buffer_t;

/* Budgets and buffers may be retained/released across executor boundaries.
 * The allocator context must outlive all outstanding allocations. */
solaris_status_t solaris_budget_create(size_t limit,
                                       const solaris_runtime_services_t *services,
                                       solaris_budget_t **out);
void solaris_budget_retain(solaris_budget_t *budget);
void solaris_budget_release(solaris_budget_t *budget);
size_t solaris_budget_used(const solaris_budget_t *budget);
size_t solaris_budget_peak(const solaris_budget_t *budget);
void *solaris_memory_allocate(solaris_budget_t *budget, size_t size);
void solaris_memory_free(void *pointer);

solaris_status_t solaris_buffer_allocate(solaris_budget_t *budget, size_t capacity,
                                         solaris_buffer_t **out);
solaris_status_t solaris_buffer_copy(solaris_budget_t *budget, const void *bytes,
                                     size_t length, solaris_buffer_t **out);
void solaris_buffer_retain(const solaris_buffer_t *buffer);
void solaris_buffer_release(const solaris_buffer_t *buffer);
void solaris_buffer_publish(solaris_buffer_t *buffer);
const uint8_t *solaris_buffer_data(const solaris_buffer_t *buffer);
size_t solaris_buffer_length(const solaris_buffer_t *buffer);
size_t solaris_buffer_capacity(const solaris_buffer_t *buffer);
/* Only an unpublished, exclusively owned buffer may be changed. */
uint8_t *solaris_buffer_mutable_data(solaris_buffer_t *buffer);
solaris_status_t solaris_buffer_set_length(solaris_buffer_t *buffer, size_t length);

typedef struct solaris_slice {
    const solaris_buffer_t *buffer;
    size_t offset;
    size_t length;
} solaris_slice_t;

int solaris_slice_valid(const solaris_slice_t *slice);

#endif
