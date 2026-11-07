#include "config/image/internal.h"
#include <string.h>
#if defined(_MSC_VER)
static __declspec(thread) solaris_budget_t *active_budget;
#else
static _Thread_local solaris_budget_t *active_budget;
#endif
typedef union yaml_allocation {
    max_align_t alignment;
    size_t size;
} yaml_allocation_t;
solaris_budget_t *solaris_yaml_enter_budget(solaris_budget_t *budget)
{
    solaris_budget_t *previous = active_budget;
    active_budget = budget;
    return previous;
}
void *solaris_yaml_malloc(size_t size)
{
    if (!active_budget || size > SIZE_MAX - sizeof(yaml_allocation_t))
        return NULL;
    yaml_allocation_t *p = solaris_memory_allocate(active_budget, sizeof(*p) + size);
    if (!p)
        return NULL;
    p->size = size;
    return p + 1;
}
void solaris_yaml_free(void *pointer)
{
    if (!pointer)
        return;
    yaml_allocation_t *p = (yaml_allocation_t *)pointer - 1;
    for (size_t i = 0; i < p->size; ++i)
        ((volatile unsigned char *)pointer)[i] = 0;
    solaris_memory_free(p);
}
void *solaris_yaml_realloc(void *pointer, size_t size)
{
    void *p = solaris_yaml_malloc(size);
    if (!p)
        return NULL;
    if (pointer) {
        size_t old = ((yaml_allocation_t *)pointer - 1)->size;
        memcpy(p, pointer, old < size ? old : size);
        solaris_yaml_free(pointer);
    }
    return p;
}
char *solaris_yaml_strdup(const char *text)
{
    size_t size = strlen(text) + 1;
    char *p = solaris_yaml_malloc(size);
    if (p)
        memcpy(p, text, size);
    return p;
}
