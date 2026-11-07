#include "contracts/io/buffer.h"
#include "runtime/memory/alignment.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

typedef union fundamental {
    long double floating;
    uintmax_t integer;
    void *object;
    void (*function)(void);
} fundamental_t;
_Static_assert(_Alignof(solaris_max_align_t) >= _Alignof(fundamental_t), "allocator must align fundamental C types");
_Static_assert(sizeof(solaris_max_align_t) % _Alignof(solaris_max_align_t) == 0, "array alignment");

int main(void)
{
    solaris_budget_t *budget = NULL;
    CHECK(solaris_budget_create(1024 * 1024, NULL, &budget) == SOLARIS_OK);
    for (size_t i = 0; i < 513; ++i) {
        size_t size = sizeof(fundamental_t) + i;
        fundamental_t *value = solaris_memory_allocate(budget, size);
        CHECK(value && (uintptr_t)value % _Alignof(fundamental_t) == 0);
        memset(value, 0, size);
        value->floating = 1.25L;
        CHECK(value->floating == 1.25L);
        value->integer = UINTMAX_MAX;
        CHECK(value->integer == UINTMAX_MAX);
        value->object = budget;
        CHECK(value->object == budget);
        solaris_memory_free(value);
    }
    CHECK(solaris_budget_used(budget) == 0);
    solaris_budget_release(budget);
    puts("C fundamental allocation alignment and release passed");
    return 0;
}
