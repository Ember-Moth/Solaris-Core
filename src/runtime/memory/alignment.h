#ifndef SOLARIS_MEMORY_ALIGNMENT_H
#define SOLARIS_MEMORY_ALIGNMENT_H

#include <stddef.h>
#include <stdint.h>

/* Native MSVC C11 mode does not provide max_align_t. Its fundamental scalar
 * alignment is covered by this union; other compilers retain their native
 * max_align_t. Over-aligned extension types require a separate allocator. */
#if defined(_MSC_VER) && !defined(__clang__) && !defined(__cplusplus)
typedef union solaris_max_align {
    long double floating;
    uintmax_t integer;
    void *object;
    void (*function)(void);
} solaris_max_align_t;
#else
typedef max_align_t solaris_max_align_t;
#endif

#endif
