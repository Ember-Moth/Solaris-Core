#ifndef SOLARIS_TEST_ENV_H
#define SOLARIS_TEST_ENV_H
#include <stdlib.h>
#include <string.h>

/* Return an owned copy of the value, or NULL for an absent option. */
static inline char *solaris_test_env_copy(const char *name)
{
#ifdef _MSC_VER
    char *copy = NULL;
    size_t length = 0;
    if (_dupenv_s(&copy, &length, name) != 0) abort();
    return copy;
#else
    const char *value = getenv(name);
    if (!value) return NULL;
    size_t length = strlen(value) + 1;
    char *copy = malloc(length);
    if (!copy) abort();
    memcpy(copy, value, length);
    return copy;
#endif
}
static inline int solaris_test_env_set(const char *name)
{
    char *value = solaris_test_env_copy(name);
    int present = value != NULL;
    free(value);
    return present;
}
#endif
