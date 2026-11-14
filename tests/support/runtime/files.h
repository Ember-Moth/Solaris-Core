#ifndef SOLARIS_TEST_FILES_H
#define SOLARIS_TEST_FILES_H
#include <stdio.h>

static inline FILE *solaris_test_fopen(const char *path, const char *mode)
{
#ifdef _MSC_VER
    FILE *file = NULL;
    return fopen_s(&file, path, mode) == 0 ? file : NULL;
#else
    return fopen(path, mode);
#endif
}
#endif
