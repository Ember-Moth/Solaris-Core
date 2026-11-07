#ifndef SOLARIS_YAML_ALLOCATOR_H
#define SOLARIS_YAML_ALLOCATOR_H
/* Force-include only for vendor compilation, after standard declarations. */
#include <stdlib.h>
#include <string.h>
void *solaris_yaml_malloc(size_t size);
void *solaris_yaml_realloc(void *pointer, size_t size);
void solaris_yaml_free(void *pointer);
char *solaris_yaml_strdup(const char *text);
#define malloc solaris_yaml_malloc
#define realloc solaris_yaml_realloc
#define free solaris_yaml_free
#define strdup solaris_yaml_strdup
#endif
