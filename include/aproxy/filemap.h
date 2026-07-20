#ifndef APROXY_FILEMAP_H
#define APROXY_FILEMAP_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/error.h"

typedef struct aproxy_filemap {
    const uint8_t *data;
    size_t len;
    void *mapping;
    int fd;
} aproxy_filemap_t;

int aproxy_filemap_open_ro(const char *path,
                           size_t max_size,
                           aproxy_filemap_t *out);

/* Restores the platform's balanced readahead policy after a forward scan. */
void aproxy_filemap_advise_normal(aproxy_filemap_t *map);

void aproxy_filemap_close(aproxy_filemap_t *map);

#endif
