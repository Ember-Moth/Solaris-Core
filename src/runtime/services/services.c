#include "runtime/services/services.h"
#include <stdlib.h>
#include <string.h>
#include <uv.h>

static void *allocate(void *context, size_t size)
{
    (void)context;
    return malloc(size);
}

static void deallocate(void *context, void *pointer)
{
    (void)context;
    free(pointer);
}

static uint64_t now_ns(void *context)
{
    (void)context;
    return uv_hrtime();
}

void solaris_runtime_services_init(solaris_runtime_services_t *services)
{
    memset(services, 0, sizeof(*services));
    services->allocate = allocate;
    services->deallocate = deallocate;
    services->now_ns = now_ns;
}
