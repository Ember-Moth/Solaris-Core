#ifndef SOLARIS_RUNTIME_SERVICES_H
#define SOLARIS_RUNTIME_SERVICES_H

#include <stddef.h>
#include <stdint.h>

typedef enum solaris_runtime_point {
    SOLARIS_POINT_MUTEX_INIT,
    SOLARIS_POINT_CONDITION_INIT,
    SOLARIS_POINT_THREAD_CREATE,
    SOLARIS_POINT_LOOP_INIT,
    SOLARIS_POINT_ASYNC_INIT,
    SOLARIS_POINT_ASYNC_SEND,
    SOLARIS_POINT_SHUTDOWN,
    SOLARIS_POINT_EXECUTOR_CREATE,
    SOLARIS_POINT_EXECUTOR_LOOP_INIT,
    SOLARIS_POINT_EXECUTOR_ASYNC_INIT,
    SOLARIS_POINT_EXECUTOR_TIMER_INIT
} solaris_runtime_point_t;

typedef struct solaris_runtime_services {
    void *context;
    void *(*allocate)(void *context, size_t size);
    void (*deallocate)(void *context, void *pointer);
    uint64_t (*now_ns)(void *context);
    int (*checkpoint)(void *context, solaris_runtime_point_t point);
} solaris_runtime_services_t;

void solaris_runtime_services_init(solaris_runtime_services_t *services);

#endif
