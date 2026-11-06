#ifndef SOLARIS_TEST_EVENT_H
#define SOLARIS_TEST_EVENT_H

#include <uv.h>

/* Counting test event with an explicit mutex handoff even when signalled
 * before wait. This also makes publication visible to ThreadSanitizer when
 * libuv itself is built without instrumentation. */
typedef struct solaris_test_event {
    uv_mutex_t mutex;
    uv_cond_t condition;
    unsigned int count;
} solaris_test_event_t;

static inline int solaris_test_event_init(solaris_test_event_t *event, unsigned int count)
{
    int rc = uv_mutex_init(&event->mutex);
    if (rc != 0) return rc;
    rc = uv_cond_init(&event->condition);
    if (rc != 0) { uv_mutex_destroy(&event->mutex); return rc; }
    event->count = count;
    return 0;
}

static inline void solaris_test_event_signal(solaris_test_event_t *event)
{
    uv_mutex_lock(&event->mutex);
    event->count++;
    uv_cond_signal(&event->condition);
    uv_mutex_unlock(&event->mutex);
}

static inline void solaris_test_event_wait(solaris_test_event_t *event)
{
    uv_mutex_lock(&event->mutex);
    while (event->count == 0u) uv_cond_wait(&event->condition, &event->mutex);
    event->count--;
    uv_mutex_unlock(&event->mutex);
}

static inline void solaris_test_event_destroy(solaris_test_event_t *event)
{
    uv_cond_destroy(&event->condition);
    uv_mutex_destroy(&event->mutex);
}

#endif
