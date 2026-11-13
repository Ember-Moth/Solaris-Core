#include <solaris/core.h>
#include <stdio.h>

static void on_event(void *context, const solaris_event_t *event)
{
    (void)context;
    printf("operation=%llu result=%s state=%u\n",
           (unsigned long long)event->operation_id,
           solaris_status_string(event->status), (unsigned int)event->state);
}

int main(void)
{
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    solaris_host_t host = {.on_event = on_event};
    solaris_error_t error;
    solaris_engine_t *engine = NULL;
    uint64_t operation_id = 0;
    solaris_status_t rc = solaris_engine_create(&options, &host, &engine, &error);
    if (rc == SOLARIS_OK) rc = solaris_engine_start(engine, &operation_id, &error);
    if (rc == SOLARIS_OK) rc = solaris_engine_flush(engine, 5000u, &error);
    if (rc == SOLARIS_OK) rc = solaris_engine_stop(engine, &operation_id, &error);
    if (rc == SOLARIS_OK) rc = solaris_engine_flush(engine, 5000u, &error);
    if (rc != SOLARIS_OK) fprintf(stderr, "%s\n", error.message);
    const solaris_status_t cleanup = solaris_engine_destroy(engine, NULL);
    return rc == SOLARIS_OK && cleanup == SOLARIS_OK ? 0 : 1;
}
