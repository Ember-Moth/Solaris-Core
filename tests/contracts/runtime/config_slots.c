#include "runtime/config/slots.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#define CHECK(x)                                                                                             \
    do                                                                                                       \
    {                                                                                                        \
        if (!(x))                                                                                            \
        {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                          \
            abort();                                                                                         \
        }                                                                                                    \
    } while (0)
typedef struct fixture
{
    solaris_budget_t *budget;
    solaris_executor_t *owners[2];
    solaris_config_slots_t *slots;
    solaris_config_slot_t *a, *copy, *b;
    solaris_config_slot_key_t first, second, conflict;
    solaris_address_t a_bound, b_bound;
    solaris_test_event_t task, drained;
    solaris_scope_t parent;
    solaris_deferred_t release;
    atomic_int fail_after;
    unsigned command;
} fixture_t;
static void *allocate(void *context, size_t size)
{
    fixture_t *f = context;
    int remaining = atomic_load(&f->fail_after);
    if (!remaining)
        return NULL;
    if (remaining > 0)
        atomic_fetch_sub(&f->fail_after, 1);
    return malloc(size);
}
static solaris_status_t accept_stream(void *context, solaris_config_slot_t *slot, solaris_executor_t *owner,
                                      const solaris_address_t *peer, const solaris_address_t *local,
                                      solaris_stream_t *stream, solaris_stream_callbacks_t *callbacks,
                                      void **stream_context)
{
    (void)context;
    (void)slot;
    (void)owner;
    (void)peer;
    (void)local;
    (void)stream;
    (void)callbacks;
    (void)stream_context;
    return SOLARIS_EACCESS;
}
static void parent_done(void *context)
{
    solaris_test_event_signal(&((fixture_t *)context)->drained);
}
static void run(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    solaris_executor_t *owner = solaris_executor_current();
    solaris_config_slot_t *unexpected = (void *)1;
    solaris_address_t bound;
    if (f->command == 0)
    {
        CHECK(solaris_config_slot_acquire(f->slots, owner, NULL, &f->first, &f->a, &f->a_bound) ==
              SOLARIS_OK);
        CHECK(f->a_bound.port && solaris_config_slot_id(f->a));
        CHECK(solaris_config_slot_acquire(f->slots, owner, NULL, &f->first, &f->copy, &bound) == SOLARIS_OK);
        CHECK(f->copy == f->a && solaris_address_equal(&bound, &f->a_bound));
        solaris_config_slot_release(f->copy, NULL);
        f->copy = NULL;
        /* Moving an explicit ephemeral override back to its actual fixed
         * endpoint still reuses the physical socket. */
        solaris_config_slot_key_t fixed = {.address = f->a_bound};
        CHECK(solaris_config_slot_acquire(f->slots, owner, NULL, &fixed, &f->copy, &bound) == SOLARIS_OK);
        CHECK(f->copy == f->a);
    }
    else if (f->command == 1)
    {
        CHECK(solaris_config_slot_acquire(f->slots, owner, NULL, &f->first, &unexpected, &bound) ==
              SOLARIS_ETHREAD);
        CHECK(!unexpected);
        CHECK(solaris_config_slot_acquire(f->slots, owner, NULL, &f->second, &f->b, &f->b_bound) ==
              SOLARIS_OK);
        CHECK(f->a_bound.port != f->b_bound.port);
    }
    else if (f->command == 2 || f->command == 3)
    {
        CHECK(solaris_scope_init(&f->parent, owner, NULL, parent_done, f) == SOLARIS_OK);
        if (f->command == 3)
            atomic_store(&f->fail_after, 1);
        solaris_status_t rc =
            solaris_config_slot_acquire(f->slots, owner, &f->parent, &f->conflict, &unexpected, &bound);
        CHECK(rc == (f->command == 3 ? SOLARIS_ENOMEM : SOLARIS_EIO) && !unexpected);
        atomic_store(&f->fail_after, -1);
        solaris_scope_cancel(&f->parent);
        /* The old listener remains available even while rejected-open native
         * cleanup is draining asynchronously. */
        CHECK(solaris_config_slot_acquire(f->slots, owner, NULL, &f->first, &unexpected, &bound) ==
              SOLARIS_OK);
        CHECK(unexpected == f->a);
        solaris_config_slot_release(unexpected, NULL);
    }
    else if (f->command == 5)
    {
        solaris_config_slot_key_t overlap = {0};
        CHECK(solaris_address_parse("0.0.0.0", f->a_bound.port, &overlap.address) == SOLARIS_OK);
        CHECK(solaris_config_slot_acquire(f->slots, owner, NULL, &overlap, &unexpected, &bound) ==
              SOLARIS_ENOTSUP);
        CHECK(!unexpected);
    }
    else if (f->command == 4)
    {
        CHECK(solaris_scope_init(&f->parent, owner, NULL, parent_done, f) == SOLARIS_OK);
        solaris_config_slot_release(f->copy, &f->parent);
        f->copy = NULL;
        solaris_config_slot_release(f->a, &f->parent);
        f->a = NULL;
        solaris_scope_cancel(&f->parent);
    }
    solaris_test_event_signal(&f->task);
}
static void late_release(void *context)
{
    fixture_t *f = context;
    solaris_config_slot_release(f->b, NULL);
    f->b = NULL;
    solaris_test_event_signal(&f->task);
}
static void command(fixture_t *f, unsigned value, unsigned owner)
{
    f->command = value;
    CHECK(solaris_executor_post(f->owners[owner], run, f) == SOLARIS_OK);
    solaris_test_event_wait(&f->task);
}
static void ignore_connection(uv_stream_t *server, int status)
{
    (void)server;
    (void)status;
}
int main(void)
{
    fixture_t f = {0};
    atomic_init(&f.fail_after, -1);
    CHECK(!solaris_test_event_init(&f.task, 0) && !solaris_test_event_init(&f.drained, 0));
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = &f;
    services.allocate = allocate;
    CHECK(solaris_budget_create(1048576, &services, &f.budget) == SOLARIS_OK);
    for (unsigned i = 0; i < 2; ++i)
    {
        solaris_executor_options_t options = {
            .id = i, .queue_capacity = 32, .resource_limit = 32, .budget = f.budget};
        CHECK(solaris_executor_create(&options, &f.owners[i]) == SOLARIS_OK);
        CHECK(solaris_executor_activate(f.owners[i], 1) == SOLARIS_OK);
    }
    CHECK(solaris_config_slots_create(f.budget, accept_stream, &f, &f.slots) == SOLARIS_OK);
    CHECK(solaris_address_parse("127.0.0.1", 0, &f.first.address) == SOLARIS_OK);
    f.first.ephemeral_id = 1;
    f.second = f.first;
    f.second.ephemeral_id = 2;
    command(&f, 0, 0);
    CHECK(solaris_config_slot_owner(f.slots, &f.first, f.owners[1]) == f.owners[0]);
    CHECK(solaris_config_slots_destroy(f.slots) == SOLARIS_EBUSY);
    command(&f, 1, 1);
    uv_loop_t loop;
    uv_tcp_t blocker;
    struct sockaddr_in address;
    CHECK(!uv_loop_init(&loop) && !uv_tcp_init(&loop, &blocker));
    CHECK(!uv_ip4_addr("127.0.0.1", 0, &address));
    CHECK(!uv_tcp_bind(&blocker, (struct sockaddr *)&address, 0));
    CHECK(!uv_listen((uv_stream_t *)&blocker, 16, ignore_connection));
    int size = sizeof(address);
    CHECK(!uv_tcp_getsockname(&blocker, (struct sockaddr *)&address, &size));
    CHECK(solaris_address_parse("127.0.0.1", ntohs(address.sin_port), &f.conflict.address) == SOLARIS_OK);
    command(&f, 2, 0);
    solaris_test_event_wait(&f.drained);
    command(&f, 3, 0);
    solaris_test_event_wait(&f.drained);
    command(&f, 5, 0);
    command(&f, 4, 0);
    solaris_test_event_wait(&f.drained);
    CHECK(!solaris_config_slots_drained(f.slots));
    /* Stop cancels the physical listener but cannot reclaim an externally
     * held handle until the coordinator's reserved release arrives. */
    CHECK(solaris_executor_begin_quiesce(f.owners[1]) == SOLARIS_OK);
    CHECK(!solaris_executor_is_quiescent(f.owners[1]));
    f.release = (solaris_deferred_t){.run = late_release, .context = &f};
    CHECK(solaris_executor_defer(f.owners[1], &f.release) == SOLARIS_OK);
    solaris_test_event_wait(&f.task);
    CHECK(solaris_executor_wait_quiescent(f.owners[1]) == SOLARIS_OK);
    CHECK(solaris_executor_quiesce(f.owners[0]) == SOLARIS_OK);
    CHECK(solaris_config_slots_drained(f.slots));
    CHECK(solaris_config_slots_destroy(f.slots) == SOLARIS_OK);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(solaris_executor_destroy(f.owners[i]) == SOLARIS_OK);
    uv_close((uv_handle_t *)&blocker, NULL);
    uv_run(&loop, UV_RUN_DEFAULT);
    CHECK(!uv_loop_close(&loop));
    CHECK(!solaris_budget_used(f.budget));
    solaris_budget_release(f.budget);
    solaris_test_event_destroy(&f.task);
    solaris_test_event_destroy(&f.drained);
    puts("physical slots: stable owners, endpoint reuse, bind/allocation "
         "rollback, parent drain and stop release passed");
    return 0;
}
