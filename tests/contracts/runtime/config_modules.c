#include "runtime/config/worker.h"
#include "support/runtime/event.h"
#include "solaris_builtin_modules.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                                                                       \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
typedef struct allocations {
    atomic_size_t calls, fail, live;
} allocations_t;
static void *allocate(void *context, size_t bytes)
{
    allocations_t *a = context;
    size_t call = atomic_fetch_add(&a->calls, 1) + 1;
    if (call == atomic_load(&a->fail))
        return NULL;
    void *p = malloc(bytes);
    if (p)
        atomic_fetch_add(&a->live, 1);
    return p;
}
static void deallocate(void *context, void *pointer)
{
    allocations_t *a = context;
    CHECK(atomic_fetch_sub(&a->live, 1));
    free(pointer);
}
static solaris_config_t *config(const char *input)
{
    char source[] = "owned-source.conf";
    solaris_config_options_t o;
    solaris_config_options_init(&o);
    o.source_name = source;
    solaris_config_t *image;
    solaris_diagnostics_t *diagnostics;
    solaris_error_t error;
    solaris_status_t rc = solaris_config_compile_bytes(input, strlen(input), &o, &image, &diagnostics, &error);
    if (rc != SOLARIS_OK)
        fprintf(stderr, "config error %d: %s\n", rc, error.message);
    CHECK(rc == SOLARIS_OK);
    solaris_diagnostics_release(diagnostics);
    memset(source, 'x', strlen(source));
    CHECK(!strcmp(solaris_config_source_name(image), "owned-source.conf"));
    return image;
}
static uint64_t node_id(solaris_config_module_set_t *set, const char *name)
{
    size_t count;
    const solaris_config_node_t *nodes = solaris_config_nodes(solaris_config_module_set_image(set), &count);
    for (size_t i = 0; i < count; ++i)
        if (!strcmp(nodes[i].name, name))
            return nodes[i].id;
    CHECK(0);
    return 0;
}
static solaris_config_module_set_t *make_set(solaris_budget_t *budget, const char *input)
{
    solaris_config_t *image = config(input);
    solaris_config_module_set_t *set;
    CHECK(solaris_config_module_set_create(budget, image, NULL, 0, &set, NULL) == SOLARIS_OK);
    solaris_config_release(image);
    return set;
}
typedef struct fixture fixture_t;
typedef struct generation {
    atomic_uint references, pins, unpins;
    int retire_on_zero;
    size_t count;
    fixture_t *workers[2];
} generation_t;
struct fixture {
    solaris_executor_t *owner;
    solaris_config_module_set_t *set;
    solaris_replay_store_t *replay;
    solaris_config_worker_t *worker;
    solaris_scope_t parent;
    solaris_dial_plan_t plan;
    solaris_datagram_t *datagram;
    solaris_deferred_t retire;
    solaris_test_event_t ready, done, opened;
    generation_t *generation;
    allocations_t *allocations;
    size_t fail, allocation_count;
    solaris_status_t result;
    atomic_uint closed, parent_done;
    unsigned policy_calls, datagrams_opened, datagrams_closed;
    solaris_module_config_t *fake_config;
    solaris_scope_t *pending;
    unsigned fake_retired, fake_destroyed, fake_closed, invalid_factory;
    solaris_outbound_t fake_outbound;
};
static void retire_deferred(void *context)
{
    fixture_t *f = context;
    if (f->worker)
        CHECK(solaris_config_worker_retire(f->worker) == SOLARIS_OK);
    solaris_scope_cancel(&f->parent);
}
static void lease_retain(void *context)
{
    generation_t *g = context;
    CHECK(atomic_fetch_add(&g->references, 1));
    atomic_fetch_add(&g->pins, 1);
}
static void lease_release(void *context)
{
    generation_t *g = context;
    unsigned old = atomic_fetch_sub(&g->references, 1);
    CHECK(old);
    atomic_fetch_add(&g->unpins, 1);
    if (old == 1 && g->retire_on_zero)
        for (size_t i = 0; i < g->count; ++i)
            CHECK(solaris_executor_defer(g->workers[i]->owner, &g->workers[i]->retire) == SOLARIS_OK);
}
static solaris_status_t socket_policy(void *context, uintptr_t socket, uint32_t family, uint32_t kind)
{
    fixture_t *f = context;
    (void)socket;
    (void)family;
    (void)kind;
    f->policy_calls++;
    return SOLARIS_OK;
}
static void parent_closed(void *context)
{
    fixture_t *f = context;
    if (f->fake_config)
        CHECK(f->fake_destroyed == 1 && !f->fake_closed);
    CHECK(!f->worker);
    atomic_fetch_add(&f->parent_done, 1);
    solaris_test_event_signal(&f->done);
}
static void worker_closed(void *context)
{
    fixture_t *f = context;
    f->worker = NULL;
    atomic_fetch_add(&f->closed, 1);
}
static void create_worker(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&f->parent, f->owner, NULL, parent_closed, f) == SOLARIS_OK);
    solaris_config_worker_options_t o = {.owner = f->owner,
                                         .set = f->set,
                                         .parent_scope = &f->parent,
                                         .lease_context = f->generation,
                                         .lease_retain = lease_retain,
                                         .lease_release = lease_release,
                                         .on_close = worker_closed,
                                         .context = f};
    solaris_dialer_options_init(&o.services.dialer);
    o.services.dialer.prepare_socket = socket_policy;
    o.services.dialer.policy_context = f;
    o.services.replay = f->replay;
    f->result = solaris_config_worker_create(&o, &f->worker, NULL);
    CHECK(f->result == SOLARIS_OK && f->worker && !f->policy_calls);
    solaris_test_event_signal(&f->ready);
}
static void acquire_direct(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    uint32_t caps;
    CHECK(solaris_config_worker_acquire(f->worker, node_id(f->set, "DIRECT"), 71, &f->plan, &caps) == SOLARIS_OK);
    CHECK((caps & SOLARIS_OUTBOUND_DATAGRAM) && (caps & SOLARIS_OUTBOUND_LOCAL_RESOLUTION) &&
          f->plan.selection_revision == 71);
    solaris_dial_plan_t blocked;
    CHECK(solaris_config_worker_acquire(f->worker, node_id(f->set, "no-udp"), 72, &blocked, &caps) == SOLARIS_OK);
    CHECK(!(caps & (SOLARIS_OUTBOUND_DATAGRAM | SOLARIS_OUTBOUND_DATAGRAM_MULTI | SOLARIS_OUTBOUND_DATAGRAM_DOMAIN)));
    CHECK((caps & SOLARIS_OUTBOUND_STREAM) && blocked.outbound->owner == f->owner);
    solaris_datagram_t *datagram = (void *)1;
    solaris_datagram_callbacks_t callbacks = {0};
    CHECK(solaris_outbound_open_datagram(blocked.outbound, SOLARIS_ADDRESS_IPV4, &callbacks, NULL, &datagram) ==
              SOLARIS_ENOTSUP &&
          !datagram);
    CHECK(solaris_dial_plan_release(&blocked) == SOLARIS_OK && !f->policy_calls);
    solaris_test_event_signal(&f->ready);
}
static void datagram_opened(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    solaris_address_t address;
    CHECK(solaris_datagram_local_address(datagram, &address) == SOLARIS_OK && address.port);
    f->datagrams_opened++;
    CHECK(solaris_datagram_close(datagram) == SOLARIS_OK);
}
static void datagram_closed(void *context, solaris_datagram_t *datagram, solaris_status_t status)
{
    fixture_t *f = context;
    (void)datagram;
    (void)status;
    f->datagram = NULL;
    f->datagrams_closed++;
    solaris_test_event_signal(&f->opened);
}
static void packet_unused(void *context, solaris_datagram_t *datagram, const solaris_address_t *peer, const solaris_buffer_t *payload)
{ (void)context; (void)datagram; (void)peer; (void)payload; CHECK(0); }
static void late_lane(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    static const solaris_datagram_callbacks_t callbacks = {.on_open = datagram_opened, .on_packet = packet_unused, .on_close = datagram_closed};
    CHECK(solaris_outbound_open_datagram(f->plan.outbound, SOLARIS_ADDRESS_IPV4, &callbacks, f, &f->datagram) ==
          SOLARIS_OK);
}
static void release_direct(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_dial_plan_release(&f->plan) == SOLARIS_OK);
    solaris_test_event_signal(&f->ready);
}
static void init_fixture(fixture_t *f, solaris_executor_t *owner, solaris_config_module_set_t *set, generation_t *g)
{
    memset(f, 0, sizeof(*f));
    f->owner = owner;
    f->set = set;
    f->generation = g;
    atomic_init(&f->closed, 0);
    atomic_init(&f->parent_done, 0);
    CHECK(!solaris_test_event_init(&f->ready, 0));
    CHECK(!solaris_test_event_init(&f->done, 0));
    CHECK(!solaris_test_event_init(&f->opened, 0));
    f->retire = (solaris_deferred_t){.run = retire_deferred, .context = f};
}
static void clear_fixture(fixture_t *f)
{
    solaris_test_event_destroy(&f->ready);
    solaris_test_event_destroy(&f->done);
    solaris_test_event_destroy(&f->opened);
}
static void invoke(fixture_t *f, solaris_task_fn fn)
{
    CHECK(solaris_executor_post(f->owner, fn, f) == SOLARIS_OK);
    solaris_test_event_wait(&f->ready);
}
static void generation_leases(solaris_budget_t *budget, solaris_executor_t **owners, solaris_replay_store_t *replay)
{
    solaris_config_module_set_t *set = make_set(budget, "[General]\n"
    "config-version = 1\n"
    "mode = rule\n"
    "\n"
    "[Proxy]\n"
    "\"no-udp\" = direct, udp-relay=\"false\"\n"
    "\n"
    "[Rule]\n"
    "FINAL,DIRECT\n");
    generation_t g = {.retire_on_zero = 1, .count = 2};
    atomic_init(&g.references, 1);
    atomic_init(&g.pins, 0);
    atomic_init(&g.unpins, 0);
    fixture_t f[2];
    for (size_t i = 0; i < 2; ++i) {
        init_fixture(&f[i], owners[i], set, &g);
        g.workers[i] = &f[i];
        f[i].replay = replay;
        invoke(&f[i], create_worker);
    }
    CHECK(atomic_load(&g.references) == 1); /* Containers must not create a reference cycle. */
    for (size_t i = 0; i < 2; ++i)
        invoke(&f[i], acquire_direct);
    CHECK(f[0].plan.outbound != f[1].plan.outbound && atomic_load(&g.references) == 3);
    lease_release(&g); /* Remove old publication: only flow/association leases remain. */
    for (size_t i = 0; i < 2; ++i) {
        CHECK(!atomic_load(&f[i].closed));
        CHECK(solaris_executor_post(f[i].owner, late_lane, &f[i]) == SOLARIS_OK);
        solaris_test_event_wait(&f[i].opened);
        CHECK(f[i].datagrams_opened == 1 && f[i].datagrams_closed == 1);
    }
    for (size_t i = 0; i < 2; ++i)
        invoke(&f[i], release_direct);
    for (size_t i = 0; i < 2; ++i) {
        solaris_test_event_wait(&f[i].done);
        CHECK(atomic_load(&f[i].closed) == 1 && atomic_load(&f[i].parent_done) == 1);
        clear_fixture(&f[i]);
    }
    CHECK(atomic_load(&g.references) == 0 && atomic_load(&g.pins) == 4 && atomic_load(&g.unpins) == 5);
    solaris_config_module_set_release(set);
}
static void failed_worker(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&f->parent, f->owner, NULL, parent_closed, f) == SOLARIS_OK);
    solaris_config_worker_options_t o = {
        .owner = f->owner, .set = f->set, .parent_scope = &f->parent, .on_close = worker_closed, .context = f};
    o.services.replay = f->replay;
    atomic_store(&f->allocations->calls, 0);
    atomic_store(&f->allocations->fail, f->fail);
    f->result = solaris_config_worker_create(&o, &f->worker, NULL);
    f->allocation_count = atomic_load(&f->allocations->calls);
    atomic_store(&f->allocations->fail, 0);
    if (f->worker)
        CHECK(solaris_config_worker_retire(f->worker) == SOLARIS_OK);
    else
        CHECK(f->result == SOLARIS_ENOMEM);
    solaris_scope_cancel(&f->parent);
    solaris_test_event_signal(&f->ready);
}
static void failure_rollback(solaris_budget_t *budget, solaris_executor_t *owner, solaris_replay_store_t *replay,
                             allocations_t *a)
{
    solaris_config_module_set_t *set = make_set(budget, "[General]\n"
    "config-version = 1\n"
    "mode = rule\n"
    "\n"
    "[Rule]\n"
    "FINAL,DIRECT\n");
    size_t count = 0;
    for (size_t fail = 0;; ++fail) {
        fixture_t f;
        init_fixture(&f, owner, set, NULL);
        f.replay = replay;
        f.allocations = a;
        f.fail = fail;
        invoke(&f, failed_worker);
        solaris_test_event_wait(&f.done);
        if (!fail) {
            CHECK(f.result == SOLARIS_OK);
            count = f.allocation_count;
        } else
            CHECK(f.result == SOLARIS_ENOMEM && !atomic_load(&f.closed));
        CHECK(atomic_load(&f.parent_done) == 1);
        clear_fixture(&f);
        if (fail == count)
            break;
    }
    solaris_config_module_set_release(set);
    printf("worker rollback: %zu allocation sites drained\n", count);
}
static solaris_status_t fake_compile(const solaris_config_view_t *view, solaris_budget_t *budget, void **out,
                                     solaris_error_t *error)
{
    (void)view;
    (void)budget;
    (void)error;
    *out = NULL;
    return SOLARIS_OK;
}
static void fake_free(void *context)
{
    (void)context;
}
static solaris_status_t fake_create(const void *config, const solaris_module_services_t *services, void **state,
                                    solaris_outbound_t **out, solaris_error_t *error)
{
    (void)config;
    (void)error;
    fixture_t *f = services->crypto.context;
    *state = f;
    f->pending = services->scope;
    solaris_scope_retain(f->pending);
    if (f->invalid_factory) {
        f->fake_outbound.owner = NULL;
        *out = &f->fake_outbound;
        return SOLARIS_OK;
    }
    return SOLARIS_EIO;
}
static void fake_retire(void *state)
{
    ((fixture_t *)state)->fake_retired++;
}
static void fake_destroy(void *state)
{
    fixture_t *f = state;
    CHECK(f->fake_retired == 1);
    f->fake_destroyed++;
}
static void fake_closed(void *context)
{
    ((fixture_t *)context)->fake_closed++;
}
static const solaris_outbound_module_t fake_module = {
    "delayed-reject", NULL, 0, NULL, 0, 0, fake_compile, fake_free, fake_create, fake_retire, fake_destroy};
static void reject_factory(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&f->parent, f->owner, NULL, parent_closed, f) == SOLARIS_OK);
    solaris_module_services_t services = {.owner = f->owner, .parent_scope = &f->parent};
    services.crypto.context = f;
    solaris_module_instance_t *instance = (void *)1;
    solaris_status_t rc = solaris_module_create(f->fake_config, &services, fake_closed, f, &instance, NULL);
    CHECK(rc == (f->invalid_factory ? SOLARIS_EINVAL : SOLARIS_EIO) && !instance && f->fake_retired == 1 &&
          !f->fake_destroyed);
    solaris_scope_cancel(&f->parent);
    solaris_test_event_signal(&f->ready);
}
static void release_rejected(void *context, solaris_status_t status)
{
    fixture_t *f = context;
    CHECK(status == SOLARIS_OK && f->pending);
    solaris_scope_release(f->pending);
    f->pending = NULL;
    solaris_test_event_signal(&f->ready);
}
static void rejected_factory_barrier(solaris_budget_t *budget, solaris_executor_t *owner)
{
    const solaris_outbound_module_t *modules[] = {&fake_module};
    solaris_registry_t *registry;
    solaris_module_config_t *compiled;
    CHECK(solaris_registry_create(modules, 1, budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_view_t empty = {.kind = SOLARIS_CONFIG_MAP};
    CHECK(solaris_registry_compile(registry, "delayed-reject", &empty, &compiled, NULL) == SOLARIS_OK);
    solaris_registry_destroy(registry);
    for (unsigned invalid = 0; invalid < 2; ++invalid) {
        fixture_t f;
        init_fixture(&f, owner, NULL, NULL);
        f.fake_config = compiled;
        f.invalid_factory = invalid;
        invoke(&f, reject_factory);
        CHECK(!atomic_load(&f.parent_done) && !f.fake_destroyed);
        invoke(&f, release_rejected);
        solaris_test_event_wait(&f.done);
        CHECK(f.fake_destroyed == 1 && !f.fake_closed);
        clear_fixture(&f);
    }
    solaris_module_config_release(compiled);
}
static void module_sets(solaris_budget_t *budget, allocations_t *a)
{
    solaris_config_t *image = config("[General]\n"
    "config-version = 1\n"
    "mode = rule\n"
    "\n"
    "[Rule]\n"
    "FINAL,DIRECT\n");
    size_t baseline = solaris_budget_used(budget);
    solaris_config_module_set_t *set = NULL;
    CHECK(solaris_config_module_set_create(budget, image, NULL, 0, &set, NULL) == SOLARIS_OK);
    CHECK(solaris_config_module_set_image(set) == image);
    solaris_config_module_set_retain(set);
    solaris_config_module_set_release(set);
    solaris_config_module_set_release(set);
    CHECK(solaris_budget_used(budget) == baseline);
    atomic_store(&a->calls, 0);
    CHECK(solaris_config_module_set_create(budget, image, NULL, 0, &set, NULL) == SOLARIS_OK);
    size_t count = atomic_load(&a->calls);
    solaris_config_module_set_release(set);
    for (size_t fail = 1; fail <= count; ++fail) {
        atomic_store(&a->calls, 0);
        atomic_store(&a->fail, fail);
        set = (void *)1;
        CHECK(solaris_config_module_set_create(budget, image, NULL, 0, &set, NULL) == SOLARIS_ENOMEM && !set);
        atomic_store(&a->fail, 0);
        CHECK(solaris_budget_used(budget) == baseline);
    }
    solaris_config_release(image);
    printf("module-set rollback: %zu allocation sites released\n", count);
}

#if SOLARIS_HAS_ANYTLS
static const char trust_pem[] = "-----BEGIN CERTIFICATE-----\n"
                                "MIIDCjCCAfKgAwIBAgIUG4RK8GxPy2GWUlo/mlcig+1/8aswDQYJKoZIhvcNAQEL\n"
                                "BQAwJTEjMCEGA1UEAwwaU29sYXJpcy1Nb2R1bGUtU2V0LVRlc3QtQ0EwHhcNMjYx\n"
                                "MTA2MTQyMTQ3WhcNMjYxMTA3MTQyMTQ3WjAlMSMwIQYDVQQDDBpTb2xhcmlzLU1v\n"
                                "ZHVsZS1TZXQtVGVzdC1DQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n"
                                "AL+IqzrIUZzQvDdhOw7Tc7o2ZghUKFJ2RuTNBgTASmft4ZIcqEw1IhxR5pNj05rB\n"
                                "ZDWWJvrPAOPmZsgpa3ttAsLcZignyLzbSzLNo9sjCZprvhinocy75Y8fmKkMM8ub\n"
                                "2e7mCYOFtu5mJfENkGlgqYrJeqdNFlymgCWJjVQlfr3NBgc55tTUaUXQ2srg5U/v\n"
                                "k5Y6OcbHtTRjRf7BxCdrzi0cbYhhqkSY2BVjy7IhB6dXkpTbUy2ZRv7vWwmCG9yJ\n"
                                "y1B892gO3c9wB6FUwssqVPtj60Bp3RWrsj3l7ZbGe3po9SiqXQkP3HUXhNI3qKIW\n"
                                "tfFJv9DM8yNWmMF5imZIaY0CAwEAAaMyMDAwHQYDVR0OBBYEFDAmBEvfyMcUdhRM\n"
                                "3tGzA34hvlSEMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJan\n"
                                "qmLvciVxyjub8Usr9l5pt2K4cmBLlFVH3wtKAMoM9hJx90OGBee86oOkGuMiR+lX\n"
                                "5xfW3YtjEsDZQivDBx4mRe72+a/o8qrbzey8R0ozS4+tCGwi1kYAvAHkfUOsqEbQ\n"
                                "1gWjbfmADUu8wfQJcUbfrg2XOYYnN6BBozc6DvC/jH4OrWUuplOvE1ci2eUIZHFU\n"
                                "sXOybwYhyWEA0/3ZrbXB+DD/1sU3jnuXJ3tYxe1ivUa2dGJyf9BcXr1b3QRdqdjz\n"
                                "bYD+yFeYlFe8T/1XuKF7KRiu63zF6hpR81E2rLPTQr2lFPiZQyxYslq/IdWGGDYU\n"
                                "I8JAikiWK/KDV94L0DM=\n"
                                "-----END CERTIFICATE-----\n";
#endif
static void tls_sets(solaris_budget_t *budget)
{
#if SOLARIS_HAS_ANYTLS
    solaris_config_t *image =
        config("[General]\n"
    "config-version = 1\n"
    "mode = rule\n"
    "\n"
    "[Proxy]\n"
    "\"secured\" = anytls, \"example.com\", \"443\", password=\"secret\"\n"
    "\n"
    "[Rule]\n"
    "FINAL,DIRECT\n");
    solaris_config_module_set_t *set = (void *)1;
    solaris_error_t error;
    CHECK(solaris_config_module_set_create(budget, image, NULL, 0, &set, &error) == SOLARIS_EINVAL && !set &&
          strstr(error.message, "secured"));
    CHECK(solaris_config_module_set_create(budget, image, "invalid trust", 13, &set, &error) == SOLARIS_EINVAL && !set);
    CHECK(solaris_config_module_set_create(budget, image, trust_pem, sizeof(trust_pem) - 1, &set, &error) ==
          SOLARIS_OK);
    size_t count;
    const solaris_config_node_t *nodes = solaris_config_nodes(image, &count);
    CHECK(count == 3 && !solaris_config_get(nodes[2].fields, "ca-pem"));
    solaris_config_release(image);
    solaris_config_module_set_release(set);
#else
    (void)budget;
#endif
}
int main(void)
{
    allocations_t allocations;
    atomic_init(&allocations.calls, 0);
    atomic_init(&allocations.fail, 0);
    atomic_init(&allocations.live, 0);
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = &allocations;
    services.allocate = allocate;
    services.deallocate = deallocate;
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(16 * 1024 * 1024, &services, &budget) == SOLARIS_OK);
    module_sets(budget, &allocations);
    tls_sets(budget);
    solaris_executor_t *owners[2];
    for (unsigned i = 0; i < 2; ++i) {
        solaris_executor_options_t options = {
            .id = i, .queue_capacity = 128, .resource_limit = 512, .budget = budget, .services = &services};
        CHECK(solaris_executor_create(&options, &owners[i]) == SOLARIS_OK);
        CHECK(solaris_executor_activate(owners[i], 1) == SOLARIS_OK);
    }
    solaris_replay_store_t *replay;
    CHECK(solaris_replay_create(budget, 128, 0, NULL, NULL, &replay) == SOLARIS_OK);
    uint8_t token[32] = {1};
    CHECK(solaris_replay_insert(replay, token) == SOLARIS_OK);
    generation_leases(budget, owners, replay);
    CHECK(solaris_replay_insert(replay, token) == SOLARIS_EACCESS);
    failure_rollback(budget, owners[0], replay, &allocations);
    rejected_factory_barrier(budget, owners[0]);
    for (unsigned i = 0; i < 2; ++i) {
        CHECK(solaris_executor_quiesce(owners[i]) == SOLARIS_OK);
        CHECK(solaris_executor_destroy(owners[i]) == SOLARIS_OK);
    }
    solaris_replay_release(replay);
    CHECK(solaris_budget_used(budget) == 0);
    solaris_budget_release(budget);
    CHECK(!atomic_load(&allocations.live));
    puts("runtime module sets/workers: owned trust, independent owners, effective UDP guards, old-generation lanes and "
         "rejection drain barriers passed");
    return 0;
}
