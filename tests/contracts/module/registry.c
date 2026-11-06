#include <solaris/core.h>
#include "contracts/module/module.h"
#include "runtime/engine/internal.h"
#include "solaris_builtin_modules.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)

static atomic_uint configs, states, retires, destroys;
typedef struct test_state {
    solaris_outbound_t outbound;
    solaris_scope_t *scope;
    solaris_deferred_t release;
    unsigned value;
    int retired;
} test_state_t;
static uint32_t test_caps(void *context)
{
    test_state_t *state = context;
    CHECK(solaris_executor_is_owner(state->outbound.owner));
    CHECK(state->value == 7u || state->value == 14u);
    return state->retired ? 0u : SOLARIS_OUTBOUND_STREAM;
}
static solaris_status_t test_stream(void *context, const solaris_address_t *address,
                                    const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    (void)address; (void)callbacks; (void)user; (void)out;
    return ((test_state_t *)context)->retired ? SOLARIS_ECLOSED : SOLARIS_EACCESS;
}
static solaris_status_t test_datagram(void *context, uint32_t family,
                                      const solaris_datagram_callbacks_t *callbacks, void *user, solaris_datagram_t **out)
{
    (void)context; (void)family; (void)callbacks; (void)user; (void)out;
    return SOLARIS_ENOTSUP;
}
static void release_lease(void *context)
{
    test_state_t *state = context;
    solaris_scope_release(state->scope);
}
static void test_retire(void *context)
{
    test_state_t *state = context;
    CHECK(!state->retired);
    state->retired = 1;
    atomic_fetch_add(&retires, 1u);
    state->release.run = release_lease; state->release.context = state;
    CHECK(solaris_executor_defer(state->outbound.owner, &state->release) == SOLARIS_OK);
}
static const solaris_outbound_ops_t test_ops = {test_caps, test_stream, test_datagram, test_retire};
static solaris_status_t test_compile(const solaris_config_view_t *view, solaris_budget_t *budget,
                                     void **out, solaris_error_t *error)
{
    static const char *const fields[] = {"value"};
    solaris_status_t rc = solaris_config_check_fields(view, fields, 1u, error);
    if (rc != SOLARIS_OK) return rc;
    uint64_t value;
    rc = solaris_config_uint(view, "value", 7u, 0u, 99u, &value, error);
    if (rc != SOLARIS_OK) return rc;
    unsigned *payload = solaris_memory_allocate(budget, sizeof(*payload));
    if (payload == NULL) return SOLARIS_ENOMEM;
    *payload = (unsigned)value; *out = payload;
    atomic_fetch_add(&configs, 1u);
    return value == 13u ? SOLARIS_EINVAL : SOLARIS_OK; /* partial compile cleanup */
}
static void test_free_config(void *payload)
{
    if (payload != NULL) { atomic_fetch_sub(&configs, 1u); solaris_memory_free(payload); }
}
static solaris_status_t test_create(const void *config, const solaris_module_services_t *services,
                                    void **state, solaris_outbound_t **out, solaris_error_t *error)
{
    (void)error;
    test_state_t *result = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*result));
    if (result == NULL) return SOLARIS_ENOMEM;
    memset(result, 0, sizeof(*result));
    result->outbound = (solaris_outbound_t){&test_ops, result, services->owner};
    result->scope = services->scope;
    result->value = *(const unsigned *)config;
    solaris_scope_retain(result->scope); /* asynchronous instance resource */
    *state = result; *out = &result->outbound;
    atomic_fetch_add(&states, 1u);
    return result->value == 14u ? SOLARIS_EIO : SOLARIS_OK;
}
static void test_destroy(void *context)
{
    test_state_t *state = context;
    CHECK(state->retired && solaris_executor_is_owner(state->outbound.owner));
    atomic_fetch_sub(&states, 1u); atomic_fetch_add(&destroys, 1u);
    solaris_memory_free(state);
}
static const char *const aliases[] = {"test-alias"};
static const solaris_outbound_module_t test_module = {
    .name = "test", .aliases = aliases, .alias_count = 1u,
    .capabilities = SOLARIS_OUTBOUND_STREAM,
    .compile = test_compile, .free_config = test_free_config, .create = test_create,
    .retire = test_retire, .destroy = test_destroy
};
static const solaris_config_view_t empty = {.kind = SOLARIS_CONFIG_MAP};

static void expect_registry_failure(const solaris_outbound_module_t *const *modules, size_t count,
                                      solaris_budget_t *budget, solaris_status_t expected, const char *message)
{
    solaris_registry_t *registry = (solaris_registry_t *)(uintptr_t)1;
    solaris_error_t error;
    size_t before = solaris_budget_used(budget);
    CHECK(solaris_registry_create(modules, count, budget, &registry, &error) == expected);
    CHECK(registry == NULL && error.code == expected && strstr(error.message, message) != NULL);
    CHECK(solaris_budget_used(budget) == before);
}
static void registry_validation(solaris_budget_t *budget)
{
    solaris_outbound_module_t a = test_module, b = test_module;
    b.name = "other"; b.aliases = NULL; b.alias_count = 0u;
    const solaris_outbound_module_t *modules[] = {&a, &b};
    solaris_registry_t *registry;
    CHECK(solaris_registry_create(modules, 2u, budget, &registry, NULL) == SOLARIS_OK);
    CHECK(solaris_registry_count(registry) == 2u && solaris_registry_find(registry, "test-alias") == &a);
    modules[0] = NULL; /* registry copied its pointer list */
    CHECK(solaris_registry_find(registry, "test") == &a);
    solaris_registry_destroy(registry);
    expect_registry_failure(modules, 2u, budget, SOLARIS_EINVAL, "invalid module");
    modules[0] = &a;
    b.name = "test";
    expect_registry_failure(modules, 2u, budget, SOLARIS_EINVAL, "duplicate");
    b.name = "test-alias";
    expect_registry_failure(modules, 2u, budget, SOLARIS_EINVAL, "duplicate");
    b.name = "other"; b.aliases = aliases; b.alias_count = 1u;
    expect_registry_failure(modules, 2u, budget, SOLARIS_EINVAL, "duplicate");
    b.aliases = NULL; b.alias_count = 0u;
    const char *repeated[] = {"test"};
    a.aliases = repeated;
    expect_registry_failure(modules, 2u, budget, SOLARIS_EINVAL, "duplicate");
    a = test_module;
    const char *needs_missing[] = {"missing"};
    a.dependencies = needs_missing; a.dependency_count = 1u;
    expect_registry_failure(modules, 2u, budget, SOLARIS_ENOTSUP, "missing dependency of test: missing");
    const char *needs_other[] = {"other"};
    a.dependencies = needs_other;
    b.dependencies = aliases; b.dependency_count = 1u;
    expect_registry_failure(modules, 2u, budget, SOLARIS_EINVAL, "cycle");
    a.dependencies = NULL; a.dependency_count = 0u;
    CHECK(solaris_registry_create(modules, 2u, budget, &registry, NULL) == SOLARIS_OK);
    solaris_registry_destroy(registry); /* dependency through an alias */
    CHECK(solaris_registry_create(NULL, 0u, budget, &registry, NULL) == SOLARIS_OK);
    CHECK(solaris_registry_count(registry) == 0u);
    solaris_registry_destroy(registry);
}

static void config_validation(solaris_budget_t *budget)
{
    const solaris_outbound_module_t *modules[] = {&test_module};
    solaris_registry_t *registry;
    CHECK(solaris_registry_create(modules, 1u, budget, &registry, NULL) == SOLARIS_OK);
    solaris_module_config_t *config = NULL;
    solaris_error_t error;
    CHECK(solaris_registry_compile(registry, "disabled", &empty, &config, &error) == SOLARIS_ENOTSUP);
    CHECK(config == NULL && strstr(error.message, "unknown or disabled") != NULL);
    solaris_config_field_t fields[] = {
        {.name = "value", .value = {.kind = SOLARIS_CONFIG_INTEGER, .line = 8u, .column = 4u, .value.integer = 13}},
        {.name = "value", .value = {.kind = SOLARIS_CONFIG_INTEGER, .line = 9u, .column = 2u, .value.integer = 7}}
    };
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {fields, 2u}};
    size_t before = solaris_budget_used(budget);
    CHECK(solaris_registry_compile(registry, "test", &view, &config, &error) == SOLARIS_EINVAL);
    CHECK(config == NULL && strstr(error.message, "9:2: duplicate") != NULL);
    view.value.map.count = 1u;
    CHECK(solaris_registry_compile(registry, "test", &view, &config, &error) == SOLARIS_EINVAL);
    CHECK(config == NULL && atomic_load(&configs) == 0u && solaris_budget_used(budget) == before);
    fields[0].value.value.integer = -1;
    CHECK(solaris_registry_compile(registry, "test", &view, &config, &error) == SOLARIS_EINVAL);
    CHECK(strstr(error.message, "8:4") != NULL);
    fields[0].name = "typo";
    CHECK(solaris_registry_compile(registry, "test", &view, &config, &error) == SOLARIS_EINVAL);
    CHECK(strstr(error.message, "unknown field") != NULL);
    fields[0].name = "value"; fields[0].value.kind = SOLARIS_CONFIG_STRING;
    fields[0].value.value.string.data = "7"; fields[0].value.value.string.length = 1u;
    CHECK(solaris_registry_compile(registry, "test", &view, &config, &error) == SOLARIS_EINVAL);
    char string[8];
    CHECK(solaris_config_string(&view, "value", 1, string, sizeof(string), &error) == SOLARIS_OK && strcmp(string, "7") == 0);
    fields[0].value.value.string.data = "a\0b"; fields[0].value.value.string.length = 3u;
    CHECK(solaris_config_string(&view, "value", 1, string, sizeof(string), &error) == SOLARIS_EINVAL);
    CHECK(solaris_config_string(&empty, "required", 1, string, sizeof(string), &error) == SOLARIS_EINVAL);
    CHECK(solaris_registry_compile(registry, "test-alias", &empty, &config, NULL) == SOLARIS_OK);
    solaris_registry_destroy(registry);
    solaris_module_config_retain(config); solaris_module_config_release(config); solaris_module_config_release(config);
    CHECK(atomic_load(&configs) == 0u);
}

typedef struct worker_case {
    solaris_module_config_t *config;
    solaris_module_config_t *failure;
    solaris_executor_t *owner;
    solaris_module_instance_t *instance;
    solaris_test_event_t ready;
    unsigned closes;
    int retire_now;
} worker_case_t;
static void instance_closed(void *context)
{
    worker_case_t *test = context;
    CHECK(solaris_executor_is_owner(test->owner));
    CHECK(solaris_module_outbound(test->instance) == NULL);
    CHECK(solaris_module_retire(test->instance) == SOLARIS_OK);
    test->instance = NULL; test->closes++;
}
static void create_on_worker(void *context, solaris_status_t status)
{
    worker_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = test->owner};
    solaris_module_instance_t *failure = NULL;
    CHECK(solaris_module_create(test->failure, &services, instance_closed, test, &failure, NULL) == SOLARIS_EIO);
    CHECK(failure == NULL); /* rejected factory never delivers on_close */
    CHECK(solaris_module_create(test->config, &services, instance_closed, test, &test->instance, NULL) == SOLARIS_OK);
    solaris_outbound_t *outbound = solaris_module_outbound(test->instance);
    uint32_t caps;
    CHECK(solaris_outbound_capabilities(outbound, &caps) == SOLARIS_OK && caps == SOLARIS_OUTBOUND_STREAM);
    if (test->retire_now) {
        CHECK(solaris_module_retire(test->instance) == SOLARIS_OK);
        CHECK(solaris_module_retire(test->instance) == SOLARIS_OK);
        CHECK(solaris_module_outbound(test->instance) == NULL);
        CHECK(solaris_outbound_capabilities(outbound, &caps) == SOLARIS_OK && caps == 0u);
    }
    solaris_test_event_signal(&test->ready);
}
static void factory_lifecycle(solaris_budget_t *budget)
{
    const solaris_outbound_module_t *modules[] = {&test_module};
    solaris_registry_t *registry;
    CHECK(solaris_registry_create(modules, 1u, budget, &registry, NULL) == SOLARIS_OK);
    solaris_module_config_t *config, *failure;
    solaris_config_field_t field = {.name = "value", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 7}};
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {&field, 1u}};
    CHECK(solaris_registry_compile(registry, "test", &view, &config, NULL) == SOLARIS_OK);
    field.value.value.integer = 14;
    CHECK(solaris_registry_compile(registry, "test", &view, &failure, NULL) == SOLARIS_OK);
    field.value.value.integer = 99; /* both compiled values must be independent */
    solaris_registry_destroy(registry);
    solaris_engine_options_t options; solaris_engine_options_init(&options); options.io_workers = 2u;
    solaris_engine_t *engine;
    CHECK(solaris_engine_create(&options, NULL, &engine, NULL) == SOLARIS_OK);
    uint64_t operation;
    CHECK(solaris_engine_start(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    worker_case_t cases[2] = {0};
    for (size_t i = 0; i < 2u; ++i) {
        cases[i].config = config; cases[i].failure = failure;
        cases[i].owner = solaris_runtime_executor(engine, (uint32_t)i); cases[i].retire_now = (int)i;
        CHECK(solaris_test_event_init(&cases[i].ready, 0) == 0);
        CHECK(solaris_executor_post(cases[i].owner, create_on_worker, &cases[i]) == SOLARIS_OK);
    }
    for (size_t i = 0; i < 2u; ++i) solaris_test_event_wait(&cases[i].ready);
    solaris_module_services_t services = {.owner = cases[0].owner};
    solaris_module_instance_t *wrong_thread;
    CHECK(solaris_module_create(config, &services, NULL, NULL, &wrong_thread, NULL) == SOLARIS_ETHREAD);
    CHECK(solaris_module_retire(cases[0].instance) == SOLARIS_ETHREAD);
    solaris_module_config_release(config); solaris_module_config_release(failure);
    CHECK(solaris_engine_stop(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    for (size_t i = 0; i < 2u; ++i) {
        CHECK(cases[i].closes == 1u && cases[i].instance == NULL);
        solaris_test_event_destroy(&cases[i].ready);
    }
    solaris_engine_snapshot_t snapshot;
    CHECK(solaris_engine_get_snapshot(engine, &snapshot, NULL) == SOLARIS_OK && snapshot.io_buffer_bytes == 0u);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    CHECK(atomic_load(&states) == 0u && atomic_load(&configs) == 0u);
    CHECK(atomic_load(&retires) == 4u && atomic_load(&destroys) == 4u);
}

static void builtin_registration(solaris_budget_t *budget)
{
    solaris_registry_t *registry;
    CHECK(solaris_builtin_registry_create(budget, &registry, NULL) == SOLARIS_OK);
    CHECK(solaris_registry_count(registry) == SOLARIS_BUILTIN_OUTBOUND_COUNT);
    CHECK((solaris_registry_find(registry, "direct") != NULL) == SOLARIS_HAS_DIRECT);
    CHECK((solaris_registry_find(registry, "block") != NULL) == SOLARIS_HAS_BLOCK);
    CHECK((solaris_registry_find(registry, "reject") != NULL) == SOLARIS_HAS_BLOCK);
    solaris_module_config_t *config;
    solaris_status_t rc = solaris_registry_compile(registry, "direct", &empty, &config, NULL);
    CHECK(rc == (SOLARIS_HAS_DIRECT ? SOLARIS_OK : SOLARIS_ENOTSUP));
    solaris_module_config_release(config);
    rc = solaris_registry_compile(registry, "reject", &empty, &config, NULL);
    CHECK(rc == (SOLARIS_HAS_BLOCK ? SOLARIS_OK : SOLARIS_ENOTSUP));
    solaris_module_config_release(config);
#if SOLARIS_HAS_DIRECT
    solaris_config_field_t field = {.name = "read-chunk-size", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 65537}};
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {&field, 1u}};
    solaris_error_t error;
    CHECK(solaris_registry_compile(registry, "direct", &view, &config, &error) == SOLARIS_EINVAL && config == NULL);
    CHECK(strstr(error.message, "read-chunk-size") != NULL);
    field.name = "bind-address"; field.value.kind = SOLARIS_CONFIG_STRING;
    field.value.value.string.data = "example.invalid"; field.value.value.string.length = 15u;
    CHECK(solaris_registry_compile(registry, "direct", &view, &config, &error) == SOLARIS_EINVAL);
    CHECK(strstr(error.message, "numeric local address") != NULL);
#endif
    solaris_registry_destroy(registry);
}

typedef struct allocation_fault {
    atomic_uint until_failure;
    atomic_uint live;
} allocation_fault_t;
static void *fault_allocate(void *context, size_t size)
{
    allocation_fault_t *fault = context;
    if (atomic_load(&fault->until_failure) != 0u && atomic_fetch_sub(&fault->until_failure, 1u) == 1u) return NULL;
    void *memory = malloc(size);
    if (memory != NULL) atomic_fetch_add(&fault->live, 1u);
    return memory;
}
static void fault_free(void *context, void *memory)
{
    allocation_fault_t *fault = context;
    if (memory != NULL) { atomic_fetch_sub(&fault->live, 1u); free(memory); }
}
typedef struct fault_case {
    allocation_fault_t *fault;
    solaris_executor_t *owner;
    solaris_module_config_t *config;
    solaris_test_event_t done;
} fault_case_t;
static void failing_factory(void *context, solaris_status_t status)
{
    fault_case_t *test = context;
    CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = test->owner};
    for (unsigned index = 1u; index <= 2u; ++index) {
        atomic_store(&test->fault->until_failure, index);
        solaris_module_instance_t *instance = NULL;
        solaris_error_t error;
        CHECK(solaris_module_create(test->config, &services, NULL, NULL, &instance, &error) == SOLARIS_ENOMEM);
        CHECK(instance == NULL && error.code == SOLARIS_ENOMEM);
        CHECK(atomic_load(&test->fault->until_failure) == 0u);
    }
    solaris_test_event_signal(&test->done);
}
static void allocation_failures(void)
{
    allocation_fault_t fault = {0};
    solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = &fault; services.allocate = fault_allocate; services.deallocate = fault_free;
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(1024u * 1024u, &services, &budget) == SOLARIS_OK);
    const solaris_outbound_module_t *modules[] = {&test_module};
    atomic_store(&fault.until_failure, 1u);
    expect_registry_failure(modules, 1u, budget, SOLARIS_ENOMEM, "out of memory");
    solaris_registry_t *registry;
    CHECK(solaris_registry_create(modules, 1u, budget, &registry, NULL) == SOLARIS_OK);
    size_t before = solaris_budget_used(budget);
    solaris_module_config_t *config;
    for (unsigned index = 1u; index <= 2u; ++index) {
        atomic_store(&fault.until_failure, index);
        solaris_error_t error;
        CHECK(solaris_registry_compile(registry, "test", &empty, &config, &error) == SOLARIS_ENOMEM);
        CHECK(config == NULL && error.code == SOLARIS_ENOMEM && solaris_budget_used(budget) == before);
    }
    CHECK(solaris_registry_compile(registry, "test", &empty, &config, NULL) == SOLARIS_OK);
    solaris_registry_destroy(registry);
    solaris_engine_t *engine;
    CHECK(solaris_runtime_create(NULL, NULL, &services, &engine, NULL) == SOLARIS_OK);
    uint64_t operation;
    CHECK(solaris_engine_start(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    fault_case_t test = {.fault = &fault, .owner = solaris_runtime_executor(engine, 0u), .config = config};
    CHECK(solaris_test_event_init(&test.done, 0) == 0);
    CHECK(solaris_executor_post(test.owner, failing_factory, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.done);
    solaris_module_config_release(config);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    solaris_test_event_destroy(&test.done);
    CHECK(solaris_budget_used(budget) == 0u && atomic_load(&configs) == 0u && atomic_load(&states) == 0u);
    solaris_budget_release(budget);
    CHECK(atomic_load(&fault.live) == 0u);
}

int main(void)
{
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    registry_validation(budget);
    config_validation(budget);
    factory_lifecycle(budget);
    builtin_registration(budget);
    CHECK(solaris_budget_used(budget) == 0u);
    solaris_budget_release(budget);
    allocation_failures();
    puts("module registry/config/factory/lifecycle contracts passed");
    return 0;
}
