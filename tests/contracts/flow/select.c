#include "policy/select/select.h"
#include "support/runtime/event.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static atomic_uint created, destroyed, opens[2];
typedef struct node { solaris_outbound_t outbound; unsigned int id; int retired; } node_t;
static uint32_t capabilities(void *state)
{ node_t *node = state; return node->retired ? 0u : SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_DATAGRAM | (node->id == 2u ? SOLARIS_OUTBOUND_HALF_CLOSE : 0u); }
static solaris_status_t open_stream(void *state, const solaris_address_t *target,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    (void)target; (void)callbacks; (void)context; node_t *node = state; *out = NULL;
    if (node->retired) return SOLARIS_ECLOSED;
    atomic_fetch_add(&opens[node->id - 1u], 1u); return SOLARIS_EACCESS;
}
static solaris_status_t open_datagram(void *state, uint32_t family,
    const solaris_datagram_callbacks_t *callbacks, void *context, solaris_datagram_t **out)
{
    (void)family; (void)callbacks; (void)context; node_t *node = state; *out = NULL;
    if (node->retired) return SOLARIS_ECLOSED;
    atomic_fetch_add(&opens[node->id - 1u], 1u); return SOLARIS_EACCESS;
}
static void retire(void *state) { ((node_t *)state)->retired = 1; }
static const solaris_outbound_ops_t node_ops = {capabilities, open_stream, open_datagram, retire};
static solaris_status_t compile(const solaris_config_view_t *view, solaris_budget_t *budget, void **out, solaris_error_t *error)
{
    uint64_t id; solaris_status_t rc = solaris_config_uint(view, "id", 1u, 1u, 2u, &id, error);
    if (rc != SOLARIS_OK) return rc;
    unsigned int *value = solaris_memory_allocate(budget, sizeof(*value)); if (value == NULL) return SOLARIS_ENOMEM;
    *value = (unsigned int)id; *out = value; return SOLARIS_OK;
}
static solaris_status_t create(const void *config, const solaris_module_services_t *services,
    void **state, solaris_outbound_t **out, solaris_error_t *error)
{
    (void)error; node_t *node = solaris_memory_allocate(solaris_executor_budget(services->owner), sizeof(*node));
    if (node == NULL) return SOLARIS_ENOMEM;
    *node = (node_t){.outbound = {&node_ops, node, services->owner}, .id = *(const unsigned int *)config};
    *state = node; *out = &node->outbound; atomic_fetch_add(&created, 1u); return SOLARIS_OK;
}
static void destroy(void *state)
{ CHECK(((node_t *)state)->retired); atomic_fetch_add(&destroyed, 1u); solaris_memory_free(state); }
static const solaris_outbound_module_t descriptor = {
    .name = "test-node", .capabilities = SOLARIS_OUTBOUND_STREAM | SOLARIS_OUTBOUND_DATAGRAM,
    .compile = compile, .free_config = solaris_memory_free, .create = create, .retire = retire, .destroy = destroy
};
typedef struct worker {
    solaris_executor_t *owner;
    solaris_select_control_t *control;
    solaris_module_config_t **configs;
    solaris_module_instance_t *nodes[2];
    solaris_select_group_t *group;
    solaris_dial_plan_t first;
    solaris_test_event_t ready, group_closed, done;
    int limited;
} worker_t;
static void group_closed(void *context) { solaris_test_event_signal(&((worker_t *)context)->group_closed); }
static void start(void *context, solaris_status_t status)
{
    worker_t *worker = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = worker->owner};
    for (size_t i = 0u; i < 2u; ++i) CHECK(solaris_module_create(worker->configs[i], &services, NULL, NULL, &worker->nodes[i], NULL) == SOLARIS_OK);
    CHECK(solaris_select_group_create(worker->owner, worker->control, worker->nodes, 1u, group_closed, worker, &worker->group) == SOLARIS_EINVAL && worker->group == NULL);
    solaris_status_t rc = solaris_select_group_create(worker->owner, worker->control, worker->nodes, 2u, group_closed, worker, &worker->group);
    if (worker->limited) CHECK(rc == SOLARIS_EAGAIN && worker->group == NULL);
    else {
        CHECK(rc == SOLARIS_OK);
        CHECK(solaris_select_plan_acquire(worker->group, &worker->first) == SOLARIS_OK && worker->first.node_id == 1u && worker->first.selection_revision == 1u);
    }
    solaris_test_event_signal(&worker->ready);
}
static void verify_selection(void *context, solaris_status_t status)
{
    worker_t *worker = context; CHECK(status == SOLARIS_OK);
    solaris_dial_plan_t current; CHECK(solaris_select_plan_acquire(worker->group, &current) == SOLARIS_OK);
    CHECK(current.node_id == 2u && current.selection_revision == 2u && current.outbound != worker->first.outbound);
    uint32_t caps; CHECK(solaris_outbound_capabilities(solaris_select_outbound(worker->group), &caps) == SOLARIS_OK && (caps & SOLARIS_OUTBOUND_HALF_CLOSE));
    CHECK(solaris_outbound_capabilities(worker->first.outbound, &caps) == SOLARIS_OK && !(caps & SOLARIS_OUTBOUND_HALF_CLOSE));
    solaris_stream_callbacks_t stream_callbacks = {0}; solaris_datagram_callbacks_t datagram_callbacks = {0};
    solaris_address_t target; CHECK(solaris_address_parse("127.0.0.1", 80u, &target) == SOLARIS_OK);
    solaris_stream_t *stream; solaris_datagram_t *datagram;
    CHECK(solaris_outbound_open_stream(worker->first.outbound, &target, &stream_callbacks, NULL, &stream) == SOLARIS_EACCESS && stream == NULL);
    CHECK(solaris_outbound_open_stream(solaris_select_outbound(worker->group), &target, &stream_callbacks, NULL, &stream) == SOLARIS_EACCESS && stream == NULL);
    /* A later family lane still uses the pinned leaf after selection changes. */
    CHECK(solaris_outbound_open_datagram(worker->first.outbound, SOLARIS_ADDRESS_IPV6, &datagram_callbacks, NULL, &datagram) == SOLARIS_EACCESS && datagram == NULL);
    CHECK(solaris_dial_plan_release(&current) == SOLARIS_OK && current.outbound == NULL);
    CHECK(solaris_dial_plan_release(&current) == SOLARIS_OK);
    solaris_test_event_signal(&worker->done);
}
static void race(void *context, solaris_status_t status)
{
    worker_t *worker = context; CHECK(status == SOLARIS_OK);
    for (unsigned int i = 0u; i < 2000u; ++i) {
        solaris_dial_plan_t plan; CHECK(solaris_select_plan_acquire(worker->group, &plan) == SOLARIS_OK);
        CHECK(plan.node_id == ((plan.selection_revision & 1u) ? 1u : 2u));
        CHECK(solaris_dial_plan_release(&plan) == SOLARIS_OK);
    }
    CHECK(solaris_select_group_retire(worker->group) == SOLARIS_OK);
    solaris_dial_plan_t rejected; CHECK(solaris_select_plan_acquire(worker->group, &rejected) == SOLARIS_ECLOSED && rejected.outbound == NULL);
    solaris_test_event_signal(&worker->done);
}
static void finish(void *context, solaris_status_t status)
{
    worker_t *worker = context; CHECK(status == SOLARIS_OK);
    if (!worker->limited) {
        uint32_t caps; CHECK(solaris_outbound_capabilities(worker->first.outbound, &caps) == SOLARIS_OK && caps != 0u);
        CHECK(solaris_dial_plan_release(&worker->first) == SOLARIS_OK);
    }
    for (size_t i = 0u; i < 2u; ++i) CHECK(solaris_module_retire(worker->nodes[i]) == SOLARIS_OK);
    solaris_test_event_signal(&worker->done);
}
int main(void)
{
    solaris_budget_t *budget; CHECK(solaris_budget_create(8u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    char name[] = "first"; solaris_select_member_t members[] = {{1u, name}, {2u, "second"}};
    solaris_select_control_t *control;
    CHECK(solaris_select_control_create(budget, members, 2u, 3u, &control) == SOLARIS_EINVAL && control == NULL);
    members[1].id = 1u; CHECK(solaris_select_control_create(budget, members, 2u, 1u, &control) == SOLARIS_EINVAL); members[1].id = 2u;
    CHECK(solaris_select_control_create(budget, members, 2u, 1u, &control) == SOLARIS_OK); name[0] = 'x';
    solaris_select_member_snapshot_t member; CHECK(solaris_select_member_snapshot(control, 0u, &member) == SOLARIS_OK && strcmp(member.name, "first") == 0 && member.health == SOLARIS_HEALTH_UNKNOWN);
    uint64_t old, latest; CHECK(solaris_select_probe_begin(control, 1u, &old) == SOLARIS_OK && solaris_select_probe_begin(control, 1u, &latest) == SOLARIS_OK);
    CHECK(solaris_select_probe_finish(control, 1u, old, SOLARIS_OK, 10u, 2u) == SOLARIS_ECANCELLED);
    CHECK(solaris_select_probe_finish(control, 1u, latest, SOLARIS_EIO, 20u, 4u) == SOLARIS_OK);
    CHECK(solaris_select_probe_begin(control, 1u, &latest) == SOLARIS_OK);
    CHECK(solaris_select_probe_finish(control, 1u, latest, SOLARIS_ECANCELLED, 30u, 0u) == SOLARIS_OK);
    CHECK(solaris_select_member_snapshot(control, 0u, &member) == SOLARIS_OK && member.health == SOLARIS_HEALTH_FAIL && !member.checking);
    solaris_select_snapshot_t snapshot; CHECK(solaris_select_snapshot(control, &snapshot) == SOLARIS_OK && snapshot.selected_id == 1u && snapshot.revision == 1u);
    const solaris_outbound_module_t *descriptors[] = {&descriptor}; solaris_registry_t *registry;
    CHECK(solaris_registry_create(descriptors, 1u, budget, &registry, NULL) == SOLARIS_OK);
    solaris_module_config_t *configs[2];
    for (size_t i = 0u; i < 2u; ++i) {
        solaris_config_field_t field = {.name = "id", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = (int64_t)i + 1}};
        solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {.fields = &field, .count = 1u}};
        CHECK(solaris_registry_compile(registry, "test-node", &view, &configs[i], NULL) == SOLARIS_OK);
    }
    solaris_registry_destroy(registry); worker_t workers[3] = {{0}};
    for (size_t i = 0u; i < 3u; ++i) {
        worker_t *worker = &workers[i]; worker->control = control; worker->configs = configs; worker->limited = i == 2u;
        CHECK(solaris_test_event_init(&worker->ready, 0u) == 0 && solaris_test_event_init(&worker->done, 0u) == 0 && solaris_test_event_init(&worker->group_closed, 0u) == 0);
        solaris_executor_options_t options = {.id = (uint32_t)i, .queue_capacity = 4u, .resource_limit = i == 2u ? 2u : 32u, .budget = budget};
        CHECK(solaris_executor_create(&options, &worker->owner) == SOLARIS_OK && solaris_executor_activate(worker->owner, 1u) == SOLARIS_OK);
        CHECK(solaris_executor_post(worker->owner, start, worker) == SOLARIS_OK); solaris_test_event_wait(&worker->ready);
    }
    for (size_t i = 0u; i < 2u; ++i) solaris_module_config_release(configs[i]);
    CHECK(solaris_select_set(control, 2u) == SOLARIS_OK && solaris_select_set(control, 2u) == SOLARIS_OK);
    CHECK(solaris_select_set(control, 99u) == SOLARIS_EINVAL);
    for (size_t i = 0u; i < 2u; ++i) { CHECK(solaris_executor_post(workers[i].owner, verify_selection, &workers[i]) == SOLARIS_OK); solaris_test_event_wait(&workers[i].done); }
    CHECK(atomic_load(&opens[0]) == 4u && atomic_load(&opens[1]) == 2u);
    solaris_dial_plan_t foreign; CHECK(solaris_select_plan_acquire(workers[0].group, &foreign) == SOLARIS_ETHREAD);
    CHECK(solaris_dial_plan_release(&workers[0].first) == SOLARIS_ETHREAD);
    for (size_t i = 0u; i < 2u; ++i) CHECK(solaris_executor_post(workers[i].owner, race, &workers[i]) == SOLARIS_OK);
    for (unsigned int i = 0u; i < 2000u; ++i) CHECK(solaris_select_set(control, (i & 1u) ? 2u : 1u) == SOLARIS_OK);
    for (size_t i = 0u; i < 2u; ++i) { solaris_test_event_wait(&workers[i].done); solaris_test_event_wait(&workers[i].group_closed); }
    solaris_select_control_release(control);
    for (size_t i = 0u; i < 3u; ++i) {
        worker_t *worker = &workers[i]; CHECK(solaris_executor_post(worker->owner, finish, worker) == SOLARIS_OK); solaris_test_event_wait(&worker->done);
        CHECK(solaris_executor_quiesce(worker->owner) == SOLARIS_OK && solaris_executor_destroy(worker->owner) == SOLARIS_OK);
        solaris_test_event_destroy(&worker->ready); solaris_test_event_destroy(&worker->done); solaris_test_event_destroy(&worker->group_closed);
    }
    CHECK(atomic_load(&created) == 6u && atomic_load(&destroyed) == 6u);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
    puts("Select: shared selection, independent health, pinned leaves/revisions, two workers and retirement passed"); return 0;
}
