#include <solaris/config.h>
#include "contracts/config/image.h"
#include "contracts/module/module.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define MAX_NODES 8

typedef struct worker {
    solaris_config_t *config;
    solaris_executor_t *owner;
    const solaris_config_node_t *nodes;
    size_t node_count;
    solaris_module_config_t **compiled;
    solaris_module_instance_t *instances[MAX_NODES];
    solaris_test_event_t done;
    size_t scenario;
    unsigned retains, releases, acquired;
    uint64_t selected, group, reject;
} worker_t;

static void pin(void *context)
{
    worker_t *worker = context;
    ++worker->retains;
    solaris_config_retain(worker->config);
}
static void unpin(void *context)
{
    worker_t *worker = context;
    ++worker->releases;
    solaris_config_release(worker->config);
}
static solaris_status_t acquire(void *context, solaris_executor_t *owner, uint64_t id,
    solaris_dial_plan_t *out, uint32_t *capabilities)
{
    worker_t *worker = context;
    CHECK(owner == worker->owner);
    ++worker->acquired;
    if (id == worker->group) id = worker->selected;
    for (size_t i = 0; i < worker->node_count; ++i) if (worker->nodes[i].id == id) {
        solaris_status_t status = solaris_module_plan_acquire(worker->instances[i], id, out);
        if (status != SOLARIS_OK) return status;
        CHECK(solaris_outbound_capabilities(out->outbound, capabilities) == SOLARIS_OK);
        if (!worker->nodes[i].udp_enabled) *capabilities &= ~SOLARIS_OUTBOUND_DATAGRAM;
        out->selection_revision = 7;
        return SOLARIS_OK;
    }
    return SOLARIS_EINVAL;
}
static void begin_route(worker_t *worker);
static void routed(void *context, solaris_status_t status, solaris_route_result_t *result)
{
    worker_t *worker = context;
    CHECK(solaris_executor_is_owner(worker->owner));
    CHECK(result->metadata.config_revision == 41 && result->metadata.selection_revision == 7);
    if (worker->scenario == 4) {
        CHECK(status == SOLARIS_ENOTSUP && result->plan.outbound == NULL);
    } else {
        CHECK(status == SOLARIS_OK);
        solaris_dial_plan_t plan;
        CHECK(solaris_route_result_take_plan(result, &plan) == SOLARIS_OK && plan.selection_revision == 7);
        uint64_t expected = worker->scenario == 0 ? worker->selected :
            worker->scenario == 2 ? worker->reject : solaris_config_direct_target(worker->config);
        CHECK(plan.node_id == expected);
        CHECK(plan.outbound->owner == worker->owner && result->plan.outbound == NULL);
        uint64_t rule = worker->scenario == 3 ? UINT64_MAX : worker->scenario;
        CHECK(result->rule_index == rule);
        if (worker->scenario == 0 || worker->scenario == 1)
            CHECK(!strcmp(result->metadata.destination.host, "api.example.com"));
        if (worker->scenario == 2) {
            /* Open the exact selected leaf: the configured REJECT policy is
             * observable through the real module, without network activity. */
            solaris_stream_t *stream = NULL;
            solaris_stream_callbacks_t callbacks = {0};
            CHECK(solaris_outbound_open_stream(plan.outbound, &result->dial_target,
                &callbacks, NULL, &stream) == SOLARIS_EACCESS && stream == NULL);
        }
        CHECK(solaris_dial_plan_release(&plan) == SOLARIS_OK);
    }
    if (++worker->scenario < 5) begin_route(worker);
    else {
        for (size_t i = 0; i < worker->node_count; ++i)
            CHECK(solaris_module_retire(worker->instances[i]) == SOLARIS_OK);
        solaris_test_event_signal(&worker->done);
    }
}
static void begin_route(worker_t *worker)
{
    solaris_route_options_t options = {0};
    options.owner = worker->owner;
    options.mode = worker->scenario == 3 ? SOLARIS_MODE_DIRECT :
        worker->scenario == 4 ? SOLARIS_MODE_GLOBAL : SOLARIS_MODE_RULE;
    options.direct_target = solaris_config_direct_target(worker->config);
    options.global_target = worker->group;
    options.rules = solaris_config_rules(worker->config, &options.rule_count);
    options.metadata.network = worker->scenario == 1 || worker->scenario == 4 ? SOLARIS_NETWORK_UDP : SOLARIS_NETWORK_TCP;
    options.metadata.config_revision = 41;
    options.metadata.selection_revision = 7;
    CHECK(solaris_address_parse("127.0.0.1", 43210, &options.metadata.source) == SOLARIS_OK);
    CHECK(solaris_address_parse(worker->scenario == 2 ? "127.0.0.2" : "api.example.com", 443,
        &options.metadata.destination) == SOLARIS_OK);
    options.timeout_ms = 5000;
    options.context = worker;
    options.retain = pin; options.release = unpin; options.acquire = acquire;
    options.done = routed; options.user = worker;
    solaris_route_job_t *job;
    CHECK(solaris_route_start(&options, &job) == SOLARIS_OK && job != NULL);
}
static void start(void *context, solaris_status_t status)
{
    worker_t *worker = context;
    CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = worker->owner};
    for (size_t i = 0; i < worker->node_count; ++i)
        CHECK(solaris_module_create(worker->compiled[i], &services, NULL, NULL,
            &worker->instances[i], NULL) == SOLARIS_OK);
    begin_route(worker);
}
int main(void)
{
    char input[] =
        "mode: rule\n"
        "proxies:\n"
        "  - {name: tcp-only, type: socks5, server: 127.0.0.1, port: 1080, udp: false}\n"
        "proxy-groups:\n"
        "  - {name: chosen, type: select, proxies: [tcp-only, DIRECT]}\n"
        "rules:\n"
        "  - DOMAIN-SUFFIX,example.com,chosen\n"
        "  - NETWORK,udp,DIRECT\n"
        "  - IP-CIDR,127.0.0.0/8,REJECT,no-resolve\n"
        "  - MATCH,DIRECT\n";
    solaris_config_t *config;
    solaris_diagnostics_t *diagnostics;
    solaris_error_t error;
    solaris_status_t status = solaris_config_compile_bytes(input, strlen(input), NULL, &config, &diagnostics, &error);
    if (status != SOLARIS_OK) fprintf(stderr, "compile failed: %s\n", error.message);
    CHECK(status == SOLARIS_OK);
    solaris_diagnostics_release(diagnostics);
    memset(input, 0, sizeof(input));
    size_t count, group_count;
    const solaris_config_node_t *nodes = solaris_config_nodes(config, &count);
    const solaris_config_group_t *groups = solaris_config_groups(config, &group_count);
    CHECK(count <= MAX_NODES && group_count >= 1);
    uint64_t group = 0, selected = 0, reject = 0;
    for (size_t i = 0; i < group_count; ++i) if (!strcmp(groups[i].name, "chosen")) {
        group = groups[i].id; selected = groups[i].selected_id;
    }
    for (size_t i = 0; i < count; ++i) if (!strcmp(nodes[i].name, "REJECT")) reject = nodes[i].id;
    CHECK(group && selected && reject);
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(4 * 1024 * 1024, NULL, &budget) == SOLARIS_OK);
    solaris_registry_t *registry;
    CHECK(solaris_builtin_registry_create(budget, &registry, &error) == SOLARIS_OK);
    solaris_module_config_t *compiled[MAX_NODES] = {0};
    for (size_t i = 0; i < count; ++i) {
        CHECK(solaris_config_get(nodes[i].fields, "name") == NULL);
        CHECK(solaris_config_get(nodes[i].fields, "type") == NULL);
        CHECK(solaris_config_get(nodes[i].fields, "udp") == NULL);
        CHECK(solaris_registry_compile(registry, nodes[i].type, nodes[i].fields, &compiled[i], &error) == SOLARIS_OK);
    }
    solaris_registry_destroy(registry);
    worker_t workers[2] = {{0}};
    for (size_t i = 0; i < 2; ++i) {
        worker_t *worker = &workers[i];
        worker->config = config; worker->nodes = nodes; worker->node_count = count; worker->compiled = compiled;
        worker->group = group; worker->selected = selected; worker->reject = reject;
        CHECK(solaris_test_event_init(&worker->done, 0) == 0);
        solaris_executor_options_t options = {.id = (uint32_t)i, .queue_capacity = 8, .resource_limit = 64, .budget = budget};
        CHECK(solaris_executor_create(&options, &worker->owner) == SOLARIS_OK);
        CHECK(solaris_executor_activate(worker->owner, 1) == SOLARIS_OK);
        CHECK(solaris_executor_post(worker->owner, start, worker) == SOLARIS_OK);
    }
    for (size_t i = 0; i < 2; ++i) {
        worker_t *worker = &workers[i];
        solaris_test_event_wait(&worker->done);
        CHECK(solaris_executor_quiesce(worker->owner) == SOLARIS_OK);
        CHECK(solaris_executor_destroy(worker->owner) == SOLARIS_OK);
        CHECK(worker->scenario == 5 && worker->retains == 5 && worker->releases == 5 && worker->acquired == 6);
        solaris_test_event_destroy(&worker->done);
    }
    for (size_t i = 0; i < count; ++i) solaris_module_config_release(compiled[i]);
    solaris_config_release(config);
    CHECK(solaris_budget_used(budget) == 0);
    solaris_budget_release(budget);
    puts("YAML image -> real module configs -> two-owner route plans, UDP filtering and revisions passed");
    return 0;
}
