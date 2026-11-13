#include "contracts/dns/exchange.h"
#include "support/runtime/event.h"
#include "solaris_builtin_modules.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct environment {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_scope_t parent;
    solaris_deadline_t *action;
    solaris_dns_exchange_t *exchange;
    solaris_dns_wire_t *query;
    const solaris_dns_wire_t *response;
    solaris_tls_context_t *trust;
    char identity[254];
    solaris_dns_exchange_options_t options;
    solaris_dns_exchange_result_t result;
    solaris_test_event_t finished, stop_ready;
    const char *mode;
    uintptr_t last_handle;
    unsigned callbacks, policy_calls, tcp_policy, udp_policy, lookups;
    int accepted, socket_closed;
    uint64_t timeout_ms;
    atomic_size_t allocations, deallocations, calls, failed;
    atomic_uint_fast64_t clock_offset;
    atomic_int fail_at;
} environment_t;
static void *allocate(void *context, size_t size)
{
    environment_t *env = context;
    size_t call = atomic_fetch_add(&env->calls, 1) + 1;
    int fail = atomic_load(&env->fail_at);
    if (fail > 0 && call == (size_t)fail) { atomic_fetch_add(&env->failed, 1); return NULL; }
    void *p = malloc(size); if (p) atomic_fetch_add(&env->allocations, 1); return p;
}
static void deallocate(void *context, void *pointer)
{ environment_t *env = context; atomic_fetch_add(&env->deallocations, 1); free(pointer); }
static uint64_t now(void *context)
{ return uv_hrtime() + atomic_load(&((environment_t *)context)->clock_offset); }
static int socket_closed(environment_t *env)
{
    if (!env->policy_calls) return 1;
    int value = 0;
#ifdef _WIN32
    int size = (int)sizeof(value);
    return getsockopt((SOCKET)env->last_handle, SOL_SOCKET, SO_TYPE, (char *)&value, &size) != 0;
#else
    socklen_t size = (socklen_t)sizeof(value);
    return getsockopt((int)env->last_handle, SOL_SOCKET, SO_TYPE, &value, &size) != 0;
#endif
}
static solaris_status_t protect_socket(void *context, uintptr_t handle, uint32_t family, uint32_t kind)
{
    environment_t *env = context; CHECK(family == env->options.upstream.family);
    ++env->policy_calls; env->last_handle = handle;
    if (kind == SOLARIS_SOCKET_TCP) ++env->tcp_policy; else { CHECK(kind == SOLARIS_SOCKET_UDP); ++env->udp_policy; }
    if (!strcmp(env->mode, "deny")) return SOLARIS_EACCESS;
    if (!strcmp(env->mode, "deny_deadline") || !strcmp(env->mode, "network_deadline"))
        atomic_fetch_add(&env->clock_offset, (env->timeout_ms + 1) * UINT64_C(1000000));
    if (!strcmp(env->mode, "deny_deadline")) return SOLARIS_EACCESS;
    if (!strcmp(env->mode, "network_changed") || !strcmp(env->mode, "network_deadline")) return SOLARIS_ENETWORK_CHANGED;
    if (!strcmp(env->mode, "cancel_protect")) CHECK(solaris_dns_exchange_cancel(env->exchange) == SOLARIS_OK);
    if (!strcmp(env->mode, "deadline_protect")) atomic_fetch_add(&env->clock_offset, (env->timeout_ms + 1) * UINT64_C(1000000));
    return SOLARIS_OK;
}
static solaris_status_t no_lookup(void *context, solaris_executor_t *owner,
    const solaris_dns_lookup_view_t *view, const solaris_address_t *target,
    uint64_t deadline, solaris_resolve_fn callback, void *user, void **out)
{
    (void)owner; (void)view; (void)target; (void)deadline; (void)callback; (void)user;
    ++((environment_t *)context)->lookups; *out = NULL; return SOLARIS_EACCESS;
}
static void no_cancel(void *context, void *request) { (void)context; (void)request; CHECK(0); }
static void parent_closed(void *context)
{
    environment_t *env = context; CHECK(!env->exchange && !env->query && !env->action);
    CHECK(socket_closed(env)); solaris_test_event_signal(&env->finished);
}
static void action(void *context, solaris_status_t status)
{
    environment_t *env = context; env->action = NULL;
    if (status == SOLARIS_OK && env->exchange) {
        if (!strcmp(env->mode, "stop")) solaris_test_event_signal(&env->stop_ready);
        else CHECK(solaris_dns_exchange_cancel(env->exchange) == SOLARIS_OK);
    }
    solaris_scope_release(&env->parent);
}
static void done(void *context, solaris_dns_exchange_t *exchange, const solaris_dns_exchange_result_t *result)
{
    environment_t *env = context;
    CHECK(exchange == env->exchange && ++env->callbacks == 1);
    CHECK(solaris_executor_is_owner(env->owner));
    CHECK(result->view.config_revision == 11 && result->view.resolver_revision == 12 &&
        result->view.network_revision == 13 && result->view.selection_revision == 14);
    CHECK(result->view.role == (!strcmp(env->mode, "bootstrap") ? SOLARIS_DNS_BOOTSTRAP : SOLARIS_DNS_CLIENT_QUERY));
    CHECK(result->completed_ns >= result->started_ns && result->duration_ns == result->completed_ns - result->started_ns);
    CHECK(result->selected_alpn_length == 0 || (result->selected_alpn_length == 3 && !memcmp(result->selected_alpn, "dot", 3)));
    env->socket_closed = socket_closed(env); CHECK(env->socket_closed);
    env->result = *result;
    if (result->status == SOLARIS_OK) {
        CHECK(result->response); env->response = result->response; solaris_dns_wire_retain(env->response);
        CHECK(solaris_dns_wire_header(env->response)->id == 0x2345 && solaris_dns_wire_header(env->response)->rcode == 0);
        CHECK(solaris_dns_wire_record_count(env->response) == 1);
        CHECK(solaris_dns_wire_record(env->response, 0)->type == SOLARIS_DNS_A &&
            solaris_dns_wire_record(env->response, 0)->value.address[3] == 42);
    } else CHECK(!result->response);
    CHECK(solaris_dns_exchange_cancel(exchange) == SOLARIS_ECLOSED);
    env->exchange = NULL;
    if (!strcmp(env->mode, "stop")) solaris_test_event_signal(&env->stop_ready);
    if (env->action) solaris_deadline_cancel(env->action);
    solaris_scope_cancel(&env->parent);
}
static void start(void *context, solaris_status_t status)
{
    environment_t *env = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&env->parent, env->owner, NULL, parent_closed, env) == SOLARIS_OK);
    solaris_dns_exchange_options_t options = env->options;
    options.parent_scope = &env->parent;
    options.deadline_ns = solaris_executor_now_ns(env->owner) + env->timeout_ms * UINT64_C(1000000);
    if (!strcmp(env->mode, "expired")) options.deadline_ns = 1;
    if (!strcmp(env->mode, "missing_trust")) options.tls_trust = NULL;
    if (!strcmp(env->mode, "missing_identity")) options.tls_identity = NULL;
    if (!strcmp(env->mode, "invalid_identity")) options.tls_identity = "bad name";
    if (!strcmp(env->mode, "tlsfields_on_tcp")) options.transport = SOLARIS_DNS_TRANSPORT_TCP;
    const char *failure = strstr(env->mode, "fail_");
    if (failure) {
        atomic_store(&env->calls, 0); atomic_store(&env->fail_at, atoi(failure + 5));
    }
    solaris_status_t rc = solaris_dns_exchange_start(env->owner, env->query, &options, done, env, &env->exchange);
    solaris_dns_wire_release(env->query); env->query = NULL;
#if SOLARIS_HAS_TLS
    solaris_tls_context_release(env->trust); env->trust = NULL;
#endif
    memset(env->identity, 0xee, sizeof(env->identity));
    memset(&options, 0xee, sizeof(options)); /* retained options are independent */
    if (rc != SOLARIS_OK) {
        CHECK(!env->exchange); env->result.status = rc; env->socket_closed = 1;
        solaris_scope_cancel(&env->parent); return;
    }
    env->accepted = 1;
    if (!strcmp(env->mode, "cancel_before")) CHECK(solaris_dns_exchange_cancel(env->exchange) == SOLARIS_OK);
    if (!strcmp(env->mode, "cancel") || !strcmp(env->mode, "stop")) {
        solaris_scope_retain(&env->parent);
        CHECK(solaris_deadline_start(env->owner, 40, action, env, &env->action) == SOLARIS_OK);
    }
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--capabilities")) {
        printf("{\"tls\":%s}\n", SOLARIS_HAS_TLS ? "true" : "false"); return 0;
    }
    CHECK(argc == 6 || argc == 7);
    environment_t env = {0}; env.mode = argv[4]; env.timeout_ms = strtoull(argv[5], NULL, 10);
    CHECK(env.timeout_ms > 0 && env.timeout_ms <= 5000);
    solaris_runtime_services_t services = {&env, allocate, deallocate, now, NULL};
    CHECK(solaris_budget_create(8u * 1024u * 1024u, &services, &env.budget) == SOLARIS_OK);
    solaris_executor_options_t executor = {.id = 0, .queue_capacity = 16, .resource_limit = 128, .budget = env.budget, .services = &services};
    CHECK(solaris_executor_create(&executor, &env.owner) == SOLARIS_OK);
    CHECK(solaris_test_event_init(&env.finished, 0) == 0 && solaris_test_event_init(&env.stop_ready, 0) == 0);
    solaris_dns_exchange_options_init(&env.options);
    CHECK(solaris_address_parse(argv[1], (uint16_t)strtoul(argv[2], NULL, 10), &env.options.upstream) == SOLARIS_OK);
    if (!strcmp(env.mode, "invalid_domain"))
        CHECK(solaris_address_parse("localhost", env.options.upstream.port, &env.options.upstream) == SOLARIS_OK);
    if (!strcmp(env.mode, "port_zero")) env.options.upstream.port = 0;
    env.options.transport = !strcmp(argv[3], "tls") ? SOLARIS_DNS_TRANSPORT_TLS :
        !strcmp(argv[3], "tcp") ? SOLARIS_DNS_TRANSPORT_TCP : SOLARIS_DNS_TRANSPORT_UDP;
#if SOLARIS_HAS_TLS
    if (env.options.transport == SOLARIS_DNS_TRANSPORT_TLS) {
        CHECK(argc == 7);
        FILE *file = fopen(argv[6], "rb"); CHECK(file);
        char *pem = malloc(262145); CHECK(pem);
        size_t size = fread(pem, 1, 262145, file); CHECK(!ferror(file) && feof(file) && size && size <= 262144); fclose(file);
        CHECK(solaris_tls_context_create(env.budget, pem, size, &env.trust) == SOLARIS_OK);
        memset(pem, 0, size); free(pem);
        (void)snprintf(env.identity, sizeof(env.identity), "%s", !strcmp(env.mode, "wrong_name") ? "wrong.example" :
            !strcmp(env.mode, "numeric_identity") ? argv[1] : "localhost");
        env.options.tls_trust = env.trust; env.options.tls_identity = env.identity;
        env.options.tls_require_alpn = !strcmp(env.mode, "alpn_required") || !strcmp(env.mode, "alpn_missing") || !strcmp(env.mode, "alpn_mismatch");
    }
#endif
    env.options.view = (solaris_dns_lookup_view_t){.role = !strcmp(env.mode, "bootstrap") ? SOLARIS_DNS_BOOTSTRAP : SOLARIS_DNS_CLIENT_QUERY,
        .config_revision = 11, .resolver_revision = 12, .network_revision = 13, .selection_revision = 14};
    env.options.dialer.prepare_socket = protect_socket; env.options.dialer.policy_context = &env;
    env.options.dialer.lookup = (solaris_dns_lookup_t){&env, no_lookup, no_cancel};
    if (!strcmp(env.mode, "oversize")) env.options.wire_limits.message_bytes = 512;
    if (!strcmp(env.mode, "query_limit")) env.options.wire_limits.message_bytes = 12;
    solaris_dns_question_t question = {.type = SOLARIS_DNS_A, .class_code = SOLARIS_DNS_IN};
    CHECK(solaris_dns_name_from_text("wire.exchange.test", &question.name) == SOLARIS_OK);
    solaris_buffer_t *query;
    CHECK(solaris_dns_wire_make_query(env.budget, 0x2345, SOLARIS_DNS_RD, &question, NULL, &query) == SOLARIS_OK);
    CHECK(solaris_dns_wire_parse(env.budget, solaris_buffer_data(query), solaris_buffer_length(query), NULL, &env.query, NULL) == SOLARIS_OK);
    solaris_buffer_release(query);
    CHECK(solaris_executor_activate(env.owner, 1) == SOLARIS_OK);
    CHECK(solaris_executor_post(env.owner, start, &env) == SOLARIS_OK);
    if (!strcmp(env.mode, "stop")) { solaris_test_event_wait(&env.stop_ready); CHECK(solaris_executor_begin_quiesce(env.owner) == SOLARIS_OK); }
    solaris_test_event_wait(&env.finished);
    CHECK(solaris_executor_quiesce(env.owner) == SOLARIS_OK);
    CHECK(solaris_executor_destroy(env.owner) == SOLARIS_OK);
    CHECK(env.callbacks == (unsigned)env.accepted && !env.lookups);
    solaris_dns_wire_release(env.response); CHECK(solaris_budget_used(env.budget) == 0);
    solaris_budget_release(env.budget); CHECK(atomic_load(&env.allocations) == atomic_load(&env.deallocations));
    solaris_test_event_destroy(&env.finished); solaris_test_event_destroy(&env.stop_ready);
    printf("{\"status\":%d,\"accepted\":%d,\"callbacks\":%u,\"closed\":%d,\"udp\":%u,\"tcp\":%u,"
        "\"fallback\":%u,\"discarded_packets\":%llu,\"discarded_frames\":%llu,\"bytes_read\":%llu,\"bytes_written\":%llu,\"allocation_failures\":%zu,\"duration_ns\":%llu,\"alpn_length\":%zu}\n",
        env.result.status, env.accepted, env.callbacks, env.socket_closed, env.udp_policy, env.tcp_policy, env.result.tcp_fallback,
        (unsigned long long)env.result.discarded_packets, (unsigned long long)env.result.discarded_frames,
        (unsigned long long)env.result.bytes_read, (unsigned long long)env.result.bytes_written, atomic_load(&env.failed),
        (unsigned long long)env.result.duration_ns, env.result.selected_alpn_length);
    return 0;
}
