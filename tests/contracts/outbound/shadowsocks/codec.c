#include "adapters/outbound/shadowsocks/internal.h"
#include "adapters/outbound/shadowsocks/packet.h"
#include "codec/address/socks.h"
#include "runtime/engine/internal.h"
#include "support/runtime/event.h"
#include <openssl/base64.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static uint64_t fixed_time(void *context) { (void)context; return UINT64_C(1700000000); }
static solaris_status_t fixed_random(void *context, uint8_t *bytes, size_t size)
{ memset(bytes, context == NULL ? 0x42 : 0x43, size); return SOLARIS_OK; }
static solaris_status_t failed_random(void *context, uint8_t *bytes, size_t size)
{ (void)context; (void)bytes; (void)size; return SOLARIS_EIO; }
static const char *const methods[] = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"};
static const char *password(unsigned int method)
{ return method == 3u ? "SUlJSUlJSUlJSUlJSUlJSQ==" : method >= 4u ? "SUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUk=" : "solaris-independent-peer"; }
static solaris_status_t parse(void *codec, const uint8_t *wire, size_t length, size_t *received, int large)
{
    const solaris_stream_codec_ops_t *ops = &solaris_ss_stream_codec;
    size_t begin = 0u, end = 0u; *received = 0u;
    while (begin < length) {
        if (end < length) { size_t step = 113u; if (step > length - end) step = length - end; end += step; }
        size_t consumed = 0u; solaris_buffer_t *plain = NULL;
        solaris_status_t rc = ops->decode(codec, wire + begin, end - begin, &consumed, &plain);
        CHECK(consumed <= end - begin); begin += consumed;
        if (rc == SOLARIS_EAGAIN) {
            CHECK(plain == NULL && consumed == 0u);
            if (end == length) return SOLARIS_EIO;
            continue;
        }
        if (rc != SOLARIS_OK) { solaris_buffer_release(plain); return rc; }
        CHECK(consumed != 0u || plain != NULL);
        if (plain != NULL) {
            size_t size = solaris_buffer_length(plain);
            for (size_t i = 0u; i < size; ++i) CHECK(solaris_buffer_data(plain)[i] == (large ? 0x5a : (uint8_t)"hello"[i]));
            *received += size; solaris_buffer_release(plain);
        }
    }
    return ops->finish(codec);
}
typedef struct replay_race { solaris_replay_store_t *store; solaris_status_t result; } replay_race_t;
static void insert(void *context)
{ replay_race_t *race = context; const uint8_t token[32] = {1}; race->result = solaris_replay_insert(race->store, token); }
static uint64_t monotonic(void *context) { return *(const uint64_t *)context; }
static solaris_status_t packet_check(solaris_ss_packet_t *codec, const char *directory, unsigned int method,
    unsigned int variant, int success)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/packet-%u-%u.bin", directory, method, variant) > 0);
    FILE *file = fopen(path, "rb"); CHECK(file != NULL);
    uint8_t wire[66000]; size_t length = fread(wire, 1u, sizeof(wire), file); CHECK(length > 0u && feof(file)); fclose(file);
    solaris_buffer_t *plain = NULL; solaris_address_t source;
    solaris_status_t rc = solaris_ss_packet_decode(codec, wire, length, &source, &plain);
    CHECK(success ? rc == SOLARIS_OK : rc != SOLARIS_OK);
    if (success) {
        solaris_address_t expected; CHECK(solaris_address_parse(variant == 15u ? "example.com" : "127.0.0.1", 443u, &expected) == SOLARIS_OK);
        CHECK(solaris_address_equal(&source, &expected));
        size_t size = solaris_buffer_length(plain); CHECK(size == (variant == 17u ? 65000u : variant == 16u ? 0u : 5u));
        for (size_t i = 0u; i < size; ++i) CHECK(solaris_buffer_data(plain)[i] == (variant == 17u ? 0x5a : (uint8_t)"hello"[i]));
    }
    solaris_buffer_release(plain); return rc;
}
static void *fail_allocate(void *context, size_t size) { return *(const int *)context ? NULL : malloc(size); }
static void packet_tests(const char *directory, solaris_budget_t *budget)
{
    for (unsigned int method = 0u; method < 6u; ++method) {
        solaris_ss_parameters_t parameters = {.source = {.random = fixed_random, .unix_seconds = fixed_time}};
        CHECK(solaris_ss_key_parse(methods[method], password(method), &parameters.key) == SOLARIS_OK);
        CHECK(solaris_replay_create(budget, 64u, 0u, NULL, NULL, &parameters.replay) == SOLARIS_OK);
        solaris_ss_packet_t *codec; uint64_t clock = 0u;
        CHECK(solaris_ss_packet_create(budget, &parameters, monotonic, &clock, &codec) == SOLARIS_OK);
        packet_check(codec, directory, method, 0u, 1);
        CHECK(packet_check(codec, directory, method, 0u, 0) == SOLARIS_EACCESS);
        packet_check(codec, directory, method, 1u, 0); packet_check(codec, directory, method, 6u, 0);
        packet_check(codec, directory, method, 13u, 0);
        if (method >= 3u) {
            for (unsigned int variant = 2u; variant <= 5u; ++variant) packet_check(codec, directory, method, variant, 0);
            /* All malformed packets used ID 11; none can reserve it. */
            packet_check(codec, directory, method, 18u, 1);
            packet_check(codec, directory, method, 7u, 1); packet_check(codec, directory, method, 8u, 0);
            packet_check(codec, directory, method, 9u, 1); packet_check(codec, directory, method, 10u, 0);
            packet_check(codec, directory, method, 11u, 1); packet_check(codec, directory, method, 12u, 0);
            clock = UINT64_C(59000000000); packet_check(codec, directory, method, 8u, 0);
            clock = UINT64_C(60000000000); packet_check(codec, directory, method, 8u, 1);
        }
        solaris_ss_packet_destroy(codec);
        for (unsigned int variant = 15u; variant <= 17u; ++variant) {
            CHECK(solaris_ss_packet_create(budget, &parameters, monotonic, &clock, &codec) == SOLARIS_OK);
            packet_check(codec, directory, method, variant, 1); solaris_ss_packet_destroy(codec);
        }
        solaris_replay_release(parameters.replay);
        /* Allocation failure must not commit a packet ID/salt. */
        int fail = 0; solaris_runtime_services_t services; solaris_runtime_services_init(&services);
        services.context = &fail; services.allocate = fail_allocate;
        solaris_budget_t *failing; CHECK(solaris_budget_create(1024u * 1024u, &services, &failing) == SOLARIS_OK);
        CHECK(solaris_replay_create(failing, 32u, 0u, NULL, NULL, &parameters.replay) == SOLARIS_OK);
        CHECK(solaris_ss_packet_create(failing, &parameters, monotonic, &clock, &codec) == SOLARIS_OK);
        fail = 1; CHECK(packet_check(codec, directory, method, 0u, 0) == SOLARIS_ENOMEM);
        fail = 0; packet_check(codec, directory, method, 0u, 1);
        solaris_ss_packet_destroy(codec); solaris_replay_release(parameters.replay);
        CHECK(solaris_budget_used(failing) == 0u); solaris_budget_release(failing);
    }
}
static void check_wire(const char *directory, const char *kind, unsigned int method, unsigned int depth,
    const solaris_buffer_t *buffer)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/request-%s-%u-%u.bin", directory, kind, method, depth) > 0);
    FILE *file = fopen(path, "rb"); CHECK(file != NULL);
    uint8_t expected[2048]; size_t length = fread(expected, 1u, sizeof(expected), file); CHECK(feof(file)); fclose(file);
    CHECK(length == solaris_buffer_length(buffer)); CHECK(memcmp(expected, solaris_buffer_data(buffer), length) == 0);
}
static void request_allocation_test(const char *directory, unsigned int method, unsigned int depth,
    const solaris_ss_parameters_t *parameters)
{
    int fail = 0; solaris_runtime_services_t services; solaris_runtime_services_init(&services);
    services.context = &fail; services.allocate = fail_allocate;
    solaris_budget_t *budget; CHECK(solaris_budget_create(1024u * 1024u, &services, &budget) == SOLARIS_OK);
    const solaris_stream_codec_ops_t *ops = &solaris_ss_stream_codec; void *stream = NULL;
    fail = 1; CHECK(ops->create(parameters, budget, &stream) == SOLARIS_ENOMEM);
    fail = 0; CHECK(ops->create(parameters, budget, &stream) == SOLARIS_OK);
    solaris_buffer_t *wire = NULL;
    fail = 1; CHECK(ops->start(stream, &wire) == SOLARIS_ENOMEM && wire == NULL);
    ops->destroy(stream);
    uint64_t clock = 0u; solaris_ss_packet_t *packet = NULL;
    CHECK(solaris_ss_packet_create(budget, parameters, monotonic, &clock, &packet) == SOLARIS_ENOMEM && packet == NULL);
    fail = 0; CHECK(solaris_ss_packet_create(budget, parameters, monotonic, &clock, &packet) == SOLARIS_OK);
    solaris_buffer_t *payload; CHECK(solaris_buffer_copy(budget, "hello", 5u, &payload) == SOLARIS_OK);
    solaris_slice_t slice = {.buffer = payload, .length = 5u};
    fail = 1; CHECK(solaris_ss_packet_encode(packet, &parameters->destination, &slice, &wire) == SOLARIS_ENOMEM && wire == NULL);
    fail = 0; CHECK(solaris_ss_packet_encode(packet, &parameters->destination, &slice, &wire) == SOLARIS_OK);
    check_wire(directory, "packet", method, depth, wire);
    solaris_buffer_release(payload); solaris_buffer_release(wire); solaris_ss_packet_destroy(packet);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
}
static void request_tests(const char *directory, solaris_budget_t *budget)
{
    const unsigned int depths[] = {0u, 1u, 2u, 8u};
    for (unsigned int method = 3u; method < 6u; ++method) for (size_t d = 0u; d < (method == 5u ? 1u : 4u); ++d) {
        unsigned int depth = depths[d]; char chain[1025] = {0}; size_t pos = 0u;
        for (unsigned int i = 0u; i < depth; ++i) {
            uint8_t identity[32]; memset(identity, 0x10u + i, sizeof(identity));
            pos += (size_t)EVP_EncodeBlock((uint8_t *)chain + pos, identity, method == 3u ? 16u : 32u);
            chain[pos++] = ':';
        }
        strcpy(chain + pos, password(method));
        solaris_ss_parameters_t parameters = {.source = {.random = fixed_random, .unix_seconds = fixed_time}};
        CHECK(solaris_ss_key_parse(methods[method], chain, &parameters.key) == SOLARIS_OK);
        CHECK(parameters.key.identity_count == depth);
        CHECK(solaris_address_parse("example.com", 443u, &parameters.destination) == SOLARIS_OK);
        request_allocation_test(directory, method, depth, &parameters);
        void *stream; CHECK(solaris_ss_stream_codec.create(&parameters, budget, &stream) == SOLARIS_OK);
        solaris_buffer_t *wire = NULL;
        CHECK(solaris_ss_stream_codec.start(stream, &wire) == SOLARIS_OK);
        check_wire(directory, "stream", method, depth, wire); solaris_buffer_release(wire);
        solaris_ss_stream_codec.destroy(stream);
        uint64_t clock = 0u; solaris_ss_packet_t *packet;
        CHECK(solaris_ss_packet_create(budget, &parameters, monotonic, &clock, &packet) == SOLARIS_OK);
        solaris_buffer_t *payload; CHECK(solaris_buffer_copy(budget, "hello", 5u, &payload) == SOLARIS_OK);
        solaris_slice_t slice = {.buffer = payload, .length = 5u};
        CHECK(solaris_ss_packet_encode(packet, &parameters.destination, &slice, &wire) == SOLARIS_OK);
        check_wire(directory, "packet", method, depth, wire); solaris_buffer_release(wire); solaris_buffer_release(payload);
        /* EIH never changes response keys: the independent reply is encrypted
         * only with the final user PSK, with no identity headers. */
        packet_check(packet, directory, method, 0u, 1);
        packet_check(packet, directory, method, 0u, 0);
        solaris_ss_packet_destroy(packet);
        if (depth == SOLARIS_SS_MAX_IDENTITIES) {
            strcat(chain, ":"); strcat(chain, password(method));
            CHECK(solaris_ss_key_parse(methods[method], chain, &parameters.key) == SOLARIS_EINVAL);
        }
    }
    solaris_ss_key_t key;
    char invalid[128];
    for (unsigned int method = 3u; method < 6u; ++method) {
        CHECK(snprintf(invalid, sizeof(invalid), ":%s", password(method)) > 0);
        CHECK(solaris_ss_key_parse(methods[method], invalid, &key) == SOLARIS_EINVAL);
        CHECK(snprintf(invalid, sizeof(invalid), "%s:", password(method)) > 0);
        CHECK(solaris_ss_key_parse(methods[method], invalid, &key) == SOLARIS_EINVAL);
        CHECK(snprintf(invalid, sizeof(invalid), "%s:%s", password(method), password(method == 3u ? 4u : 3u)) > 0);
        CHECK(solaris_ss_key_parse(methods[method], invalid, &key) == SOLARIS_EINVAL);
    }
    CHECK(snprintf(invalid, sizeof(invalid), "%s:%s", password(5u), password(5u)) > 0);
    CHECK(solaris_ss_key_parse(methods[5], invalid, &key) == SOLARIS_EINVAL);
}
static void replay_test(solaris_budget_t *budget)
{
    solaris_replay_store_t *store; CHECK(solaris_replay_create(budget, 8u, 0u, NULL, NULL, &store) == SOLARIS_OK);
    uv_thread_t threads[8]; replay_race_t races[8];
    for (size_t i = 0u; i < 8u; ++i) { races[i].store = store; CHECK(uv_thread_create(&threads[i], insert, &races[i]) == 0); }
    unsigned int accepted = 0u;
    for (size_t i = 0u; i < 8u; ++i) {
        CHECK(uv_thread_join(&threads[i]) == 0); CHECK(races[i].result == SOLARIS_OK || races[i].result == SOLARIS_EACCESS);
        accepted += races[i].result == SOLARIS_OK;
    }
    CHECK(accepted == 1u && solaris_replay_is_persistent(store)); solaris_replay_release(store);
    uint64_t clock = 0u; CHECK(solaris_replay_create(budget, 2u, 60u, monotonic, &clock, &store) == SOLARIS_OK);
    uint8_t token[32] = {1}; CHECK(solaris_replay_insert(store, token) == SOLARIS_OK);
    token[0] = 2; CHECK(solaris_replay_insert(store, token) == SOLARIS_OK);
    token[0] = 3; CHECK(solaris_replay_insert(store, token) == SOLARIS_EBUSY);
    token[0] = 1; clock = 59u; CHECK(solaris_replay_insert(store, token) == SOLARIS_EACCESS);
    clock = 60u; CHECK(solaris_replay_insert(store, token) == SOLARIS_OK);
    CHECK(solaris_replay_insert(store, token) == SOLARIS_EACCESS);
    solaris_replay_release(store);
}
static void config_tests(solaris_budget_t *budget)
{
    solaris_registry_t *registry;
    CHECK(solaris_builtin_registry_create(budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[] = {
        {.name = "server", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"127.0.0.1", 9u}}},
        {.name = "port", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 443}},
        {.name = "cipher", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"aes-128-gcm", 11u}}},
        {.name = "password", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"secret", 6u}}},
        {.name = "udp-over-tcp", .value = {.kind = SOLARIS_CONFIG_BOOL, .value.boolean = 1}}
    };
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {fields, sizeof(fields) / sizeof(fields[0])}};
    solaris_module_config_t *compiled;
    CHECK(solaris_registry_compile(registry, "ss", &view, &compiled, NULL) == SOLARIS_OK);
    solaris_module_config_release(compiled);
    fields[4].value.kind = SOLARIS_CONFIG_INTEGER; fields[4].value.value.integer = 1;
    CHECK(solaris_registry_compile(registry, "ss", &view, &compiled, NULL) == SOLARIS_EINVAL && compiled == NULL);
    fields[4].value.kind = SOLARIS_CONFIG_BOOL; fields[4].value.value.boolean = 0;
    CHECK(solaris_registry_compile(registry, "ss", &view, &compiled, NULL) == SOLARIS_OK);
    solaris_module_config_release(compiled);
    fields[4].name = "unknown-udp";
    CHECK(solaris_registry_compile(registry, "ss", &view, &compiled, NULL) == SOLARIS_EINVAL && compiled == NULL);
    view.value.map.count = 2u;
    CHECK(solaris_registry_compile(registry, "ss", &view, &compiled, NULL) == SOLARIS_EINVAL && compiled == NULL);
    solaris_registry_destroy(registry);
}
typedef struct plugin_case {
    solaris_executor_t *owner;
    solaris_module_config_t *configs[2];
    solaris_stream_plugin_provider_t provider;
    solaris_test_event_t ready;
    unsigned int creates, opens, retires, destroys, closes;
    int reject;
} plugin_case_t;
typedef struct plugin_state {
    plugin_case_t *test;
    solaris_scope_t *scope;
    solaris_deferred_t release;
    int retired;
} plugin_state_t;
static solaris_status_t plugin_open(void *context, solaris_executor_t *owner,
    const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *user, solaris_stream_t **out)
{
    plugin_state_t *state = context;
    (void)options; (void)callbacks; (void)user;
    CHECK(owner == state->test->owner && peer->port == 443u && !state->retired);
    state->test->opens++; *out = NULL; return SOLARIS_ENOTSUP;
}
static void plugin_release(void *context)
{ plugin_state_t *state = context; solaris_scope_release(state->scope); }
static void plugin_retire(void *context)
{
    plugin_state_t *state = context; CHECK(!state->retired); state->retired = 1;
    state->test->retires++; state->release.run = plugin_release; state->release.context = state;
    CHECK(solaris_executor_defer(state->test->owner, &state->release) == SOLARIS_OK);
}
static void plugin_destroy(void *context)
{
    plugin_state_t *state = context; CHECK(state->retired);
    state->test->destroys++; solaris_memory_free(state);
}
static solaris_status_t plugin_create(void *context, const solaris_stream_plugin_request_t *request,
    solaris_stream_plugin_binding_t *out, solaris_error_t *error)
{
    (void)error; plugin_case_t *test = context; test->creates++;
    CHECK(strcmp(request->name, "fixture") == 0 && strcmp(request->options, "opaque=value") == 0);
    CHECK(request->owner == test->owner && request->scope != NULL && request->server.port == 443u);
    if (test->reject) return SOLARIS_ENOTSUP;
    plugin_state_t *state = solaris_memory_allocate(solaris_executor_budget(test->owner), sizeof(*state));
    CHECK(state != NULL); memset(state, 0, sizeof(*state)); state->test = test; state->scope = request->scope;
    solaris_scope_retain(state->scope);
    *out = (solaris_stream_plugin_binding_t){.carrier = {.context = state, .open = plugin_open},
        .state = state, .retire = plugin_retire, .destroy = plugin_destroy};
    return SOLARIS_OK;
}
static void unexpected_stream(void *context, solaris_stream_t *stream, solaris_status_t status)
{ (void)context; (void)stream; (void)status; CHECK(0); }
static void unexpected_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{ (void)context; (void)stream; (void)buffer; CHECK(0); }
static void unexpected_packet(void *context, solaris_datagram_t *packet, solaris_status_t status)
{ (void)context; (void)packet; (void)status; CHECK(0); }
static void unexpected_payload(void *context, solaris_datagram_t *packet, const solaris_address_t *source, const solaris_buffer_t *buffer)
{ (void)context; (void)packet; (void)source; (void)buffer; CHECK(0); }
static void plugin_closed(void *context) { ((plugin_case_t *)context)->closes++; }
static void plugin_worker(void *context, solaris_status_t status)
{
    plugin_case_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = test->owner};
    solaris_module_instance_t *instance = NULL;
    CHECK(solaris_module_create(test->configs[0], &services, plugin_closed, test, &instance, NULL) == SOLARIS_ENOTSUP && instance == NULL);
    test->provider = (solaris_stream_plugin_provider_t){.context = test, .create = plugin_create};
    services.stream_plugin = &test->provider; test->reject = 1;
    CHECK(solaris_module_create(test->configs[0], &services, plugin_closed, test, &instance, NULL) == SOLARIS_ENOTSUP && instance == NULL);
    test->reject = 0;
    for (unsigned int uot = 0u; uot < 2u; ++uot) {
        CHECK(solaris_module_create(test->configs[uot], &services, plugin_closed, test, &instance, NULL) == SOLARIS_OK);
        solaris_outbound_t *outbound = solaris_module_outbound(instance); uint32_t caps;
        CHECK(solaris_outbound_capabilities(outbound, &caps) == SOLARIS_OK);
        CHECK(((caps & SOLARIS_OUTBOUND_DATAGRAM) != 0u) == (uot != 0u));
        solaris_address_t target; CHECK(solaris_address_parse("example.com", 80u, &target) == SOLARIS_OK);
        solaris_stream_callbacks_t callbacks = {.on_open = unexpected_stream, .on_close = unexpected_stream, .on_data = unexpected_data};
        solaris_stream_t *stream = NULL;
        CHECK(solaris_outbound_open_stream(outbound, &target, &callbacks, test, &stream) == SOLARIS_ENOTSUP && stream == NULL);
        unsigned int opens = test->opens;
        solaris_datagram_callbacks_t udp_callbacks = {.on_open = unexpected_packet, .on_close = unexpected_packet, .on_packet = unexpected_payload};
        solaris_datagram_t *datagram = NULL;
        CHECK(solaris_outbound_open_datagram(outbound, SOLARIS_ADDRESS_IPV4, &udp_callbacks, test, &datagram) == SOLARIS_ENOTSUP && datagram == NULL);
        CHECK(test->opens == opens + uot);
        CHECK(solaris_module_retire(instance) == SOLARIS_OK);
        CHECK(solaris_module_retire(instance) == SOLARIS_OK);
    }
    solaris_test_event_signal(&test->ready);
}
static void plugin_tests(solaris_budget_t *budget)
{
    solaris_config_field_t fields[] = {
        {.name = "server", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"127.0.0.1", 9u}}},
        {.name = "port", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 443}},
        {.name = "cipher", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"2022-blake3-chacha20-poly1305", 29u}}},
        {.name = "password", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"SUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUk=", 44u}}},
        {.name = "plugin", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"fixture", 7u}}},
        {.name = "plugin-opts", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"opaque=value", 12u}}},
        {.name = "udp-over-tcp", .value = {.kind = SOLARIS_CONFIG_BOOL}}
    };
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {fields, 7u}};
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(budget, &registry, NULL) == SOLARIS_OK);
    plugin_case_t test = {0};
    for (unsigned int i = 0u; i < 2u; ++i) {
        fields[6].value.value.boolean = (int)i;
        CHECK(solaris_registry_compile(registry, "ss", &view, &test.configs[i], NULL) == SOLARIS_OK);
    }
    fields[4].value.value.string.length = 0u;
    solaris_module_config_t *invalid;
    CHECK(solaris_registry_compile(registry, "ss", &view, &invalid, NULL) == SOLARIS_EINVAL && invalid == NULL);
    solaris_registry_destroy(registry);
    solaris_engine_options_t options; solaris_engine_options_init(&options); options.io_workers = 1u;
    solaris_engine_t *engine; CHECK(solaris_engine_create(&options, NULL, &engine, NULL) == SOLARIS_OK);
    uint64_t operation; CHECK(solaris_engine_start(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    test.owner = solaris_runtime_executor(engine, 0u); CHECK(solaris_test_event_init(&test.ready, 0u) == 0);
    CHECK(solaris_executor_post(test.owner, plugin_worker, &test) == SOLARIS_OK); solaris_test_event_wait(&test.ready);
    CHECK(solaris_engine_stop(engine, &operation, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 5000u, NULL) == SOLARIS_OK);
    CHECK(test.creates == 3u && test.opens == 3u && test.retires == 2u && test.destroys == 2u && test.closes == 2u);
    CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK); solaris_test_event_destroy(&test.ready);
    for (unsigned int i = 0u; i < 2u; ++i) solaris_module_config_release(test.configs[i]);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    solaris_budget_t *budget; CHECK(solaris_budget_create(8u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    config_tests(budget);
    plugin_tests(budget);
    replay_test(budget);
    packet_tests(argv[1], budget);
    request_tests(argv[1], budget);
    solaris_ss_key_t invalid;
    CHECK(solaris_ss_key_parse(methods[3], "SUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUk=", &invalid) == SOLARIS_EINVAL);
    CHECK(solaris_ss_key_parse(methods[4], "SUlJSUlJSUlJSUlJSUlJSQ==", &invalid) == SOLARIS_EINVAL);
    CHECK(solaris_ss_key_parse(methods[3], "SUlJSUlJSUlJSUlJSUlJSQ=\n", &invalid) == SOLARIS_EINVAL);
    CHECK(solaris_ss_key_parse("rc4-md5", "password", &invalid) == SOLARIS_ENOTSUP);
    for (unsigned int method = 0u; method < 6u; ++method) for (unsigned int variant = 0u; variant < 10u; ++variant) {
        char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/stream-%u-%u.bin", argv[1], method, variant) > 0);
        FILE *file = fopen(path, "rb"); CHECK(file != NULL);
        uint8_t wire[66000]; size_t length = fread(wire, 1u, sizeof(wire), file); CHECK(length > 0u && feof(file)); fclose(file);
        solaris_ss_parameters_t parameters = {.source = {.random = fixed_random, .unix_seconds = fixed_time}};
        CHECK(solaris_ss_key_parse(methods[method], password(method), &parameters.key) == SOLARIS_OK);
        CHECK(solaris_address_parse("example.com", 443u, &parameters.destination) == SOLARIS_OK);
        CHECK(solaris_replay_create(budget, 32u, 0u, NULL, NULL, &parameters.replay) == SOLARIS_OK);
        void *codec; const solaris_stream_codec_ops_t *ops = &solaris_ss_stream_codec;
        CHECK(ops->create(&parameters, budget, &codec) == SOLARIS_OK);
        solaris_buffer_t *preface = NULL; CHECK(ops->start(codec, &preface) == SOLARIS_OK); solaris_buffer_release(preface);
        size_t received; solaris_status_t rc = parse(codec, wire, length, &received, variant == 9u);
        int success = variant == 0u || variant == 7u || variant == 8u || variant == 9u || (method < 3u && variant >= 3u && variant <= 5u);
        CHECK(success ? rc == SOLARIS_OK : rc != SOLARIS_OK);
        if (success) CHECK(received == (variant == 8u ? 0u : variant == 9u ? (method < 3u ? 16383u : 65535u) : 5u));
        else CHECK(received == 0u);
        ops->destroy(codec);
        if (method < 3u && variant == 0u) {
            parameters.source.context = &parameters;
            CHECK(ops->create(&parameters, budget, &codec) == SOLARIS_OK);
            CHECK(ops->start(codec, &preface) == SOLARIS_OK); solaris_buffer_release(preface);
            CHECK(parse(codec, wire, length, &received, 0) == SOLARIS_EACCESS && received == 0u); ops->destroy(codec);
        }
        parameters.source.random = failed_random;
        CHECK(ops->create(&parameters, budget, &codec) == SOLARIS_OK); preface = NULL;
        CHECK(ops->start(codec, &preface) == SOLARIS_EIO && preface == NULL); ops->destroy(codec);
        solaris_replay_release(parameters.replay); CHECK(solaris_budget_used(budget) == 0u);
    }
    solaris_budget_release(budget); puts("SS independent codec fixtures, replay race/retention/full, entropy failure passed"); return 0;
}
