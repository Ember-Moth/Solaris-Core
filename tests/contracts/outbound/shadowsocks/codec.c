#include "adapters/outbound/shadowsocks/internal.h"
#include "adapters/outbound/shadowsocks/packet.h"
#include "codec/address/socks.h"
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
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"};
static const char *password(unsigned int method)
{ return method == 3u ? "SUlJSUlJSUlJSUlJSUlJSQ==" : method == 4u ? "SUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUk=" : "solaris-independent-peer"; }
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
    for (unsigned int method = 0u; method < 5u; ++method) {
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
int main(int argc, char **argv)
{
    CHECK(argc == 2);
    solaris_budget_t *budget; CHECK(solaris_budget_create(8u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    config_tests(budget);
    replay_test(budget);
    packet_tests(argv[1], budget);
    solaris_ss_key_t invalid;
    CHECK(solaris_ss_key_parse(methods[3], "SUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUk=", &invalid) == SOLARIS_EINVAL);
    CHECK(solaris_ss_key_parse(methods[4], "SUlJSUlJSUlJSUlJSUlJSQ==", &invalid) == SOLARIS_EINVAL);
    CHECK(solaris_ss_key_parse(methods[3], "SUlJSUlJSUlJSUlJSUlJSQ=\n", &invalid) == SOLARIS_EINVAL);
    CHECK(solaris_ss_key_parse("rc4-md5", "password", &invalid) == SOLARIS_ENOTSUP);
    for (unsigned int method = 0u; method < 5u; ++method) for (unsigned int variant = 0u; variant < 10u; ++variant) {
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
