#include "adapters/outbound/vless/vision/codec.h"
#include "adapters/outbound/vless/datagram.h"
#include "codec/address/vmess.h"
#include "contracts/module/module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static const solaris_stream_codec_ops_t *ops = &solaris_vless_vision_codec;
typedef struct environment { int fail; solaris_budget_t *budget; } environment_t;
static void *allocate(void *context, size_t size)
{ environment_t *env = context; if (env->fail) { env->fail = 0; return NULL; } return malloc(size); }
static solaris_status_t random_bytes(void *context, uint8_t *out, size_t size)
{ (void)context; memset(out, 0x42, size); return SOLARIS_OK; }
static size_t load(const char *root, const char *name, uint8_t *out, size_t capacity)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/%s", root, name) > 0);
    FILE *file = fopen(path, "rb"); CHECK(file != NULL); size_t size = fread(out, 1u, capacity, file); CHECK(feof(file)); fclose(file); return size;
}
static void save(const char *root, const char *name, const solaris_buffer_t *buffer)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/%s", root, name) > 0);
    FILE *file = fopen(path, "wb"); CHECK(file != NULL);
    CHECK(fwrite(solaris_buffer_data(buffer), 1u, solaris_buffer_length(buffer), file) == solaris_buffer_length(buffer)); CHECK(fclose(file) == 0);
}
static void *create(environment_t *env, const char *root)
{
    solaris_vless_vision_parameters_t parameters = {.request = {.command = 1u, .vision = 1u}, .crypto = {.random = random_bytes}};
    for (unsigned int i = 0u; i < 16u; ++i) parameters.request.uuid[i] = (uint8_t)i;
    CHECK(solaris_address_parse("127.0.0.1", 443u, &parameters.request.destination) == SOLARIS_OK);
    void *state; CHECK(ops->create(&parameters, env->budget, &state) == SOLARIS_OK);
    solaris_buffer_t *preface;
    env->fail = 1; CHECK(ops->start(state, &preface) == SOLARIS_ENOMEM && preface == NULL);
    CHECK(ops->start(state, &preface) == SOLARIS_OK); save(root, "start.bin", preface); solaris_buffer_release(preface); return state;
}
static solaris_status_t parse(environment_t *env, void *state, const uint8_t *wire, size_t size,
    const uint8_t *expected, size_t expected_size, int allocation_failure)
{
    size_t begin = 0u, end = 0u, received = 0u; int failed = 0;
    while (begin < size) {
        if (end < size) { size_t step = size - end; if (step > 113u) step = 113u; end += step; }
        size_t consumed; solaris_buffer_t *out = NULL;
        if (allocation_failure && !failed && begin >= 2u) env->fail = 1;
        solaris_status_t rc = ops->decode(state, wire + begin, end - begin, &consumed, &out);
        if (rc == SOLARIS_ENOMEM) { CHECK(consumed == 0u && out == NULL); failed = 1; continue; }
        if (rc == SOLARIS_EAGAIN) {
            CHECK(consumed == 0u && out == NULL); if (end == size) return SOLARIS_EIO; continue;
        }
        if (rc != SOLARIS_OK) { CHECK(out == NULL); env->fail = 0; return rc; }
        CHECK(consumed != 0u && consumed <= end - begin); begin += consumed;
        if (out != NULL) {
            size_t count = solaris_buffer_length(out); CHECK(count <= expected_size - received);
            CHECK(memcmp(solaris_buffer_data(out), expected + received, count) == 0); received += count; solaris_buffer_release(out);
        }
    }
    CHECK(received == expected_size);
    if (allocation_failure) CHECK(failed);
    return ops->finish(state);
}
static solaris_buffer_t *encode(environment_t *env, void *state, const uint8_t *input, size_t size)
{
    solaris_buffer_t *plain, *out = NULL; CHECK(solaris_buffer_copy(env->budget, input, size, &plain) == SOLARIS_OK);
    solaris_slice_t slice = {plain, 0u, size}; env->fail = 1;
    CHECK(ops->encode(state, &slice, &out) == SOLARIS_ENOMEM && out == NULL);
    CHECK(ops->encode(state, &slice, &out) == SOLARIS_OK); solaris_buffer_release(plain); return out;
}
static void exchanges(environment_t *env, const char *root)
{
    uint8_t application[512], client[512];
    size_t app_size = load(root, "application.bin", application, sizeof(application));
    size_t client_size = load(root, "client-hello.bin", client, sizeof(client));
    for (int index = 0; index < 10; ++index) {
        void *state = create(env, root);
        /* Split the outbound TLS header as well as the later application body. */
        solaris_buffer_t *encoded = encode(env, state, client, 2u); solaris_buffer_release(encoded);
        encoded = encode(env, state, client + 2u, client_size - 2u); solaris_buffer_release(encoded);
        CHECK(ops->carrier_raw->requested(state) == 0u);
        char name[64]; uint8_t response[140000], expected[140000];
        CHECK(snprintf(name, sizeof(name), "response-%d.bin", index) > 0); size_t size = load(root, name, response, sizeof(response));
        CHECK(snprintf(name, sizeof(name), "hello-%d.bin", index) > 0); size_t n = load(root, name, expected, sizeof(expected));
        CHECK(parse(env, state, response, size, expected, n, 1) == SOLARIS_OK && ops->carrier_raw->requested(state) == 0u);
        encoded = encode(env, state, application, 13u); CHECK(ops->carrier_raw->requested(state) == 0u);
        CHECK(snprintf(name, sizeof(name), "first-%d.bin", index) > 0); save(root, name, encoded); solaris_buffer_release(encoded);
        encoded = encode(env, state, application + 13u, app_size - 13u);
        CHECK(snprintf(name, sizeof(name), "second-%d.bin", index) > 0); save(root, name, encoded); solaris_buffer_release(encoded);
        CHECK(ops->carrier_raw->requested(state) == (index < 3 ? SOLARIS_STREAM_RAW_WRITE : 0u));
        ops->carrier_raw->applied(state, SOLARIS_STREAM_RAW_WRITE);
        encoded = encode(env, state, application, app_size);
        CHECK(solaris_buffer_length(encoded) == app_size && memcmp(solaris_buffer_data(encoded), application, app_size) == 0);
        solaris_buffer_release(encoded);
        CHECK(snprintf(name, sizeof(name), "tail-%d.bin", index) > 0); size = load(root, name, response, sizeof(response));
        memcpy(expected, application, app_size); memcpy(expected + app_size, application, app_size);
        CHECK(parse(env, state, response, size, expected, 2u * app_size, 1) == SOLARIS_OK);
        CHECK(ops->carrier_raw->requested(state) == (index < 3 ? SOLARIS_STREAM_RAW_READ : 0u));
        ops->carrier_raw->applied(state, SOLARIS_STREAM_RAW_READ); CHECK(ops->carrier_raw->requested(state) == 0u);
        ops->destroy(state);
    }
}
static void invalid(environment_t *env, const char *root)
{
    const char *files[] = {"bad-command.bin", "bad-uuid.bin", "bad-early-direct.bin"};
    uint8_t wire[140000], expected[65535];
    for (size_t i = 0u; i < 3u; ++i) {
        void *state = create(env, root); size_t size = load(root, files[i], wire, sizeof(wire));
        CHECK(parse(env, state, wire, size, NULL, 0u, 0) == (i == 1u ? SOLARIS_EACCESS : SOLARIS_EIO));
        CHECK(ops->carrier_raw->requested(state) == 0u); ops->destroy(state);
    }
    size_t size = load(root, "maximum.bin", wire, sizeof(wire));
    for (size_t i = 0u; i < sizeof(expected); ++i) expected[i] = (uint8_t)(i * 19u);
    void *state = create(env, root); CHECK(parse(env, state, wire, size, expected, sizeof(expected), 1) == SOLARIS_OK); ops->destroy(state);
    const size_t cuts[] = {1u, 2u + 15u, 2u + 20u, 2u + 21u, 65535u, 131090u};
    for (size_t i = 0u; i < sizeof(cuts) / sizeof(cuts[0]); ++i) {
        state = create(env, root); CHECK(parse(env, state, wire, cuts[i], NULL, 0u, 0) == SOLARIS_EIO);
        ops->destroy(state);
    }
}
static void udp443(environment_t *env)
{
    solaris_buffer_t *plain; CHECK(solaris_buffer_copy(env->budget, "packet", 6u, &plain) == SOLARIS_OK);
    solaris_slice_t slice = {plain, 0u, 6u}; solaris_address_t address; CHECK(solaris_address_parse("127.0.0.1", 443u, &address) == SOLARIS_OK);
    for (int deny = 0; deny < 2; ++deny) {
        void *state; CHECK(solaris_vless_xudp_codec.create(&deny, env->budget, &state) == SOLARIS_OK);
        solaris_buffer_t *out = NULL;
        if (deny) CHECK(solaris_vless_xudp_codec.encode(state, &address, &slice, &out) == SOLARIS_EACCESS && out == NULL);
        address.port = deny ? 53u : 443u;
        CHECK(solaris_vless_xudp_codec.encode(state, &address, &slice, &out) == SOLARIS_OK);
        CHECK(solaris_buffer_data(out)[4] == 1u); /* refused first packet did not commit New */
        solaris_address_t parsed; size_t used;
        CHECK(solaris_vmess_address_read(solaris_buffer_data(out) + 7u, solaris_buffer_length(out) - 7u, &parsed, &used) == SOLARIS_OK);
        CHECK(parsed.port == address.port); solaris_buffer_release(out); address.port = 443u;
        solaris_vless_xudp_codec.destroy(state);
    }
    solaris_buffer_release(plain);
}
static solaris_config_field_t field(const char *name, const char *value)
{ solaris_config_field_t f = {.name = name, .value = {.kind = SOLARIS_CONFIG_STRING}}; f.value.value.string.data = value; f.value.value.string.length = strlen(value); return f; }
static void configurations(environment_t *env, const char *root)
{
    char encryption[256]; size_t size = load(root, "encryption.txt", (uint8_t *)encryption, sizeof(encryption) - 1u); encryption[size] = '\0';
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(env->budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[] = {field("server", "127.0.0.1"), {.name = "port", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 1234}},
        field("uuid", "00010203-0405-0607-0809-0a0b0c0d0e0f"), field("flow", "xtls-rprx-vision"), field("encryption", "none")};
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {.fields = fields, .count = 5u}};
    solaris_module_config_t *config = NULL;
    CHECK(solaris_registry_compile(registry, "vless", &view, &config, NULL) != SOLARIS_OK && config == NULL);
    fields[4] = field("encryption", encryption);
    CHECK(solaris_registry_compile(registry, "vless", &view, &config, NULL) == SOLARIS_OK); solaris_module_config_release(config);
    fields[3] = field("flow", "xtls-rprx-vision-udp443");
    CHECK(solaris_registry_compile(registry, "vless", &view, &config, NULL) == SOLARIS_OK); solaris_module_config_release(config);
    fields[3] = field("flow", "xtls-rprx-unknown"); config = NULL;
    CHECK(solaris_registry_compile(registry, "vless", &view, &config, NULL) != SOLARIS_OK && config == NULL);
    fields[3] = field("flow", ""); fields[4] = field("encryption", "none");
    CHECK(solaris_registry_compile(registry, "vless", &view, &config, NULL) == SOLARIS_OK); solaris_module_config_release(config);
    fields[3].name = "unknown-flow";
    CHECK(solaris_registry_compile(registry, "vless", &view, &config, NULL) != SOLARIS_OK && config == NULL);
    view.value.map.count = 2u;
    CHECK(solaris_registry_compile(registry, "vless", &view, &config, NULL) != SOLARIS_OK && config == NULL);
    solaris_registry_destroy(registry);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2); environment_t env = {0}; solaris_runtime_services_t services;
    solaris_runtime_services_init(&services); services.context = &env; services.allocate = allocate;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &services, &env.budget) == SOLARIS_OK);
    exchanges(&env, argv[1]); invalid(&env, argv[1]); udp443(&env); configurations(&env, argv[1]);
    CHECK(solaris_budget_used(env.budget) == 0u); solaris_budget_release(env.budget);
    puts("Vision codec: TLS classification, framing, raw boundaries, allocation and UDP/443 policy passed"); return 0;
}
