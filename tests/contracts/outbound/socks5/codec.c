#include "support/runtime/files.h"
#include "adapters/outbound/socks5/codec.h"
#include "contracts/module/module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct environment { int fail; solaris_budget_t *budget; } environment_t;
static void *allocate(void *context, size_t size) { environment_t *env = context; if (env->fail) { env->fail = 0; return NULL; } return malloc(size); }
static size_t load(const char *directory, const char *name, uint8_t *out, size_t capacity)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/%s", directory, name) > 0);
    FILE *file = solaris_test_fopen(path, "rb"); CHECK(file != NULL); size_t n = fread(out, 1u, capacity, file); CHECK(feof(file)); fclose(file); return n;
}
static void output(environment_t *env, solaris_socks5_handshake_t *state, const char *directory, const char *name)
{
    uint8_t expected[1024]; size_t size = load(directory, name, expected, sizeof(expected)); solaris_buffer_t *wire = NULL;
    uint8_t stage = state->stage; env->fail = 1;
    CHECK(solaris_socks5_handshake_write(state, env->budget, &wire) == SOLARIS_ENOMEM && wire == NULL && state->stage == stage);
    CHECK(solaris_socks5_handshake_write(state, env->budget, &wire) == SOLARIS_OK);
    CHECK(solaris_buffer_length(wire) == size && memcmp(solaris_buffer_data(wire), expected, size) == 0);
    solaris_buffer_release(wire);
    CHECK(solaris_socks5_handshake_write(state, env->budget, &wire) == SOLARIS_EBUSY && wire == NULL);
}
static void read_reply(solaris_socks5_handshake_t *state, const uint8_t *data, size_t size)
{
    size_t used; uint8_t stage = state->stage;
    for (size_t n = 0u; n < size; ++n) CHECK(solaris_socks5_handshake_read(state, data, n, &used) == SOLARIS_EAGAIN && used == 0u && state->stage == stage);
    CHECK(solaris_socks5_handshake_read(state, data, size, &used) == SOLARIS_OK && used == size);
}
static void handshake_tests(environment_t *env, const char *directory)
{
    const char *hosts[] = {"1.2.3.4", "::1", "example.com", NULL}; char large[256]; memset(large, 'd', 255u); large[255] = '\0'; hosts[3] = large;
    solaris_socks5_credentials_t credentials = {0}; solaris_address_t target; uint8_t wire[1024]; char name[64];
    for (unsigned int auth = 0u; auth < 2u; ++auth) for (unsigned int address = 0u; address < 4u; ++address) {
        memset(&credentials, 0, sizeof(credentials));
        if (auth) { memcpy(credentials.username, "solaris", 7u); credentials.username_length = 7u; memcpy(credentials.password, "password", 8u); credentials.password_length = 8u; }
        CHECK(solaris_address_parse(hosts[address], 443u, &target) == SOLARIS_OK);
        solaris_socks5_handshake_t state; CHECK(solaris_socks5_handshake_init(&state, &credentials, 1u, &target) == SOLARIS_OK);
        output(env, &state, directory, auth ? "greeting-auth" : "greeting-none");
        uint8_t method[] = {5u, auth ? 2u : 0u}; read_reply(&state, method, sizeof(method));
        if (auth) { output(env, &state, directory, "auth"); const uint8_t ok[] = {1u,0u}; read_reply(&state, ok, sizeof(ok)); }
        CHECK(snprintf(name, sizeof(name), "connect-%u", address) > 0); output(env, &state, directory, name);
        CHECK(snprintf(name, sizeof(name), "reply-%u", address) > 0); size_t size = load(directory, name, wire, sizeof(wire));
        read_reply(&state, wire, size); CHECK(state.stage == SOLARIS_SOCKS5_READY && state.bound.port == 1080u);
        target.port = 1080u; CHECK(solaris_address_equal(&state.bound, &target)); solaris_socks5_clear(&state, sizeof(state));
    }
    memset(&credentials, 0, sizeof(credentials));
    CHECK(solaris_address_parse("0.0.0.0", 0u, &target) == SOLARIS_OK);
    solaris_socks5_handshake_t state; CHECK(solaris_socks5_handshake_init(&state, &credentials, 3u, &target) == SOLARIS_OK);
    output(env, &state, directory, "greeting-none"); const uint8_t method[] = {5u,0u}; read_reply(&state, method, 2u);
    output(env, &state, directory, "associate"); size_t size = load(directory, "reply-zero", wire, sizeof(wire)), used;
    CHECK(solaris_socks5_handshake_read(&state, wire, size, &used) == SOLARIS_EIO && used == 0u);
    state.command = 1u; read_reply(&state, wire, size); CHECK(state.bound.port == 0u);
    memset(credentials.username, 'a', 255u); memset(credentials.password, 'b', 255u); credentials.username_length = credentials.password_length = 255u;
    target.port = 443u; CHECK(solaris_socks5_handshake_init(&state, &credentials, 1u, &target) == SOLARIS_OK);
    output(env, &state, directory, "greeting-auth"); const uint8_t auth[] = {5u,2u}; read_reply(&state, auth, 2u); output(env, &state, directory, "auth-max");
    const uint8_t bad_auth[] = {1u,1u}; CHECK(solaris_socks5_handshake_read(&state, bad_auth, 2u, &used) == SOLARIS_EACCESS);
    state.stage = SOLARIS_SOCKS5_METHOD;
    CHECK(solaris_socks5_handshake_read(&state, method, 2u, &used) == SOLARIS_EACCESS); /* no authentication downgrade */
    for (unsigned int reply = 1u; reply <= 9u; ++reply) {
        state.stage = SOLARIS_SOCKS5_REPLY; uint8_t bytes[] = {5u, (uint8_t)reply, 0u};
        solaris_status_t expected = reply == 2u ? SOLARIS_EACCESS : reply == 6u ? SOLARIS_ETIMEDOUT : reply == 7u || reply == 8u ? SOLARIS_ENOTSUP : SOLARIS_EIO;
        CHECK(solaris_socks5_handshake_read(&state, bytes, sizeof(bytes), &used) == expected && used == 0u);
    }
    const uint8_t invalid[][4] = {{4u,0u,0u,1u},{5u,0u,1u,1u},{5u,0u,0u,255u}};
    for (size_t i = 0u; i < 3u; ++i) CHECK(solaris_socks5_handshake_read(&state, invalid[i], 4u, &used) == SOLARIS_EIO);
    CHECK(solaris_socks5_handshake_init(&state, &credentials, 2u, &target) == SOLARIS_EINVAL);
}
static void packets(environment_t *env, const char *directory)
{
    uint8_t wire[66000], changed[66000]; char name[64];
    for (unsigned int i = 0u; i < 4u; ++i) {
        CHECK(snprintf(name, sizeof(name), "packet-%u", i) > 0); size_t size = load(directory, name, wire, sizeof(wire));
        solaris_address_t source; solaris_buffer_t *plain = NULL, *encoded = NULL;
        env->fail = 1; CHECK(solaris_socks5_packet_decode(env->budget, wire, size, &source, &plain) == SOLARIS_ENOMEM && plain == NULL);
        CHECK(solaris_socks5_packet_decode(env->budget, wire, size, &source, &plain) == SOLARIS_OK);
        size_t length = solaris_buffer_length(plain); CHECK(length == (i == 1u ? 0u : i == 3u ? 65000u : 5u));
        CHECK(source.port == 443u);
        solaris_slice_t slice = {plain, 0u, length}; env->fail = 1;
        CHECK(solaris_socks5_packet_encode(env->budget, &source, &slice, &encoded) == SOLARIS_ENOMEM && encoded == NULL);
        CHECK(solaris_socks5_packet_encode(env->budget, &source, &slice, &encoded) == SOLARIS_OK && solaris_buffer_length(encoded) == size);
        CHECK(memcmp(solaris_buffer_data(encoded), wire, size) == 0); solaris_buffer_release(encoded); solaris_buffer_release(plain);
        for (unsigned int bad = 0u; bad < 3u; ++bad) {
            memcpy(changed, wire, size); changed[bad] = 1u;
            CHECK(solaris_socks5_packet_decode(env->budget, changed, size, &source, &plain) != SOLARIS_OK && plain == NULL);
        }
        for (size_t n = 0u; n < (i == 3u ? 262u : i == 1u ? 22u : i == 2u ? 18u : 10u); ++n)
            CHECK(solaris_socks5_packet_decode(env->budget, wire, n, &source, &plain) != SOLARIS_OK && plain == NULL);
    }
    solaris_buffer_t *plain, *out = NULL; CHECK(solaris_buffer_allocate(env->budget, 65001u, &plain) == SOLARIS_OK);
    CHECK(solaris_buffer_set_length(plain, 65001u) == SOLARIS_OK); solaris_slice_t slice = {plain, 0u, 65001u};
    solaris_address_t target; CHECK(solaris_address_parse("127.0.0.1", 53u, &target) == SOLARIS_OK);
    CHECK(solaris_socks5_packet_encode(env->budget, &target, &slice, &out) == SOLARIS_EMSGSIZE && out == NULL); solaris_buffer_release(plain);
}
static solaris_config_field_t string(const char *name, const char *value)
{ solaris_config_field_t f = {.name = name, .value = {.kind = SOLARIS_CONFIG_STRING}}; f.value.value.string.data = value; f.value.value.string.length = strlen(value); return f; }
static void configurations(environment_t *env)
{
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(env->budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[] = {string("server", "localhost"), {.name = "port", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 1080}}, string("username", "solaris"), string("password", "password")};
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {.fields = fields, .count = 4u}};
    solaris_module_config_t *config;
    CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_OK); solaris_module_config_release(config);
    view.value.map.count = 3u; CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_EINVAL && config == NULL);
    view.value.map.count = 2u; CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_OK); solaris_module_config_release(config);
    view.value.map.count = 1u; CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_EINVAL && config == NULL);
    view.value.map.count = 4u; fields[2].name = "tls";
    CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_EINVAL && config == NULL);
    char long_user[257]; memset(long_user, 'a', 256u); long_user[256] = '\0'; fields[2] = string("username", long_user);
    CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_EINVAL && config == NULL);
    long_user[255] = '\0'; fields[2] = string("username", long_user);
    CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_OK); solaris_module_config_release(config);
    fields[2] = string("username", ""); CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_EINVAL && config == NULL);
    fields[2] = string("username", "solaris"); env->fail = 1;
    CHECK(solaris_registry_compile(registry, "socks5", &view, &config, NULL) == SOLARIS_ENOMEM && config == NULL);
    solaris_registry_destroy(registry);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2); environment_t env = {0}; solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = &env; services.allocate = allocate;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &services, &env.budget) == SOLARIS_OK);
    handshake_tests(&env, argv[1]); packets(&env, argv[1]); configurations(&env);
    CHECK(solaris_budget_used(env.budget) == 0u); solaris_budget_release(env.budget);
    puts("SOCKS5 codec: method/auth/commands, bounds, zero BND port, fragments, empty/max UDP and configuration failures passed"); return 0;
}
