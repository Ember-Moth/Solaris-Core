#include "support/runtime/files.h"
#include "adapters/outbound/anytls/internal.h"
#include "contracts/module/module.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
extern const solaris_outbound_module_t solaris_anytls_module;
typedef struct allocator { int fail; } allocator_t;
static void *allocate(void *context, size_t size) { allocator_t *a = context; if (a->fail) { a->fail = 0; return NULL; } return malloc(size); }
static void diagnostic(void *context, const char *component, solaris_status_t status, const uint8_t *message, size_t length)
{
    CHECK(strcmp(component, "anytls") == 0 && status == SOLARIS_EACCESS && length == 8u && memcmp(message, "rejected", 8u) == 0);
    (*(unsigned int *)context)++;
}
static solaris_status_t random_bytes(void *context, uint8_t *out, size_t size) { (void)context; memset(out, 17, size); return SOLARIS_OK; }
static size_t load(const char *root, const char *name, uint8_t *out, size_t capacity)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/%s", root, name) > 0);
    FILE *f = solaris_test_fopen(path, "rb"); CHECK(f != NULL); size_t size = fread(out, 1u, capacity, f); CHECK(feof(f)); fclose(f); return size;
}
static void check_batch(const solaris_session_batch_t *batch, const uint8_t *expected, size_t size)
{
    uint8_t *wire = malloc(2u*1024u*1024u); CHECK(wire != NULL); size_t n = 0u;
    for (size_t i = 0u; i < batch->count; ++i) {
        size_t count = solaris_buffer_length(batch->buffers[i]); CHECK(n + count <= 2u*1024u*1024u);
        memcpy(wire + n, solaris_buffer_data(batch->buffers[i]), count); n += count;
    }
    CHECK(n >= size && memcmp(wire, expected, size) == 0);
    for (size_t i = size; i < n;) {
        CHECK(n - i >= 7u && wire[i] == 0u && wire[i+1] == 0u && wire[i+2] == 0u && wire[i+3] == 0u && wire[i+4] == 0u);
        size_t count = (size_t)wire[i+5] << 8 | wire[i+6]; CHECK(count <= n - i - 7u);
        for (size_t j = 0u; j < count; ++j) CHECK(wire[i+7u+j] == 0u);
        i += 7u + count;
    }
    free(wire);
}
static void clear_event(solaris_session_event_t *event)
{ solaris_buffer_release(event->data); solaris_session_batch_clear(&event->reply); memset(event, 0, sizeof(*event)); }
static void policy_tests(void)
{
    const char *bad[] = {"", "stop=-1", "stop=4294967296", "stop=1\nstop=2", "stop=1\n0=c", "stop=1\n0=1-1,2-2", "stop=1\n1=0-2",
        "stop=1\n1=1-65536", "stop=1\n4294967296=1-1", "stop=2\n1=1-1\n1=2-2", "stop=1\n1=1-1,", "stop=1\n1=x", "stop=1\n1=1-1\0hidden"};
    solaris_anytls_policy_t p;
    for (size_t i = 0u; i < sizeof(bad)/sizeof(bad[0])-1u; ++i) CHECK(solaris_anytls_policy_parse((const uint8_t *)bad[i], strlen(bad[i]), &p) == SOLARIS_EINVAL);
    CHECK(solaris_anytls_policy_parse((const uint8_t *)bad[sizeof(bad)/sizeof(bad[0])-1u], 22u, &p) == SOLARIS_EINVAL);
    const char *good = "stop=2\n0=30-20\n1=50-50,c,20-20\n";
    CHECK(solaris_anytls_policy_parse((const uint8_t *)good, strlen(good), &p) == SOLARIS_OK && p.rows[0][0].low == 20u && p.rows[0][0].high == 30u);
    good = "stop=4294967295\n4000000000=17-17\n0=30-30";
    CHECK(solaris_anytls_policy_parse((const uint8_t *)good, strlen(good), &p) == SOLARIS_OK && p.stop == UINT32_MAX && p.packets[1] == 4000000000u);
}
static void config_tests(solaris_budget_t *budget)
{
    solaris_config_field_t fields[] = {
        {.name = "password", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"secret", 6u}}},
        {.name = "server", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"localhost", 9u}}},
        {.name = "port", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 443}},
        {.name = "session-limit", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 2}},
        {.name = "idle-session-check-interval-ms", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 20}},
        {.name = "min-idle-session", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 2}}
    };
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {fields, sizeof(fields)/sizeof(fields[0])}};
    solaris_error_t error; void *compiled;
    for (size_t i = 0u; i < 3u; ++i) {
        fields[4].value.value.integer = i == 1u ? 0 : 20;
        fields[5].value.value.integer = i == 2u ? 3 : 2;
        compiled = NULL;
        CHECK(solaris_anytls_module.compile(&view, budget, &compiled, &error) == SOLARIS_EINVAL);
        /* Valid idle settings reach the independently required TLS check. */
        const char *expected = i == 0u ? "tls at " : i == 1u ? "idle-session-check-interval-ms at " : "min-idle-session at ";
        CHECK(strncmp(error.message, expected, strlen(expected)) == 0);
        solaris_anytls_module.free_config(compiled);
    }
}
static void negotiation_tests(const char *root, solaris_anytls_parameters_t *parameters, solaris_budget_t *budget)
{
    const solaris_session_codec_t *codec = &solaris_anytls_session_codec;
    const char *settings[] = {"v1-settings", "future-settings", "duplicate-version", "missing-version", "overflow-version", "invalid-utf8", "malformed-setting", "bad-version"};
    solaris_address_t target; CHECK(solaris_address_parse("1.2.3.4", 443u, &target) == SOLARIS_OK);
    for (size_t i = 0u; i < sizeof(settings)/sizeof(settings[0]); ++i) {
        void *state; CHECK(codec->create(parameters, budget, &state) == SOLARIS_OK);
        solaris_session_batch_t batch = {0}; int ack;
        CHECK(codec->open(state, 1u, &target, &ack, &batch) == SOLARIS_OK && !ack); solaris_session_batch_clear(&batch);
        uint8_t fixture[256]; size_t size = load(root, "reply", fixture, sizeof(fixture)), used;
        solaris_session_event_t event = {0};
        /* No settings is a valid v1 peer, including a server-first protocol. */
        CHECK(codec->decode(state, fixture, size, &used, &event) == SOLARIS_OK && event.kind == SOLARIS_SESSION_DATA); clear_event(&event);
        size = load(root, "heart", fixture, sizeof(fixture));
        CHECK(codec->decode(state, fixture, size, &used, &event) == SOLARIS_EIO && used == 0u); clear_event(&event);
        size = load(root, settings[i], fixture, sizeof(fixture));
        CHECK(codec->decode(state, fixture, size, &used, &event) == (i < 2u ? SOLARIS_OK : SOLARIS_EIO)); clear_event(&event);
        CHECK(codec->open(state, 2u, &target, &ack, &batch) == SOLARIS_OK && ack == (i == 1u)); solaris_session_batch_clear(&batch);
        codec->destroy(state);
    }
    /* Sparse packet IDs retain padding semantics without allocating by stop. */
    solaris_anytls_policy_t policy;
    const char *text = "stop=4294967295\n4000000000=17-17\n0=30-30";
    CHECK(solaris_anytls_policy_parse((const uint8_t *)text, strlen(text), &policy) == SOLARIS_OK);
    solaris_session_batch_t batch = {0}; uint8_t data[3] = {2, 3, 4};
    CHECK(solaris_anytls_pad(parameters, &policy, 4000000000u, budget, data, sizeof(data), &batch) == SOLARIS_OK);
    CHECK(batch.count == 1u && solaris_buffer_length(batch.buffers[0]) == 17u); solaris_session_batch_clear(&batch);
}
int main(int argc, char **argv)
{
    CHECK(argc == 2); policy_tests(); allocator_t allocator = {0}; solaris_runtime_services_t services;
    solaris_runtime_services_init(&services); services.context = &allocator; services.allocate = allocate;
    solaris_budget_t *budget; CHECK(solaris_budget_create(8u*1024u*1024u, &services, &budget) == SOLARIS_OK);
    config_tests(budget);
    uint8_t *fixture = malloc(128u*1024u); CHECK(fixture != NULL);
    size_t size = load(argv[1], "auth", fixture, 128u*1024u);
    unsigned int alerts = 0u;
    solaris_anytls_parameters_t parameters = {.crypto = {.random = random_bytes}, .diagnostic = {.context = &alerts, .report = diagnostic}};
    memcpy(parameters.password_hash, fixture, 32u); CHECK(solaris_anytls_policy_default(&parameters.policy) == SOLARIS_OK);
    negotiation_tests(argv[1], &parameters, budget);
    const solaris_session_codec_t *codec = &solaris_anytls_session_codec; void *state;
    CHECK(codec->create(&parameters, budget, &state) == SOLARIS_OK);
    solaris_session_batch_t batch = {0}; CHECK(codec->start(state, &batch) == SOLARIS_OK); check_batch(&batch, fixture, size); solaris_session_batch_clear(&batch);
    solaris_address_t target; CHECK(solaris_address_parse("1.2.3.4", 443u, &target) == SOLARIS_OK); int ack;
    allocator.fail = 1; CHECK(codec->open(state, 1u, &target, &ack, &batch) == SOLARIS_ENOMEM); solaris_session_batch_clear(&batch);
    CHECK(codec->open(state, 1u, &target, &ack, &batch) == SOLARIS_OK && !ack);
    size = load(argv[1], "first", fixture, 128u*1024u); check_batch(&batch, fixture, size); solaris_session_batch_clear(&batch);
    solaris_buffer_t *plain; CHECK(solaris_buffer_allocate(budget, 65541u, &plain) == SOLARIS_OK);
    for (size_t i = 0u; i < 65541u; ++i) solaris_buffer_mutable_data(plain)[i] = (uint8_t)(i*13u+7u);
    CHECK(solaris_buffer_set_length(plain, 65541u) == SOLARIS_OK); solaris_slice_t slice = {plain, 0u, 65541u};
    allocator.fail = 1; CHECK(codec->write(state, 1u, &slice, &batch) == SOLARIS_ENOMEM); solaris_session_batch_clear(&batch);
    CHECK(codec->write(state, 1u, &slice, &batch) == SOLARIS_OK);
    size = load(argv[1], "data", fixture, 128u*1024u); check_batch(&batch, fixture, size); solaris_session_batch_clear(&batch); solaris_buffer_release(plain);
    const char *names[] = {"settings", "ack", "reply", "fin", "error", "heart", "update"};
    for (size_t i = 0u; i < sizeof(names)/sizeof(names[0]); ++i) {
        size = load(argv[1], names[i], fixture, 128u*1024u); solaris_session_event_t event = {0}; size_t used;
        for (size_t n = 0u; n < size; ++n) {
            CHECK(codec->decode(state, fixture, n, &used, &event) == SOLARIS_EAGAIN && used == 0u && event.data == NULL && event.reply.count == 0u);
        }
        CHECK(codec->decode(state, fixture, size, &used, &event) == SOLARIS_OK && used == size);
        if (i == 1u) CHECK(event.kind == SOLARIS_SESSION_READY && event.id == 1u && event.status == SOLARIS_OK);
        if (i == 2u) CHECK(event.kind == SOLARIS_SESSION_DATA && solaris_buffer_length(event.data) == 5u && memcmp(solaris_buffer_data(event.data), "hello", 5u) == 0);
        if (i == 3u) CHECK(event.kind == SOLARIS_SESSION_END && event.id == 1u);
        if (i == 4u) CHECK(event.kind == SOLARIS_SESSION_READY && event.status == SOLARIS_EACCESS);
        if (i == 5u) { size_t expected = load(argv[1], "heart-response", fixture, 128u*1024u); check_batch(&event.reply, fixture, expected); }
        clear_event(&event);
    }
    /* An update affects future sessions only; the active session keeps its
     * snapshot. Failed update parsing cannot mutate the client's policy. */
    CHECK(parameters.policy.rows[0][0].low == 41u);
    CHECK(codec->start(state, &batch) == SOLARIS_OK && solaris_buffer_length(batch.buffers[0]) == 64u); solaris_session_batch_clear(&batch);
    void *new_state; CHECK(codec->create(&parameters, budget, &new_state) == SOLARIS_OK);
    CHECK(codec->start(new_state, &batch) == SOLARIS_OK && solaris_buffer_length(batch.buffers[0]) == 75u); solaris_session_batch_clear(&batch); codec->destroy(new_state);
    const char *bad[] = {"bad-update", "bad-fin", "bad-version", "bad-command", "alert", "bad-heart", "bad-heart-response", "bad-settings-id", "bad-psh", "bad-synack-id", "server-syn"};
    for (size_t i = 0u; i < sizeof(bad)/sizeof(bad[0]); ++i) {
        size = load(argv[1], bad[i], fixture, 128u*1024u); solaris_session_event_t event = {0}; size_t used;
        CHECK(codec->decode(state, fixture, size, &used, &event) != SOLARIS_OK && used == 0u); clear_event(&event);
    }
    CHECK(parameters.policy.rows[0][0].low == 41u);
    CHECK(alerts == 1u);
    codec->destroy(state); free(fixture); CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget);
    puts("AnyTLS codec: independent wire fixtures, framing, padding updates and allocation rollback passed"); return 0;
}
