#include "adapters/outbound/vless/encryption/client.h"
#include "adapters/outbound/vless/encryption/crypto.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
static const solaris_stream_codec_ops_t *ops = &solaris_vless_encryption_codec;
typedef struct environment { uint32_t random; uint64_t clock; int allocations, fail_at, fail_next; } environment_t;
typedef struct fixture { environment_t env; solaris_budget_t *budget; solaris_vless_encryption_client_t *client; void *stream; } fixture_t;
static uint8_t pattern(size_t i) { return (uint8_t)(i * 17u + 29u); }
static void *allocate(void *context, size_t size)
{
    environment_t *env = context; env->allocations++;
    if (env->fail_next || env->allocations == env->fail_at) { env->fail_next = 0; return NULL; }
    return malloc(size);
}
static uint64_t now_ns(void *context) { return ((environment_t *)context)->clock; }
static solaris_status_t random_bytes(void *context, uint8_t *out, size_t size)
{ environment_t *env = context; for (size_t i = 0u; i < size; ++i) out[i] = (uint8_t)env->random++; return SOLARIS_OK; }
static size_t load(const char *root, const char *name, int id, uint8_t *out, size_t capacity)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/%s-%d.bin", root, name, id) > 0);
    FILE *file = fopen(path, "rb"); CHECK(file != NULL);
    size_t n = fread(out, 1u, capacity, file); CHECK(feof(file)); fclose(file); return n;
}
static void save(const char *root, const char *name, int id, const uint8_t *data, size_t size)
{
    char path[1024]; CHECK(snprintf(path, sizeof(path), "%s/%s-%d.bin", root, name, id) > 0);
    FILE *file = fopen(path, "wb"); CHECK(file != NULL); CHECK(fwrite(data, 1u, size, file) == size); CHECK(fclose(file) == 0);
}
static void init(fixture_t *f, const char *root, int id)
{
    memset(f, 0, sizeof(*f)); f->env.random = 1u;
    solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = &f->env; services.allocate = allocate;
    CHECK(solaris_budget_create(4u * 1024u * 1024u, &services, &f->budget) == SOLARIS_OK);
    char text[SOLARIS_VLESS_ENCRYPTION_TEXT]; size_t n = load(root, "config", id, (uint8_t *)text, sizeof(text) - 1u); text[n] = '\0';
    solaris_vless_encryption_config_t config; CHECK(solaris_vless_encryption_config_parse(text, &config) == SOLARIS_OK); config.chacha = id >= 3;
    solaris_crypto_source_t crypto = {.context = &f->env, .random = random_bytes};
    CHECK(solaris_vless_encryption_client_create(&config, f->budget, &crypto, &f->env, now_ns, &f->client) == SOLARIS_OK);
    CHECK(ops->create(f->client, f->budget, &f->stream) == SOLARIS_OK);
}
static void clear(fixture_t *f)
{
    if (f->stream != NULL) ops->destroy(f->stream);
    solaris_vless_encryption_client_release(f->client);
    CHECK(solaris_budget_used(f->budget) == 0u); solaris_budget_release(f->budget);
}
static solaris_status_t hello(void *stream, uint8_t *wire, size_t *size)
{
    *size = 0u; solaris_buffer_t *buffer = NULL;
    solaris_status_t rc = ops->start(stream, &buffer);
    if (rc != SOLARIS_OK) { CHECK(buffer == NULL); return rc; }
    for (;;) {
        CHECK(buffer != NULL && *size + solaris_buffer_length(buffer) <= 80000u);
        memcpy(wire + *size, solaris_buffer_data(buffer), solaris_buffer_length(buffer)); *size += solaris_buffer_length(buffer);
        solaris_buffer_release(buffer); buffer = NULL; uint64_t delay;
        rc = ops->next_preface(stream, &buffer, &delay);
        if (rc != SOLARIS_OK) { CHECK(buffer == NULL); return rc; }
        CHECK(delay == 0u);
        if (buffer == NULL) break;
    }
    return SOLARIS_OK;
}
static void start_fixture(fixture_t *f, const char *root, int id, int emit)
{
    uint8_t wire[80000], expected[80000]; size_t size;
    CHECK(ops->raw->read(f->stream) == SOLARIS_EBUSY && ops->raw->write(f->stream) == SOLARIS_EBUSY);
    CHECK(hello(f->stream, wire, &size) == SOLARIS_OK && size == 1370u && !ops->ready(f->stream));
    if (emit) save(root, "hello", id, wire, size);
    else { size_t count = load(root, "hello", id, expected, sizeof(expected)); CHECK(count == size && memcmp(wire, expected, size) == 0); }
}
static solaris_status_t parse(fixture_t *f, const uint8_t *wire, size_t size, size_t *received, int faults)
{
    size_t begin = 0u, end = 0u; *received = 0u; int padding_fault = 0, record_fault = 0;
    while (begin < size) {
        if (end < size) { size_t step = size - end; if (step > 37u) step = 37u; end += step; }
        if (faults && ((begin == 1186u && end - begin >= 17u && !padding_fault) ||
                       (begin == 1203u && end - begin >= 8213u && !record_fault))) {
            f->env.fail_next = 1; size_t consumed; solaris_buffer_t *out = NULL;
            CHECK(ops->decode(f->stream, wire + begin, end - begin, &consumed, &out) == SOLARIS_ENOMEM);
            CHECK(consumed == 0u && out == NULL);
            if (begin == 1186u) padding_fault = 1; else record_fault = 1;
        }
        size_t consumed = 0u; solaris_buffer_t *out = NULL;
        solaris_status_t rc = ops->decode(f->stream, wire + begin, end - begin, &consumed, &out);
        CHECK(consumed <= end - begin); begin += consumed;
        if (rc == SOLARIS_EAGAIN) {
            CHECK(consumed == 0u && out == NULL); if (end == size) return SOLARIS_EIO; continue;
        }
        if (rc != SOLARIS_OK) { CHECK(out == NULL); return rc; }
        CHECK(consumed != 0u);
        if (out != NULL) {
            CHECK(ops->ready(f->stream));
            for (size_t i = 0u; i < solaris_buffer_length(out); ++i) CHECK(solaris_buffer_data(out)[i] == pattern(*received + i));
            *received += solaris_buffer_length(out); solaris_buffer_release(out);
        }
    }
    if (faults) CHECK(padding_fault && record_fault);
    return ops->finish(f->stream);
}
static solaris_buffer_t *encode(fixture_t *f, int allocation_failure)
{
    solaris_buffer_t *plain, *wire = NULL; CHECK(solaris_buffer_allocate(f->budget, 20003u, &plain) == SOLARIS_OK);
    for (size_t i = 0u; i < 20003u; ++i) solaris_buffer_mutable_data(plain)[i] = pattern(i);
    CHECK(solaris_buffer_set_length(plain, 20003u) == SOLARIS_OK); solaris_slice_t slice = {plain, 0u, 20003u};
    if (allocation_failure) { f->env.fail_next = 1; CHECK(ops->encode(f->stream, &slice, &wire) == SOLARIS_ENOMEM && wire == NULL); }
    CHECK(ops->encode(f->stream, &slice, &wire) == SOLARIS_OK); solaris_buffer_release(plain); return wire;
}
static void full(fixture_t *f, const char *root, int id, int faults)
{
    uint8_t wire[80000]; size_t size = load(root, "response", id, wire, sizeof(wire)), received;
    CHECK(parse(f, wire, size, &received, faults) == SOLARIS_OK && received == 20003u);
}
static void raw_exchange(fixture_t *f, const char *root, int id, int emit)
{
    uint8_t plain[87], wire[87], response[128], received[87];
    for (size_t i = 0u; i < 3u; ++i) {
        uint8_t *p = plain + i * 29u; p[0] = 23u; p[1] = p[2] = 3u; p[3] = 0u; p[4] = 24u;
        for (size_t n = 0u; n < 24u; ++n) p[5u + n] = pattern(n);
    }
    CHECK(ops->raw->write(f->stream) == SOLARIS_OK && ops->raw->read(f->stream) == SOLARIS_OK);
    for (size_t offset = 0u; offset < sizeof(plain);) {
        size_t count = offset % 7u + 1u; if (count > sizeof(plain) - offset) count = sizeof(plain) - offset;
        solaris_buffer_t *input, *out = NULL;
        CHECK(solaris_buffer_copy(f->budget, plain + offset, count, &input) == SOLARIS_OK);
        solaris_slice_t slice = {input, 0u, count};
        f->env.fail_next = 1; CHECK(ops->encode(f->stream, &slice, &out) == SOLARIS_ENOMEM && out == NULL);
        CHECK(ops->encode(f->stream, &slice, &out) == SOLARIS_OK && solaris_buffer_length(out) == count);
        memcpy(wire + offset, solaris_buffer_data(out), count); offset += count;
        solaris_buffer_release(input); solaris_buffer_release(out);
    }
    if (emit) save(root, "raw-request", id, wire, sizeof(wire));
    CHECK(load(root, "raw-response", id, response, sizeof(response)) == sizeof(plain));
    for (size_t offset = 0u; offset < sizeof(plain);) {
        size_t count = offset % 11u + 1u; if (count > sizeof(plain) - offset) count = sizeof(plain) - offset;
        size_t consumed; solaris_buffer_t *out = NULL;
        f->env.fail_next = 1;
        CHECK(ops->decode(f->stream, response + offset, count, &consumed, &out) == SOLARIS_ENOMEM && consumed == 0u && out == NULL);
        CHECK(ops->decode(f->stream, response + offset, count, &consumed, &out) == SOLARIS_OK && consumed == count);
        CHECK(solaris_buffer_length(out) == count); memcpy(received + offset, solaris_buffer_data(out), count);
        offset += count; solaris_buffer_release(out);
        if (id % 3 == 2 && offset < 29u) CHECK(ops->finish(f->stream) == SOLARIS_EIO);
    }
    CHECK(memcmp(received, plain, sizeof(plain)) == 0 && ops->finish(f->stream) == SOLARIS_OK);
}
static void normal(const char *root, int id, int resumed_response)
{
    fixture_t f; init(&f, root, id); start_fixture(&f, root, id, 0); full(&f, root, id, !resumed_response);
    solaris_buffer_t *records = encode(&f, !resumed_response);
    if (!resumed_response) save(root, "records", id, solaris_buffer_data(records), solaris_buffer_length(records));
    solaris_buffer_release(records); raw_exchange(&f, root, id, !resumed_response);
    ops->destroy(f.stream); f.stream = NULL;
    CHECK(ops->create(f.client, f.budget, &f.stream) == SOLARIS_OK);
    uint8_t request[80000]; size_t count;
    CHECK(hello(f.stream, request, &count) == SOLARIS_OK && count == 98u && ops->ready(f.stream));
    records = encode(&f, 0);
    memcpy(request + count, solaris_buffer_data(records), solaris_buffer_length(records)); count += solaris_buffer_length(records);
    solaris_buffer_release(records);
    if (!resumed_response) save(root, "resume", id, request, count);
    else {
        uint8_t expected[80000]; size_t expected_count = load(root, "resume", id, expected, sizeof(expected));
        CHECK(expected_count == count && memcmp(request, expected, count) == 0);
        size_t received, n = load(root, "resumed-response", id, expected, sizeof(expected));
        CHECK(parse(&f, expected, n, &received, 0) == SOLARIS_OK && received == 20003u);
    }
    clear(&f);
}
static void invalid_resumption(fixture_t *f)
{
    uint8_t noise[32] = {0}; size_t used; solaris_buffer_t *out;
    CHECK(ops->decode(f->stream, noise, sizeof(noise), &used, &out) == SOLARIS_OK && used == 16u && out == NULL);
    CHECK(ops->decode(f->stream, noise, 5u, &used, &out) == SOLARIS_EIO && used == 0u && out == NULL);
}
static void cache_tests(const char *root, int id)
{
    for (int mode = 0; mode < 5; ++mode) {
        fixture_t f; init(&f, root, id); start_fixture(&f, root, id, 0); full(&f, root, id, 0);
        ops->destroy(f.stream); f.stream = NULL;
        CHECK(ops->create(f.client, f.budget, &f.stream) == SOLARIS_OK);
        uint8_t request[80000]; size_t size;
        if (mode == 0) f.env.clock = UINT64_C(1000000000000);
        CHECK(hello(f.stream, request, &size) == SOLARIS_OK && size == (mode == 0 ? 1370u : 98u));
        if (mode == 0) { clear(&f); continue; }
        if (mode == 3) {
            /* A late failure of the older resumed channel cannot erase a
             * newer authenticated ticket. Deterministic entropy only lets
             * this unit test replay its own full-handshake fixture. */
            void *old = f.stream; f.env.clock = UINT64_C(1000000000000); f.env.random = 1u;
            CHECK(ops->create(f.client, f.budget, &f.stream) == SOLARIS_OK);
            start_fixture(&f, root, id, 0); full(&f, root, id, 0); ops->destroy(f.stream); f.stream = old;
        }
        if (mode == 2) CHECK(ops->finish(f.stream) == SOLARIS_EIO);
        else if (mode != 4) invalid_resumption(&f);
        ops->destroy(f.stream); f.stream = NULL;
        CHECK(ops->create(f.client, f.budget, &f.stream) == SOLARIS_OK);
        CHECK(hello(f.stream, request, &size) == SOLARIS_OK && size == (mode == 3 ? 98u : 1370u));
        clear(&f);
    }
}
static void invalid_tests(const char *root, int id)
{
    uint8_t good[80000], wire[80000]; size_t size = load(root, "response", id, good, sizeof(good));
    const size_t tamper[] = {1135u, 1167u, 1185u, 1202u, 1220u};
    for (size_t i = 0u; i < sizeof(tamper) / sizeof(tamper[0]); ++i) {
        fixture_t f; init(&f, root, id); start_fixture(&f, root, id, 0); memcpy(wire, good, size); wire[tamper[i]] ^= 1u;
        size_t received; CHECK(parse(&f, wire, size, &received, 0) == SOLARIS_EACCESS && received == 0u); clear(&f);
    }
    const char *names[] = {"bad-length", "bad-point"};
    for (size_t i = 0u; i < 2u; ++i) {
        fixture_t f; init(&f, root, id); start_fixture(&f, root, id, 0);
        size_t n = load(root, names[i], id, wire, sizeof(wire)), received;
        CHECK(parse(&f, wire, n, &received, 0) == (i == 0u ? SOLARIS_EIO : SOLARIS_EACCESS) && received == 0u); clear(&f);
    }
    const size_t cuts[] = {1u, 1135u, 1136u, 1167u, 1168u, 1185u, 1186u, 1202u, 1204u};
    for (size_t i = 0u; i < sizeof(cuts) / sizeof(cuts[0]); ++i) {
        fixture_t f; init(&f, root, id); start_fixture(&f, root, id, 0); size_t received;
        CHECK(parse(&f, good, cuts[i], &received, 0) == SOLARIS_EIO && received == 0u); clear(&f);
    }
    for (int reorder = 0; reorder < 2; ++reorder) {
        fixture_t f; init(&f, root, id); start_fixture(&f, root, id, 0);
        memcpy(wire, good, 1203u);
        if (reorder) memcpy(wire + 1203u, good + 1203u + 8213u, 8213u);
        else { memcpy(wire + 1203u, good + 1203u, 8213u); memcpy(wire + 1203u + 8213u, good + 1203u, 8213u); }
        size_t received; solaris_status_t rc = parse(&f, wire, 1203u + (reorder ? 8213u : 16426u), &received, 0);
        CHECK(rc == SOLARIS_EACCESS || (id % 3 == 2 && rc == SOLARIS_EIO));
        CHECK(received == (reorder ? 0u : 8192u)); clear(&f);
    }
    fixture_t f; init(&f, root, id); f.env.random = 17u; size_t count, received;
    CHECK(hello(f.stream, wire, &count) == SOLARIS_OK);
    CHECK(parse(&f, good, size, &received, 0) == SOLARIS_EACCESS && received == 0u); clear(&f);
}
static void rekey_tests(const char *root, int id)
{
    uint8_t expected[128], wire[87], united[96], iv[16], plain[8], output[8];
    CHECK(load(root, "rekey", id, expected, sizeof(expected)) == 87u);
    for (size_t i = 0u; i < 96u; ++i) united[i] = pattern(i);
    for (size_t i = 0u; i < 16u; ++i) iv[i] = pattern(i);
    for (size_t i = 0u; i < 8u; ++i) plain[i] = pattern(i);
    for (int direction = 0; direction < 2; ++direction) {
        solaris_vless_encryption_aead_t aead = {0}; solaris_vless_encryption_ctr_t ctr = {0};
        CHECK(solaris_vless_encryption_aead_init(&aead, id >= 3, "record-test", 11u, united, 96u) == SOLARIS_OK);
        memset(aead.nonce, 255, 12u); aead.nonce[11] = 254u;
        if (id % 3 == 2) solaris_vless_encryption_ctr_init(&ctr, united, 96u, iv);
        for (size_t record = 0u; record < 3u; ++record) {
            if (direction == 0) CHECK(solaris_vless_encryption_record_seal(&aead, &ctr, id % 3 == 2, id >= 3, united, plain, 8u, wire + record * 29u) == SOLARIS_OK);
            else {
                uint8_t nonce[12], bad[29]; memcpy(nonce, aead.nonce, 12u); solaris_vless_encryption_ctr_t before = ctr;
                for (size_t cut = 0u; cut < 29u; ++cut) {
                    size_t length; CHECK(solaris_vless_encryption_record_size(&ctr, id % 3 == 2, expected + record * 29u, cut, &length) == SOLARIS_EAGAIN);
                }
                memcpy(bad, expected + record * 29u, 29u); bad[28] ^= 1u;
                CHECK(solaris_vless_encryption_record_open(&aead, &ctr, id % 3 == 2, id >= 3, united, bad, 29u, output) == SOLARIS_EACCESS);
                CHECK(memcmp(nonce, aead.nonce, 12u) == 0 && memcmp(&before, &ctr, sizeof(ctr)) == 0);
                CHECK(solaris_vless_encryption_record_open(&aead, &ctr, id % 3 == 2, id >= 3, united, expected + record * 29u, 29u, output) == SOLARIS_OK);
                CHECK(memcmp(output, plain, 8u) == 0);
            }
        }
        if (direction == 0) CHECK(memcmp(wire, expected, 87u) == 0);
        solaris_vless_encryption_aead_clear(&aead);
    }
}
static void config_tests(const char *root)
{
    char text[16384], valid[16384]; size_t n = load(root, "config", 0, (uint8_t *)valid, sizeof(valid) - 1u); valid[n] = '\0';
    const char *key = strrchr(valid, '.') + 1;
    const char *bad[] = {"", "mlkem768x25519plus.native.0rtt.", "other.native.0rtt", "mlkem768x25519plus.invalid.0rtt",
        "mlkem768x25519plus.native.2rtt", "mlkem768x25519plus.native.0rtt.99-35-35", "mlkem768x25519plus.native.0rtt.100-34-35",
        "mlkem768x25519plus.native.0rtt.100-35-34", "mlkem768x25519plus.native.0rtt.100-65554-65554",
        "mlkem768x25519plus.native.0rtt.100-35-35.100-60001-60001.100-35-35",
        "mlkem768x25519plus.native.0rtt.100-35-35.0-0-0", "mlkem768x25519plus.native.0rtt.100-35-35-3"};
    solaris_vless_encryption_config_t config; CHECK(solaris_vless_encryption_config_parse("none", &config) == SOLARIS_OK && config.key_count == 0u);
    for (size_t i = 0u; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        CHECK(snprintf(text, sizeof(text), "%s.%s", bad[i], key) > 0);
        CHECK(solaris_vless_encryption_config_parse(text, &config) != SOLARIS_OK);
    }
    CHECK(snprintf(text, sizeof(text), "mlkem768x25519plus.native.0rtt.%s=", key) > 0);
    CHECK(solaris_vless_encryption_config_parse(text, &config) != SOLARIS_OK);
    CHECK(solaris_vless_encryption_config_parse("mlkem768x25519plus.native.0rtt.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &config) != SOLARIS_OK);
}
int main(int argc, char **argv)
{
    CHECK(argc == 3);
    if (strcmp(argv[1], "emit") == 0) {
        for (int id = 0; id < 6; ++id) { fixture_t f; init(&f, argv[2], id); start_fixture(&f, argv[2], id, 1); clear(&f); }
    } else if (strcmp(argv[1], "verify") == 0) {
        config_tests(argv[2]);
        for (int id = 0; id < 6; ++id) {
            normal(argv[2], id, 0); invalid_tests(argv[2], id); cache_tests(argv[2], id); rekey_tests(argv[2], id);
            for (int allocation = 1; allocation <= 3; ++allocation) {
                fixture_t f; init(&f, argv[2], id); f.env.fail_at = f.env.allocations + allocation;
                uint8_t wire[80000]; size_t size; CHECK(hello(f.stream, wire, &size) == SOLARIS_ENOMEM); clear(&f);
            }
        }
    } else {
        CHECK(strcmp(argv[1], "resumed") == 0); for (int id = 0; id < 6; ++id) normal(argv[2], id, 1);
    }
    puts("VLESS encryption codec phase passed"); return 0;
}
