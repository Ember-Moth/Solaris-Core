#include "solaris_builtin_modules.h"
#include "codec/address/socks.h"
#include "codec/address/vmess.h"
#include "codec/uot/codec.h"
#include "codec/xudp/codec.h"
#include "codec/ip/packet.h"
#if SOLARIS_HAS_PROXY_INBOUND
#include "codec/http/proxy.h"
#endif
#include "observe/probe/http_codec.h"
#include "contracts/module/module.h"
#if SOLARIS_HAS_TLS
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/mem.h>
#endif
#if SOLARIS_HAS_VLESS
#include "adapters/outbound/vless/internal.h"
#include "adapters/outbound/vless/vision/codec.h"
#include "adapters/outbound/vless/encryption/client.h"
#include "adapters/outbound/vless/encryption/crypto.h"
#include <openssl/base64.h>
#include <openssl/curve25519.h>
#endif
#if SOLARIS_HAS_SHADOWSOCKS
#include "adapters/outbound/shadowsocks/packet.h"
#endif
#if SOLARIS_HAS_ANYTLS
#include "adapters/outbound/anytls/internal.h"
#endif
#if SOLARIS_HAS_SOCKS5
#include "adapters/outbound/socks5/codec.h"
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Corpus prefix: parser id, variant, allocation failure index (zero disables).
 * The target owns no network/thread/process state and returns to zero budget
 * after every input. Stateful parsers receive a small split then coalesced
 * input, with a bounded number of records per invocation. */
typedef struct fuzz_environment { unsigned int allocations, failure, random; } fuzz_environment_t;
static void *allocate(void *context, size_t size)
{ fuzz_environment_t *env = context; if (++env->allocations == env->failure) return NULL; return malloc(size); }
#if SOLARIS_HAS_VLESS || SOLARIS_HAS_SHADOWSOCKS || SOLARIS_HAS_ANYTLS
static solaris_status_t fixed_random(void *context, uint8_t *out, size_t size)
{ (void)context; memset(out, 0x42, size); return SOLARIS_OK; }
#endif
#if SOLARIS_HAS_SHADOWSOCKS
static uint64_t unix_time(void *context) { (void)context; return UINT64_C(1700000000); }
#endif
#if SOLARIS_HAS_VLESS || SOLARIS_HAS_SHADOWSOCKS
static uint64_t clock_time(void *context) { (void)context; return 0u; }
#endif
static void address_fuzz(const uint8_t *data, size_t size, int vmess)
{
    solaris_address_t address = {0}, decoded; size_t used = 0u, written = 0u, again = 0u; uint8_t wire[260];
    solaris_status_t rc = vmess ? solaris_vmess_address_read(data, size, &address, &used) : solaris_socks_address_read(data, size, &address, &used);
    assert(used <= size);
    if (rc != SOLARIS_OK) return;
    rc = vmess ? solaris_vmess_address_write(&address, wire, sizeof(wire), &written) : solaris_socks_address_write(&address, wire, sizeof(wire), &written);
    if (rc != SOLARIS_OK) return;
    rc = vmess ? solaris_vmess_address_read(wire, written, &decoded, &again) : solaris_socks_address_read(wire, written, &decoded, &again);
    assert(rc == SOLARIS_OK && again == written && solaris_address_equal(&address, &decoded));
}
static void datagram_fuzz(solaris_budget_t *budget, const solaris_datagram_codec_ops_t *ops, const uint8_t *data, size_t size, unsigned int mode)
{
    void *state = NULL; if (ops->create(NULL, budget, &state) != SOLARIS_OK) { if (state != NULL) ops->destroy(state); return; }
    solaris_address_t target; (void)solaris_address_parse("127.0.0.1", 53u, &target);
    solaris_buffer_t *plain = NULL, *wire = NULL;
    if (solaris_buffer_copy(budget, "x", 1u, &plain) == SOLARIS_OK) {
        solaris_slice_t slice = {plain, 0u, 1u}; (void)ops->encode(state, &target, &slice, &wire);
    }
    solaris_buffer_release(plain); solaris_buffer_release(wire);
    size_t begin = 0u, end = size < mode % 32u + 1u ? size : mode % 32u + 1u;
    for (unsigned int steps = 0u; begin < size && steps < 64u; ++steps) {
        size_t used = 0u; solaris_address_t source = {0}; solaris_buffer_t *out = NULL;
        solaris_status_t rc = ops->decode(state, data + begin, end - begin, &used, &source, &out);
        assert(used <= end - begin); begin += used; solaris_buffer_release(out);
        if (rc == SOLARIS_EAGAIN && end < size) { end = size; continue; }
        if (rc != SOLARIS_OK) break;
        assert(used != 0u || out != NULL); end = size;
    }
    (void)ops->finish(state); ops->destroy(state);
}
#if SOLARIS_HAS_VLESS || SOLARIS_HAS_SHADOWSOCKS
static void stream_fuzz(solaris_budget_t *budget, const solaris_stream_codec_ops_t *ops, const void *parameters,
    const uint8_t *data, size_t size, unsigned int mode)
{
    void *state = NULL;
    if (ops->create(parameters, budget, &state) != SOLARIS_OK) { if (state != NULL) ops->destroy(state); return; }
    solaris_buffer_t *preface = NULL; solaris_status_t rc = ops->start(state, &preface); solaris_buffer_release(preface);
    if (rc == SOLARIS_OK && ops->next_preface != NULL) for (unsigned int n = 0u; n < 32u; ++n) {
        uint64_t delay; preface = NULL; rc = ops->next_preface(state, &preface, &delay);
        int last = preface == NULL; solaris_buffer_release(preface); if (rc != SOLARIS_OK || last) break;
    }
    if (rc == SOLARIS_OK) {
        if (size > ops->receive_limit) size = ops->receive_limit;
        size_t begin = 0u, end = size < mode % 32u + 1u ? size : mode % 32u + 1u;
        for (unsigned int steps = 0u; begin < size && steps < 64u; ++steps) {
            size_t used = 0u; solaris_buffer_t *out = NULL;
            rc = ops->decode(state, data + begin, end - begin, &used, &out);
            assert(used <= end - begin); begin += used; solaris_buffer_release(out);
            if (rc == SOLARIS_EAGAIN && end < size) { end = size; continue; }
            if (rc != SOLARIS_OK) break;
            assert(used != 0u || out != NULL); end = size;
            if (ops->carrier_raw != NULL) ops->carrier_raw->applied(state, ops->carrier_raw->requested(state));
        }
        (void)ops->finish(state);
    }
    ops->destroy(state);
}
#endif
#if SOLARIS_HAS_VLESS
static solaris_vless_vision_parameters_t vision_parameters(void)
{
    solaris_vless_vision_parameters_t parameters = {.request = {.command = 1u, .vision = 1u}, .crypto = {.random = fixed_random}};
    (void)solaris_address_parse("127.0.0.1", 443u, &parameters.request.destination);
    for (unsigned int i = 0u; i < 16u; ++i) parameters.request.uuid[i] = (uint8_t)i;
    return parameters;
}
static void vision_encode_fuzz(solaris_budget_t *budget, const uint8_t *data, size_t size)
{
    solaris_vless_vision_parameters_t parameters = vision_parameters(); void *state = NULL;
    const solaris_stream_codec_ops_t *ops = &solaris_vless_vision_codec;
    if (ops->create(&parameters, budget, &state) != SOLARIS_OK) return;
    solaris_buffer_t *out = NULL; solaris_status_t rc = ops->start(state, &out); solaris_buffer_release(out);
    if (rc == SOLARIS_OK) {
        if (size >= 2u) {
            size_t response = ((size_t)data[0] << 8u) | data[1];
            if (response <= size - 2u) {
                size_t offset = 0u;
                for (unsigned int step = 0u; offset < response && step < 32u; ++step) {
                    size_t used = 0u; out = NULL;
                    rc = ops->decode(state, data + 2u + offset, response - offset, &used, &out);
                    assert(used <= response - offset); solaris_buffer_release(out);
                    if (rc != SOLARIS_OK || used == 0u) break;
                    offset += used; ops->carrier_raw->applied(state, ops->carrier_raw->requested(state));
                }
                data += 2u + response; size -= 2u + response;
            }
        }
        solaris_buffer_t *input = NULL;
        if (solaris_buffer_copy(budget, data, size, &input) == SOLARIS_OK) {
            solaris_slice_t slice = {input, 0u, size}; out = NULL; (void)ops->encode(state, &slice, &out); solaris_buffer_release(out);
            ops->carrier_raw->applied(state, ops->carrier_raw->requested(state)); solaris_buffer_release(input);
        }
    }
    ops->destroy(state);
}
static solaris_status_t sequential_random(void *context, uint8_t *out, size_t size)
{ fuzz_environment_t *env = context; for (size_t i = 0u; i < size; ++i) out[i] = (uint8_t)env->random++; return SOLARIS_OK; }
static void encryption_fuzz(solaris_budget_t *budget, fuzz_environment_t *env, const uint8_t *data, size_t size, unsigned int mode)
{
    uint8_t private_key[32], public_key[32], encoded[45];
    for (unsigned int i = 0u; i < 32u; ++i) private_key[i] = (uint8_t)(i + 1u);
    X25519_public_from_private(public_key, private_key); (void)EVP_EncodeBlock(encoded, public_key, 32u);
    for (size_t i = 0u; i < 43u; ++i) { if (encoded[i] == '+') encoded[i] = '-'; else if (encoded[i] == '/') encoded[i] = '_'; } encoded[43] = 0u;
    const char *appearances[] = {"native", "xorpub", "random"}; char text[256];
    (void)snprintf(text, sizeof(text), "mlkem768x25519plus.%s.0rtt.100-35-35.100-0-0.100-37-37.%s", appearances[mode % 3u], encoded);
    solaris_vless_encryption_config_t config;
    if (solaris_vless_encryption_config_parse(text, &config) != SOLARIS_OK) abort(); config.chacha = (mode / 3u) % 2u;
    solaris_crypto_source_t random = {.context = env, .random = sequential_random}; solaris_vless_encryption_client_t *client = NULL;
    if (solaris_vless_encryption_client_create(&config, budget, &random, NULL, clock_time, &client) == SOLARIS_OK)
        stream_fuzz(budget, &solaris_vless_encryption_codec, client, data, size, mode);
    solaris_vless_encryption_client_release(client);
}
static void record_fuzz(const uint8_t *data, size_t size, unsigned int mode)
{
    uint8_t key[96], iv[16], wire[8213], output[8213], raw[8213]; memset(key, 0x42, sizeof(key)); memset(iv, 0x24, sizeof(iv));
    solaris_vless_encryption_aead_t tx = {0}, rx = {0}; solaris_vless_encryption_ctr_t a = {0}, b = {0};
    int chacha = mode & 1u, masked = (mode & 2u) != 0;
    if (solaris_vless_encryption_aead_init(&tx, chacha, "fuzz", 4u, key, sizeof(key)) != SOLARIS_OK ||
        solaris_vless_encryption_aead_init(&rx, chacha, "fuzz", 4u, key, sizeof(key)) != SOLARIS_OK) goto done;
    solaris_vless_encryption_ctr_init(&a, key, sizeof(key), iv); b = a;
    size_t observed; (void)solaris_vless_encryption_record_size(&a, masked, data, size, &observed);
    if (size < 13u) goto done;
    memcpy(tx.nonce, data, 12u); memcpy(rx.nonce, data, 12u); data += 12u; size -= 12u; if (size > 8192u) size = 8192u;
    if (solaris_vless_encryption_record_seal(&tx, &a, masked, chacha, key, data, size, wire) != SOLARIS_OK) goto done;
    if (mode & 4u) wire[size + 20u] ^= 1u;
    solaris_status_t rc = solaris_vless_encryption_record_open(&rx, &b, masked, chacha, key, wire, size + 21u, output);
    if (mode & 4u) assert(rc == SOLARIS_EACCESS); else assert(rc == SOLARIS_OK && memcmp(output, data, size) == 0);
    size_t payload = size < 17u ? 17u : size;
    raw[0] = 23u; raw[1] = raw[2] = 3u; raw[3] = (uint8_t)(payload >> 8u); raw[4] = (uint8_t)payload;
    memset(raw + 5u, 0, payload); memcpy(raw + 5u, data, size);
    solaris_vless_encryption_ctr_init(&a, key, sizeof(key), iv); b = a;
    solaris_vless_encryption_mask_t ma = {0}, mb = {0};
    assert(solaris_vless_encryption_mask_stream(&a, &ma, 1, raw, payload + 5u, wire) == SOLARIS_OK);
    assert(solaris_vless_encryption_mask_stream(&b, &mb, 0, wire, 2u, output) == SOLARIS_OK);
    assert(solaris_vless_encryption_mask_stream(&b, &mb, 0, wire + 2u, payload + 3u, output + 2u) == SOLARIS_OK);
    assert(memcmp(raw, output, payload + 5u) == 0);
done:
    solaris_vless_encryption_aead_clear(&tx); solaris_vless_encryption_aead_clear(&rx);
}
#endif
#if SOLARIS_HAS_SHADOWSOCKS
static void ss_fuzz(solaris_budget_t *budget, const uint8_t *data, size_t size, unsigned int mode, int packet)
{
    const char *methods[] = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"};
    unsigned int method = mode % 6u;
    const char *password = method == 3u ? "SUlJSUlJSUlJSUlJSUlJSQ==" : method >= 4u ? "SUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUlJSUk=" : "solaris-independent-peer";
    solaris_ss_parameters_t parameters = {.source = {.random = fixed_random, .unix_seconds = unix_time}};
    (void)solaris_address_parse("127.0.0.1", 53u, &parameters.destination);
    if (solaris_ss_key_parse(methods[method], password, &parameters.key) != SOLARIS_OK) abort();
    if (solaris_replay_create(budget, 64u, 0u, NULL, NULL, &parameters.replay) != SOLARIS_OK) return;
    if (packet) {
        solaris_ss_packet_t *codec = NULL;
        if (solaris_ss_packet_create(budget, &parameters, clock_time, NULL, &codec) == SOLARIS_OK) {
            solaris_address_t source; solaris_buffer_t *out = NULL;
            (void)solaris_ss_packet_decode(codec, data, size, &source, &out); solaris_buffer_release(out); solaris_ss_packet_destroy(codec);
        }
    } else stream_fuzz(budget, &solaris_ss_stream_codec, &parameters, data, size, mode);
    solaris_replay_release(parameters.replay);
}
#endif
#if SOLARIS_HAS_ANYTLS
static void anytls_fuzz(solaris_budget_t *budget, const uint8_t *data, size_t size, unsigned int mode)
{
    solaris_anytls_parameters_t parameters = {.crypto = {.random = fixed_random}};
    (void)solaris_anytls_policy_default(&parameters.policy); void *state = NULL;
    const solaris_session_codec_t *ops = &solaris_anytls_session_codec;
    if (ops->create(&parameters, budget, &state) != SOLARIS_OK) return;
    solaris_session_batch_t batch = {0}; solaris_status_t rc = ops->start(state, &batch); solaris_session_batch_clear(&batch);
    solaris_address_t target; (void)solaris_address_parse("127.0.0.1", 443u, &target); int wait_ack;
    if (rc == SOLARIS_OK) { rc = ops->open(state, 1u, &target, &wait_ack, &batch); solaris_session_batch_clear(&batch); }
    if (rc == SOLARIS_OK) {
        size_t begin = 0u, end = size < mode % 32u + 1u ? size : mode % 32u + 1u;
        for (unsigned int step = 0u; begin < size && step < 64u; ++step) {
            solaris_session_event_t event = {0}; size_t used = 0u;
            rc = ops->decode(state, data + begin, end - begin, &used, &event);
            assert(used <= end - begin); begin += used; solaris_buffer_release(event.data); solaris_session_batch_clear(&event.reply);
            if (rc == SOLARIS_EAGAIN && end < size) { end = size; continue; }
            if (rc != SOLARIS_OK) break;
            assert(used != 0u); end = size;
        }
    }
    ops->destroy(state);
}
#endif
static void config_fuzz(solaris_budget_t *budget, const uint8_t *data, size_t size, unsigned int mode)
{
    solaris_registry_t *registry = NULL; if (solaris_builtin_registry_create(budget, &registry, NULL) != SOLARIS_OK) return;
    const char *types[] = {"vless", "shadowsocks", "anytls", "direct", "block", "socks5"};
    const char *keys[] = {"encryption", "flow", "cipher", "password", "server", "unknown", "uuid", "ca-pem", "username"};
    solaris_config_field_t fields[8] = {
        {.name = "server", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"127.0.0.1", 9u}}},
        {.name = "port", .value = {.kind = SOLARIS_CONFIG_INTEGER, .value.integer = 443}},
    };
    unsigned int type = mode % 6u;
    size_t count = type == 3u || type == 4u ? 0u : 2u;
    if (type == 0u) fields[count++] = (solaris_config_field_t){.name = "uuid", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"00010203-0405-0607-0809-0a0b0c0d0e0f", 36u}}};
    if (type == 1u) fields[count++] = (solaris_config_field_t){.name = "cipher", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"aes-128-gcm", 11u}}};
    if (type == 1u || type == 2u || type == 5u) fields[count++] = (solaris_config_field_t){.name = "password", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"password", 8u}}};
    if (type == 5u) fields[count++] = (solaris_config_field_t){.name = "username", .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {"username", 8u}}};
    if (type == 2u) fields[count++] = (solaris_config_field_t){.name = "tls", .value = {.kind = SOLARIS_CONFIG_BOOL, .value.boolean = 1}};
    const char *name = keys[(mode / 6u) % 9u]; size_t index = count;
    if (!(mode & 128u)) for (size_t i = 0u; i < count; ++i) if (strcmp(fields[i].name, name) == 0) { index = i; break; }
    fields[index] = (solaris_config_field_t){.name = name, .value = {.kind = SOLARIS_CONFIG_STRING, .value.string = {(const char *)data, size}}};
    if (index == count) count++;
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {fields, count}}; solaris_module_config_t *compiled = NULL;
    (void)solaris_registry_compile(registry, types[type], &view, &compiled, NULL); solaris_module_config_release(compiled); solaris_registry_destroy(registry);
}
#if SOLARIS_HAS_SOCKS5
static void socks5_fuzz(solaris_budget_t *budget, const uint8_t *data, size_t size, unsigned int mode)
{
    solaris_socks5_credentials_t credentials = {0};
    if (mode & 1u) { credentials.username_length = credentials.password_length = 1u; credentials.username[0] = 'u'; credentials.password[0] = 'p'; }
    solaris_address_t target; (void)solaris_address_parse("127.0.0.1", 53u, &target);
    solaris_socks5_handshake_t state;
    assert(solaris_socks5_handshake_init(&state, &credentials, mode & 2u ? 3u : 1u, &target) == SOLARIS_OK);
    size_t begin = 0u, end = size < mode % 32u + 1u ? size : mode % 32u + 1u;
    for (unsigned step = 0u; step < 16u && state.stage != SOLARIS_SOCKS5_READY; ++step) {
        if (solaris_socks5_handshake_wants_write(&state)) {
            solaris_buffer_t *wire = NULL;
            solaris_status_t rc = solaris_socks5_handshake_write(&state, budget, &wire); solaris_buffer_release(wire);
            if (rc != SOLARIS_OK) break;
        } else {
            size_t used = 0u; solaris_status_t rc = solaris_socks5_handshake_read(&state, data + begin, end - begin, &used);
            assert(used <= end - begin); begin += used;
            if (rc == SOLARIS_EAGAIN && end < size) { end = size; continue; }
            if (rc != SOLARIS_OK) break;
            assert(used != 0u); end = size;
        }
    }
    solaris_socks5_clear(&state, sizeof(state));
}
#endif
#if SOLARIS_HAS_PROXY_INBOUND
static void http_proxy_fuzz(solaris_budget_t *budget, const uint8_t *data, size_t size, unsigned mode)
{
    size_t header = 0;
    for (size_t i = 3; i < size && i < 32768; ++i)
        if (!memcmp(data + i - 3, "\r\n\r\n", 4)) { header = i + 1; break; }
    if (!header) header = size;
    solaris_http_metadata_t meta;
    solaris_http_request_t *request = NULL; solaris_buffer_t *output = NULL;
    solaris_status_t rc = solaris_http_request_create(budget, data, header, 32768, &meta, &output, &request);
    solaris_http_credentials_clear(&meta); solaris_buffer_release(output);
    if (rc != SOLARIS_OK) return;
    if (!meta.connect && !meta.websocket) {
        size_t offset = header;
        for (unsigned i = 0; i < 64 && !solaris_http_request_complete(request); ++i) {
            size_t used, n = size - offset, chunk = i ? 8192 : mode % 64 + 1;
            if (n > chunk) n = chunk;
            rc = solaris_http_request_body(request, data + offset, n, &used, &output);
            assert(used <= n); solaris_buffer_release(output); offset += used;
            if (rc != SOLARIS_OK || !n) break;
            assert(used || solaris_http_request_complete(request));
        }
        (void)solaris_http_request_eof(request);
    }
    solaris_http_request_destroy(request);
}
#endif
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < 3u || size > 196608u) return 0;
    unsigned int parser = data[0] % 23u, mode = data[1]; fuzz_environment_t environment = {.failure = data[2] & 63u, .random = 1u};
    data += 3u; size -= 3u;
    solaris_runtime_services_t services; solaris_runtime_services_init(&services); services.context = &environment; services.allocate = allocate;
    solaris_budget_t *budget = NULL; if (solaris_budget_create(8u * 1024u * 1024u, &services, &budget) != SOLARIS_OK) return 0;
    switch (parser) {
#if SOLARIS_HAS_PROXY_INBOUND
    case 21: http_proxy_fuzz(budget, data, size, mode); break;
    case 22: {
        solaris_http_upgrade_response_t *response = NULL;
        if (solaris_http_upgrade_response_create(budget, 32768, &response) != SOLARIS_OK) break;
        for (size_t offset = 0; offset < size;) {
            size_t n = size - offset, chunk = offset ? 4096 : mode % 64 + 1;
            if (n > chunk) n = chunk;
            solaris_buffer_t *output = NULL;
            solaris_status_t rc = solaris_http_upgrade_response_feed(response, data + offset, n, &output);
            solaris_buffer_release(output); offset += n;
            if (rc != SOLARIS_OK) break;
        }
        (void)solaris_http_upgrade_response_eof(response);
        solaris_http_upgrade_response_destroy(response); break;
    }
#endif
    case 20: {
        solaris_ip_packet_t packet;
        if (solaris_ip_parse(data, size, mode & 1u, &packet) == SOLARIS_OK) {
            assert(packet.payload_offset + packet.payload_length == size);
            solaris_buffer_t *copy = NULL;
            if (solaris_buffer_allocate(budget, size, &copy) == SOLARIS_OK) {
                memcpy(solaris_buffer_mutable_data(copy), data, size);
                assert(solaris_ip_rewrite(solaris_buffer_mutable_data(copy), size,
                    &packet.destination, &packet.source) == SOLARIS_OK);
                assert(solaris_ip_parse(solaris_buffer_data(copy), size, 1, &packet) == SOLARIS_OK);
                solaris_buffer_release(copy);
            }
        }
        break;
    }
    case 0: address_fuzz(data, size, 0); break;
    case 1: address_fuzz(data, size, 1); break;
    case 2: datagram_fuzz(budget, &solaris_uot_v2_codec, data, size, mode); break;
    case 3: datagram_fuzz(budget, &solaris_xudp_codec, data, size, mode); break;
#if SOLARIS_HAS_VLESS
    case 4: {
        solaris_vless_vision_parameters_t parameters = vision_parameters(); parameters.request.vision = 0u;
        stream_fuzz(budget, &solaris_vless_stream_codec, &parameters.request, data, size, mode); break;
    }
    case 5: { solaris_vless_vision_parameters_t parameters = vision_parameters(); stream_fuzz(budget, &solaris_vless_vision_codec, &parameters, data, size, mode); break; }
    case 6: vision_encode_fuzz(budget, data, size); break;
    case 11: {
        char text[SOLARIS_VLESS_ENCRYPTION_TEXT]; if (size >= sizeof(text)) size = sizeof(text) - 1u;
        memcpy(text, data, size); text[size] = '\0'; solaris_vless_encryption_config_t config; (void)solaris_vless_encryption_config_parse(text, &config); break;
    }
    case 12: record_fuzz(data, size, mode); break;
    case 13: encryption_fuzz(budget, &environment, data, size, mode); break;
#endif
#if SOLARIS_HAS_SHADOWSOCKS
    case 7: ss_fuzz(budget, data, size, mode, 0); break;
    case 8: ss_fuzz(budget, data, size, mode, 1); break;
#endif
#if SOLARIS_HAS_ANYTLS
    case 9: { solaris_anytls_policy_t policy; (void)solaris_anytls_policy_parse(data, size, &policy); break; }
    case 10: anytls_fuzz(budget, data, size, mode); break;
#endif
    case 14: {
        char url[2049]; if (size >= sizeof(url)) size = sizeof(url) - 1u; memcpy(url, data, size); url[size] = '\0';
        solaris_http_probe_target_t target; solaris_buffer_t *request = NULL;
        (void)solaris_http_probe_request(budget, url, &target, &request); solaris_buffer_release(request); break;
    }
    case 15: { uint16_t status; (void)solaris_http_probe_response(data, size, &status); break; }
    case 16: config_fuzz(budget, data, size, mode); break;
#if SOLARIS_HAS_SOCKS5
    case 17: socks5_fuzz(budget, data, size, mode); break;
    case 18: {
        solaris_address_t source; solaris_buffer_t *out = NULL;
        (void)solaris_socks5_packet_decode(budget, data, size, &source, &out); solaris_buffer_release(out); break;
    }
#endif
#if SOLARIS_HAS_TLS
    case 19: {
        SSL_CTX *context = SSL_CTX_new(TLS_method());
        if (context != NULL) {
            SSL_SESSION *session = SSL_SESSION_from_bytes(data, size, context);
            if (session != NULL && SSL_SESSION_is_resumable(session)) {
                uint8_t *encoded = NULL; size_t encoded_size;
                if (SSL_SESSION_to_bytes(session, &encoded, &encoded_size)) {
                    SSL_SESSION *copy = SSL_SESSION_from_bytes(encoded, encoded_size, context);
                    assert(copy != NULL); SSL_SESSION_free(copy); OPENSSL_free(encoded);
                }
            }
            SSL_SESSION_free(session); SSL_CTX_free(context); ERR_clear_error();
        }
        break;
    }
#endif
    default: break;
    }
    assert(solaris_budget_used(budget) == 0u); solaris_budget_release(budget); return 0;
}
