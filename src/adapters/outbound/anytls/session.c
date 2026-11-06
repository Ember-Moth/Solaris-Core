#include "adapters/outbound/anytls/internal.h"
#include "codec/address/socks.h"
#include <stdio.h>
#include <string.h>

enum { WASTE, SYN, PSH, FIN, SETTINGS, ALERT, UPDATE_PADDING, SYNACK, HEART_REQUEST, HEART_RESPONSE, SERVER_SETTINGS };
typedef struct anytls_session {
    solaris_budget_t *budget;
    solaris_anytls_parameters_t *client;
    solaris_anytls_policy_t policy;
    uint32_t packet;
    int settings_sent, server_settings;
} anytls_session_t;
static void frame(uint8_t *p, uint8_t command, uint32_t id, size_t length)
{
    p[0] = command; p[1] = (uint8_t)(id >> 24); p[2] = (uint8_t)(id >> 16); p[3] = (uint8_t)(id >> 8); p[4] = (uint8_t)id;
    p[5] = (uint8_t)(length >> 8); p[6] = (uint8_t)length;
}
static solaris_status_t create(void *parameters, solaris_budget_t *budget, void **out)
{
    anytls_session_t *s = solaris_memory_allocate(budget, sizeof(*s)); if (s == NULL) return SOLARIS_ENOMEM;
    memset(s, 0, sizeof(*s)); s->client = parameters; s->policy = s->client->policy; s->budget = budget; *out = s; return SOLARIS_OK;
}
static solaris_status_t start(void *state, solaris_session_batch_t *out)
{
    anytls_session_t *s = state; size_t pad;
    solaris_status_t rc = solaris_anytls_padding0(s->client, &s->policy, &pad); if (rc != SOLARIS_OK) return rc;
    solaris_buffer_t *b; rc = solaris_buffer_allocate(s->budget, 34u + pad, &b); if (rc != SOLARIS_OK) return rc;
    uint8_t *p = solaris_buffer_mutable_data(b); memcpy(p, s->client->password_hash, 32u);
    p[32] = (uint8_t)(pad >> 8); p[33] = (uint8_t)pad; memset(p + 34u, 0, pad);
    (void)solaris_buffer_set_length(b, 34u + pad); out->buffers[out->count++] = b; return SOLARIS_OK;
}
static solaris_status_t pad(anytls_session_t *s, const uint8_t *data, size_t size, solaris_session_batch_t *out)
{
    uint32_t packet = s->packet == UINT32_MAX ? UINT32_MAX : s->packet + 1u;
    solaris_status_t rc = solaris_anytls_pad(s->client, &s->policy, packet, s->budget, data, size, out);
    if (rc == SOLARIS_OK) s->packet = packet;
    return rc;
}
static solaris_status_t open_stream(void *state, uint32_t id, const solaris_address_t *peer, int *wait_ack, solaris_session_batch_t *out)
{
    anytls_session_t *s = state; uint8_t wire[512]; size_t pos = 0u;
    /* UoT has an application preface before the server can acknowledge its
     * destination. Let the datagram layer send that preface after open. */
    *wait_ack = !(peer->family == SOLARIS_ADDRESS_DOMAIN && peer->port == 0u && strcmp(peer->host, "sp.v2.udp-over-tcp.arpa") == 0);
    if (!s->settings_sent) {
        char settings[128]; int size = snprintf(settings, sizeof(settings), "v=2\nclient=Solaris/0.1.0\npadding-md5=%s", s->policy.md5);
        if (size <= 0 || (size_t)size >= sizeof(settings)) return SOLARIS_EIO;
        frame(wire, SETTINGS, 0u, (size_t)size); memcpy(wire + 7u, settings, (size_t)size); pos = 7u + (size_t)size;
    }
    frame(wire + pos, SYN, id, 0u); pos += 7u;
    size_t address_size = 0u;
    solaris_status_t rc = solaris_socks_address_encode(peer, wire + pos + 7u, sizeof(wire) - pos - 7u, &address_size);
    if (rc != SOLARIS_OK) return rc;
    frame(wire + pos, PSH, id, address_size); pos += 7u + address_size;
    rc = pad(s, wire, pos, out); if (rc == SOLARIS_OK) s->settings_sent = 1;
    return rc;
}
static solaris_status_t write_stream(void *state, uint32_t id, const solaris_slice_t *data, solaris_session_batch_t *out)
{
    anytls_session_t *s = state;
    if (data->length > 512u * 1024u) return SOLARIS_EMSGSIZE;
    size_t frames = data->length == 0u ? 1u : (data->length + 65534u) / 65535u;
    size_t size = data->length + 7u * frames;
    uint8_t *wire = solaris_memory_allocate(s->budget, size); if (wire == NULL) return SOLARIS_ENOMEM;
    size_t pos = 0u, offset = 0u;
    for (size_t i = 0u; i < frames; ++i) {
        size_t count = data->length - offset; if (count > 65535u) count = 65535u;
        frame(wire + pos, PSH, id, count); pos += 7u;
        if (count != 0u) memcpy(wire + pos, solaris_buffer_data(data->buffer) + data->offset + offset, count);
        pos += count; offset += count;
    }
    solaris_status_t rc = pad(s, wire, size, out); solaris_memory_free(wire); return rc;
}
static solaris_status_t end_stream(void *state, uint32_t id, solaris_session_batch_t *out)
{ uint8_t wire[7]; frame(wire, FIN, id, 0u); return pad(state, wire, sizeof(wire), out); }
static int version2(const uint8_t *p, size_t size)
{
    size_t start = 0u; int found = 0;
    for (size_t i = 0u; i <= size; ++i) {
        if (i != size && p[i] != '\n') { if (p[i] < 32u || p[i] > 126u) return 0; continue; }
        if (i - start >= 2u && p[start] == 'v' && p[start + 1u] == '=') {
            if (found || i - start != 3u || p[start + 2u] != '2') return 0;
            found = 1;
        }
        start = i + 1u;
    }
    return found;
}
static solaris_status_t decode(void *state, const uint8_t *wire, size_t size, size_t *used, solaris_session_event_t *event)
{
    anytls_session_t *s = state; *used = 0u;
    if (size < 7u) return SOLARIS_EAGAIN;
    uint8_t command = wire[0]; uint32_t id = (uint32_t)wire[1]<<24 | (uint32_t)wire[2]<<16 | (uint32_t)wire[3]<<8 | wire[4];
    size_t length = (size_t)wire[5] << 8 | wire[6];
    if (size < 7u + length) return SOLARIS_EAGAIN;
    const uint8_t *data = wire + 7u; event->id = id;
    solaris_status_t rc = SOLARIS_OK;
    switch (command) {
    case WASTE: break;
    case PSH:
        if (id == 0u || !s->server_settings) return SOLARIS_EIO;
        event->kind = SOLARIS_SESSION_DATA; rc = solaris_buffer_copy(s->budget, data, length, &event->data); break;
    case FIN:
        if (id == 0u || length != 0u) return SOLARIS_EIO;
        event->kind = SOLARIS_SESSION_END; break;
    case SYNACK:
        if (id == 0u || !s->server_settings) return SOLARIS_EIO;
        event->kind = SOLARIS_SESSION_READY; event->status = length == 0u ? SOLARIS_OK : SOLARIS_EACCESS; break;
    case SERVER_SETTINGS:
        if (id != 0u || s->server_settings || !version2(data, length)) return SOLARIS_EIO;
        s->server_settings = 1; break;
    case UPDATE_PADDING: {
        if (id != 0u) return SOLARIS_EIO;
        solaris_anytls_policy_t policy;
        rc = solaris_anytls_policy_parse(data, length, &policy);
        if (rc == SOLARIS_OK) s->client->policy = policy;
        break;
    }
    case HEART_REQUEST: {
        if (length != 0u || !s->server_settings) return SOLARIS_EIO;
        uint8_t response[7]; frame(response, HEART_RESPONSE, id, 0u); rc = pad(s, response, sizeof(response), &event->reply); break;
    }
    case HEART_RESPONSE: if (length != 0u || !s->server_settings) return SOLARIS_EIO; break;
    case ALERT:
        if (id != 0u) return SOLARIS_EIO;
        if (s->client->diagnostic.report != NULL)
            s->client->diagnostic.report(s->client->diagnostic.context, "anytls", SOLARIS_EACCESS, data, length > 1024u ? 1024u : length);
        return SOLARIS_EACCESS;
    default: return SOLARIS_EIO;
    }
    if (rc == SOLARIS_OK) *used = 7u + length;
    return rc;
}
static void destroy(void *state) { solaris_memory_free(state); }
const solaris_session_codec_t solaris_anytls_session_codec = {65542u, create, start, open_stream, write_stream, end_stream, decode, destroy};
