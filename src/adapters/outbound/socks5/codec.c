#include "adapters/outbound/socks5/codec.h"
#include "codec/address/socks.h"
#include <string.h>

void solaris_socks5_clear(void *memory, size_t size)
{ volatile uint8_t *bytes = memory; while (size-- != 0u) *bytes++ = 0u; }
solaris_status_t solaris_socks5_handshake_init(solaris_socks5_handshake_t *state,
    const solaris_socks5_credentials_t *credentials, uint8_t command, const solaris_address_t *target)
{
    if (state == NULL || credentials == NULL || target == NULL || (command != 1u && command != 3u) ||
        ((credentials->username_length == 0u) != (credentials->password_length == 0u))) return SOLARIS_EINVAL;
    uint8_t address[260]; size_t written;
    solaris_status_t rc = command == 3u ? solaris_socks_address_encode(target, address, sizeof(address), &written) :
        solaris_socks_address_write(target, address, sizeof(address), &written);
    if (rc != SOLARIS_OK) return rc;
    memset(state, 0, sizeof(*state)); state->credentials = *credentials; state->target = *target; state->command = command;
    return SOLARIS_OK;
}
int solaris_socks5_handshake_wants_write(const solaris_socks5_handshake_t *state)
{ return state->stage == SOLARIS_SOCKS5_GREETING || state->stage == SOLARIS_SOCKS5_AUTH_SEND || state->stage == SOLARIS_SOCKS5_REQUEST; }
solaris_status_t solaris_socks5_handshake_write(solaris_socks5_handshake_t *state, solaris_budget_t *budget, solaris_buffer_t **out)
{
    if (out == NULL || state == NULL) return SOLARIS_EINVAL;
    *out = NULL; uint8_t wire[513], next; size_t size = 0u;
    if (state->stage == SOLARIS_SOCKS5_GREETING) {
        wire[0] = 5u; wire[1] = 1u; wire[2] = state->credentials.username_length != 0u ? 2u : 0u;
        size = 3u; next = SOLARIS_SOCKS5_METHOD;
    } else if (state->stage == SOLARIS_SOCKS5_AUTH_SEND) {
        wire[size++] = 1u; wire[size++] = state->credentials.username_length;
        memcpy(wire + size, state->credentials.username, state->credentials.username_length); size += state->credentials.username_length;
        wire[size++] = state->credentials.password_length;
        memcpy(wire + size, state->credentials.password, state->credentials.password_length); size += state->credentials.password_length;
        next = SOLARIS_SOCKS5_AUTH_REPLY;
    } else if (state->stage == SOLARIS_SOCKS5_REQUEST) {
        wire[0] = 5u; wire[1] = state->command; wire[2] = 0u;
        size_t address;
        solaris_status_t rc = solaris_socks_address_encode(&state->target, wire + 3u, sizeof(wire) - 3u, &address);
        if (rc != SOLARIS_OK) return rc;
        size = address + 3u; next = SOLARIS_SOCKS5_REPLY;
    } else return SOLARIS_EBUSY;
    solaris_status_t rc = solaris_buffer_copy(budget, wire, size, out);
    solaris_socks5_clear(wire, sizeof(wire)); if (rc == SOLARIS_OK) state->stage = next; return rc;
}
/* CONNECT replies may carry an unspecified BND port. Keep that protocol
 * detail here; ordinary destination and UDP source codecs remain strict. */
static solaris_status_t bound_address(const uint8_t *data, size_t size, solaris_address_t *out, size_t *consumed)
{
    if (size < 1u) return SOLARIS_EAGAIN;
    size_t length, offset = 1u; solaris_address_t address = {0};
    if (data[0] == 1u) { address.family = SOLARIS_ADDRESS_IPV4; length = 4u; }
    else if (data[0] == 4u) { address.family = SOLARIS_ADDRESS_IPV6; length = 16u; }
    else if (data[0] == 3u) {
        if (size < 2u) return SOLARIS_EAGAIN;
        length = data[1]; offset = 2u; address.family = SOLARIS_ADDRESS_DOMAIN;
        if (length == 0u) return SOLARIS_EIO;
    } else return SOLARIS_EIO;
    if (size - offset < length + 2u) return SOLARIS_EAGAIN;
    if (address.family == SOLARIS_ADDRESS_DOMAIN) {
        if (memchr(data + offset, 0, length) != NULL) return SOLARIS_EIO;
        memcpy(address.host, data + offset, length);
    } else memcpy(address.ip, data + offset, length);
    offset += length; address.port = (uint16_t)(((uint16_t)data[offset] << 8u) | data[offset + 1u]);
    *out = address; *consumed = offset + 2u; return SOLARIS_OK;
}
solaris_status_t solaris_socks5_handshake_read(solaris_socks5_handshake_t *state,
    const uint8_t *data, size_t size, size_t *consumed)
{
    if (state == NULL || consumed == NULL || (data == NULL && size != 0u)) return SOLARIS_EINVAL;
    *consumed = 0u;
    if (state->stage == SOLARIS_SOCKS5_METHOD) {
        if (size < 2u) return SOLARIS_EAGAIN;
        if (data[0] != 5u) return SOLARIS_EIO;
        uint8_t expected = state->credentials.username_length != 0u ? 2u : 0u;
        if (data[1] != expected) return SOLARIS_EACCESS;
        state->stage = expected == 2u ? SOLARIS_SOCKS5_AUTH_SEND : SOLARIS_SOCKS5_REQUEST; *consumed = 2u; return SOLARIS_OK;
    }
    if (state->stage == SOLARIS_SOCKS5_AUTH_REPLY) {
        if (size < 2u) return SOLARIS_EAGAIN;
        if (data[0] != 1u) return SOLARIS_EIO;
        if (data[1] != 0u) return SOLARIS_EACCESS;
        state->stage = SOLARIS_SOCKS5_REQUEST; *consumed = 2u; return SOLARIS_OK;
    }
    if (state->stage != SOLARIS_SOCKS5_REPLY) return SOLARIS_EBUSY;
    if (size < 3u) return SOLARIS_EAGAIN;
    if (data[0] != 5u || data[2] != 0u) return SOLARIS_EIO;
    state->reply_code = data[1];
    if (data[1] != 0u) return data[1] == 2u ? SOLARIS_EACCESS : data[1] == 6u ? SOLARIS_ETIMEDOUT :
        data[1] == 7u || data[1] == 8u ? SOLARIS_ENOTSUP : SOLARIS_EIO;
    solaris_address_t bound; size_t address = 0u;
    solaris_status_t rc = bound_address(data + 3u, size - 3u, &bound, &address);
    if (rc != SOLARIS_OK) return rc;
    if (state->command == 3u && bound.port == 0u) return SOLARIS_EIO;
    state->bound = bound; state->stage = SOLARIS_SOCKS5_READY; *consumed = address + 3u; return SOLARIS_OK;
}
solaris_status_t solaris_socks5_packet_encode(solaris_budget_t *budget, const solaris_address_t *target,
    const solaris_slice_t *payload, solaris_buffer_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL; if (target == NULL || !solaris_slice_valid(payload)) return SOLARIS_EINVAL;
    if (payload->length > SOLARIS_SOCKS5_UDP_MAX) return SOLARIS_EMSGSIZE;
    uint8_t address[260]; size_t length;
    solaris_status_t rc = solaris_socks_address_write(target, address, sizeof(address), &length);
    if (rc != SOLARIS_OK) return rc;
    rc = solaris_buffer_allocate(budget, 3u + length + payload->length, out); if (rc != SOLARIS_OK) return rc;
    uint8_t *wire = solaris_buffer_mutable_data(*out); memset(wire, 0, 3u); memcpy(wire + 3u, address, length);
    if (payload->length != 0u) memcpy(wire + 3u + length, solaris_buffer_data(payload->buffer) + payload->offset, payload->length);
    return solaris_buffer_set_length(*out, 3u + length + payload->length);
}
solaris_status_t solaris_socks5_packet_decode(solaris_budget_t *budget, const uint8_t *data, size_t size,
    solaris_address_t *source, solaris_buffer_t **out)
{
    if (out == NULL || source == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (data == NULL || size < 3u || data[0] != 0u || data[1] != 0u) return SOLARIS_EIO;
    if (data[2] != 0u) return SOLARIS_ENOTSUP;
    solaris_address_t address; size_t length;
    solaris_status_t rc = solaris_socks_address_read(data + 3u, size - 3u, &address, &length);
    if (rc != SOLARIS_OK) return SOLARIS_EIO;
    size_t payload = size - 3u - length;
    if (payload > SOLARIS_SOCKS5_UDP_MAX) return SOLARIS_EMSGSIZE;
    rc = solaris_buffer_copy(budget, data + 3u + length, payload, out);
    if (rc == SOLARIS_OK) *source = address;
    return rc;
}
