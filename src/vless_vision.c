/*
 * Wire-compatible implementation of XTLS Vision at Xray-core
 * b17a88f9b46d. This file is licensed under MPL-2.0.
 */

#include "vless/vision.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/rand.h>

#define VISION_UUID_LEN 16u
#define VISION_HEADER_LEN 5u
#define VISION_INITIAL_HEADER_LEN (VISION_UUID_LEN + VISION_HEADER_LEN)
#define VISION_RESHAPE_LIMIT (8192u - VISION_INITIAL_HEADER_LEN)
#define VISION_TLS_FILTER_PACKETS 8u
#define VISION_TLS_RECORD_LIMIT (16384u + 256u + 5u)

typedef enum vision_decode_mode {
    VISION_DECODE_INITIAL = 0,
    VISION_DECODE_HEADER,
    VISION_DECODE_CONTENT,
    VISION_DECODE_PADDING,
    VISION_DECODE_PASSTHROUGH,
    VISION_DECODE_DIRECT,
} vision_decode_mode_t;

struct vless_vision {
    uint8_t uuid[VISION_UUID_LEN];
    uint8_t initial_header[VISION_INITIAL_HEADER_LEN];
    uint8_t padding_header[VISION_HEADER_LEN];
    size_t initial_header_len;
    size_t padding_header_len;
    size_t remaining_content;
    size_t remaining_padding;
    uint8_t current_command;
    vision_decode_mode_t decode_mode;
    int allow_direct;
    int write_uuid;
    int padding_writes;
    int direct_write;
    int direct_read;

    unsigned int filter_packets;
    int is_tls;
    int is_tls12_or_above;
    int enable_xtls;
    size_t server_hello_expected;
    aproxy_buffer_t server_hello;
    aproxy_buffer_t incoming_probe;
};

static int random_bounded(uint32_t upper, uint32_t *out)
{
    if (upper == 0u || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    const uint32_t limit = UINT32_MAX - (UINT32_MAX % upper);
    uint32_t value = 0u;
    do {
        if (RAND_bytes((uint8_t *)&value, sizeof(value)) != 1) {
            return APROXY_ERR_CRYPTO;
        }
    } while (value >= limit);
    *out = value % upper;
    return APROXY_OK;
}

static const uint8_t *find_bytes(const uint8_t *haystack,
                                 size_t haystack_len,
                                 const uint8_t *needle,
                                 size_t needle_len)
{
    if (needle_len == 0u) {
        return haystack;
    }
    if (haystack == NULL || needle == NULL || haystack_len < needle_len) {
        return NULL;
    }
    const size_t last = haystack_len - needle_len;
    for (size_t i = 0u; i <= last; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return NULL;
}

static size_t find_last_application_record(const uint8_t *input, size_t len)
{
    static const uint8_t marker[3] = {23u, 3u, 3u};
    if (len < sizeof(marker)) {
        return SIZE_MAX;
    }
    for (size_t i = len - sizeof(marker) + 1u; i > 0u; i--) {
        const size_t offset = i - 1u;
        if (memcmp(input + offset, marker, sizeof(marker)) == 0) {
            return offset;
        }
    }
    return SIZE_MAX;
}

static int cipher_allows_xtls(uint16_t cipher)
{
    switch (cipher) {
    case 0x1301u:
    case 0x1302u:
    case 0x1303u:
    case 0x1304u:
        return 1;
    default:
        return 0;
    }
}

static void inspect_server_hello(vless_vision_t *vision)
{
    static const uint8_t tls13_version[] = {
        0x00u, 0x2bu, 0x00u, 0x02u, 0x03u, 0x04u,
    };
    if (vision->server_hello.len >= 46u) {
        const size_t session_id_len = vision->server_hello.data[43];
        const size_t cipher_offset = 44u + session_id_len;
        if (session_id_len <= 32u &&
            cipher_offset + 2u <= vision->server_hello.len &&
            cipher_offset + 2u <= vision->server_hello_expected) {
            const uint16_t cipher =
                ((uint16_t)vision->server_hello.data[cipher_offset] << 8u) |
                vision->server_hello.data[cipher_offset + 1u];
            if (find_bytes(vision->server_hello.data,
                           vision->server_hello.len, tls13_version,
                           sizeof(tls13_version)) != NULL) {
                vision->enable_xtls = cipher_allows_xtls(cipher);
                vision->filter_packets = 0u;
                return;
            }
        }
    }
    if (vision->server_hello.len >= vision->server_hello_expected) {
        vision->filter_packets = 0u;
    }
}

static int filter_tls(vless_vision_t *vision,
                      const uint8_t *input,
                      size_t len,
                      int incoming)
{
    if (vision->filter_packets == 0u || len == 0u) {
        return APROXY_OK;
    }
    if (incoming && vision->server_hello_expected == 0u &&
        (vision->incoming_probe.len > 0u || len < 7u)) {
        int rc = aproxy_buffer_append(&vision->incoming_probe, input, len);
        if (rc != APROXY_OK) {
            return rc;
        }
        if (vision->incoming_probe.len < 7u) {
            return APROXY_OK;
        }
        input = vision->incoming_probe.data;
        len = vision->incoming_probe.len;
    }
    if (vision->server_hello_expected == 0u) {
        vision->filter_packets--;
    }
    int starts_server_hello = 0;
    if (len > 6u && input[0] == 22u && input[1] == 3u) {
        if (input[2] == 3u && input[5] == 2u) {
            const size_t expected =
                (((size_t)input[3] << 8u) | input[4]) + 5u;
            vision->is_tls = 1;
            vision->is_tls12_or_above = 1;
            if (expected <= VISION_TLS_RECORD_LIMIT) {
                aproxy_buffer_clear(&vision->server_hello);
                vision->server_hello_expected = expected;
                starts_server_hello = 1;
            } else {
                vision->filter_packets = 0u;
            }
        } else if (input[5] == 1u) {
            vision->is_tls = 1;
        }
    }
    if (starts_server_hello ||
        (vision->server_hello_expected > vision->server_hello.len &&
         vision->server_hello_expected > 0u)) {
        size_t append_len = len;
        if (append_len >
            vision->server_hello_expected - vision->server_hello.len) {
            append_len =
                vision->server_hello_expected - vision->server_hello.len;
        }
        const int rc = aproxy_buffer_append(&vision->server_hello, input,
                                            append_len);
        if (rc != APROXY_OK) {
            return rc;
        }
        inspect_server_hello(vision);
    }
    if (incoming && vision->incoming_probe.len > 0u) {
        aproxy_buffer_clear(&vision->incoming_probe);
    }
    return APROXY_OK;
}

int vless_vision_new(const uint8_t uuid[16],
                     int allow_direct,
                     vless_vision_t **out)
{
    if (uuid == NULL || out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    vless_vision_t *vision =
        (vless_vision_t *)calloc(1u, sizeof(*vision));
    if (vision == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    memcpy(vision->uuid, uuid, sizeof(vision->uuid));
    vision->allow_direct = allow_direct != 0;
    vision->write_uuid = 1;
    vision->padding_writes = 1;
    vision->filter_packets = VISION_TLS_FILTER_PACKETS;
    vision->decode_mode = VISION_DECODE_INITIAL;
    aproxy_buffer_init(&vision->server_hello);
    aproxy_buffer_init(&vision->incoming_probe);
    *out = vision;
    return APROXY_OK;
}

void vless_vision_free(vless_vision_t *vision)
{
    if (vision == NULL) {
        return;
    }
    aproxy_buffer_free(&vision->server_hello);
    aproxy_buffer_free(&vision->incoming_probe);
    memset(vision, 0, sizeof(*vision));
    free(vision);
}

static int append_padded_block(vless_vision_t *vision,
                               const uint8_t *content,
                               size_t content_len,
                               uint8_t command,
                               aproxy_buffer_t *output)
{
    if (content_len > UINT16_MAX || command > VLESS_VISION_COMMAND_DIRECT) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    uint32_t random_part = 0u;
    int rc;
    size_t padding_len;
    if (content_len < 900u && vision->is_tls) {
        rc = random_bounded(500u, &random_part);
        padding_len = 900u - content_len + random_part;
    } else {
        rc = random_bounded(256u, &random_part);
        padding_len = random_part;
    }
    if (rc != APROXY_OK) {
        return rc;
    }
    const size_t header_len = vision->write_uuid
                                  ? VISION_INITIAL_HEADER_LEN
                                  : VISION_HEADER_LEN;
    if (output->len > SIZE_MAX - header_len - content_len - padding_len) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    const size_t start = output->len;
    rc = aproxy_buffer_reserve(output, start + header_len + content_len +
                                           padding_len);
    if (rc != APROXY_OK) {
        return rc;
    }
    uint8_t *position = output->data + start;
    if (vision->write_uuid) {
        memcpy(position, vision->uuid, sizeof(vision->uuid));
        position += sizeof(vision->uuid);
        vision->write_uuid = 0;
    }
    position[0] = command;
    position[1] = (uint8_t)(content_len >> 8u);
    position[2] = (uint8_t)content_len;
    position[3] = (uint8_t)(padding_len >> 8u);
    position[4] = (uint8_t)padding_len;
    position += VISION_HEADER_LEN;
    if (content_len > 0u) {
        memcpy(position, content, content_len);
        position += content_len;
    }
    memset(position, 0, padding_len);
    output->len += header_len + content_len + padding_len;
    return APROXY_OK;
}

static int encode_block(vless_vision_t *vision,
                        const uint8_t *input,
                        size_t len,
                        aproxy_buffer_t *output,
                        int *direct)
{
    static const uint8_t application_marker[3] = {23u, 3u, 3u};
    uint8_t command = VLESS_VISION_COMMAND_CONTINUE;
    if (vision->is_tls && len > 6u &&
        memcmp(input, application_marker, sizeof(application_marker)) == 0) {
        command = vision->allow_direct && vision->enable_xtls
                      ? VLESS_VISION_COMMAND_DIRECT
                      : VLESS_VISION_COMMAND_END;
    } else if (!vision->is_tls12_or_above && vision->filter_packets <= 1u) {
        command = VLESS_VISION_COMMAND_END;
    }
    const int rc = append_padded_block(vision, input, len, command, output);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (command != VLESS_VISION_COMMAND_CONTINUE) {
        vision->padding_writes = 0;
    }
    if (command == VLESS_VISION_COMMAND_DIRECT) {
        vision->direct_write = 1;
        *direct = 1;
    }
    return APROXY_OK;
}

int vless_vision_encode(vless_vision_t *vision,
                        const uint8_t *input,
                        size_t input_len,
                        aproxy_buffer_t *output,
                        size_t *consumed,
                        int *switch_to_direct)
{
    if (vision == NULL || output == NULL || consumed == NULL ||
        switch_to_direct == NULL || (input == NULL && input_len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *consumed = 0u;
    *switch_to_direct = 0;
    if (input_len == 0u) {
        return APROXY_OK;
    }
    if (vision->direct_write) {
        *switch_to_direct = 1;
        return APROXY_OK;
    }
    int rc = filter_tls(vision, input, input_len, 0);
    if (rc != APROXY_OK) {
        return rc;
    }
    if (!vision->padding_writes) {
        rc = aproxy_buffer_append(output, input, input_len);
        if (rc == APROXY_OK) {
            *consumed = input_len;
        }
        return rc;
    }

    size_t first_len = input_len;
    size_t second_len = 0u;
    if (input_len >= VISION_RESHAPE_LIMIT) {
        const size_t marker = find_last_application_record(input, input_len);
        first_len = marker != SIZE_MAX && marker > 0u ? marker : 4096u;
        if (first_len > input_len) {
            first_len = input_len;
        }
        second_len = input_len - first_len;
    }
    if (first_len > UINT16_MAX || second_len > UINT16_MAX) {
        return APROXY_ERR_FRAME_TOO_LARGE;
    }
    int direct = 0;
    rc = encode_block(vision, input, first_len, output, &direct);
    if (rc != APROXY_OK) {
        return rc;
    }
    *consumed = first_len;
    if (direct) {
        *switch_to_direct = 1;
        return APROXY_OK;
    }
    if (second_len > 0u) {
        if (vision->padding_writes) {
            rc = encode_block(vision, input + first_len, second_len, output,
                              &direct);
        } else {
            rc = aproxy_buffer_append(output, input + first_len, second_len);
        }
        if (rc != APROXY_OK) {
            return rc;
        }
        *consumed = input_len;
        if (direct) {
            *switch_to_direct = 1;
        }
    }
    return APROXY_OK;
}

static int load_header(vless_vision_t *vision, const uint8_t header[5])
{
    if (header[0] > VLESS_VISION_COMMAND_DIRECT) {
        return APROXY_ERR_INVALID_FRAME;
    }
    vision->current_command = header[0];
    vision->remaining_content = ((size_t)header[1] << 8u) | header[2];
    vision->remaining_padding = ((size_t)header[3] << 8u) | header[4];
    if (vision->remaining_content > 0u) {
        vision->decode_mode = VISION_DECODE_CONTENT;
    } else if (vision->remaining_padding > 0u) {
        vision->decode_mode = VISION_DECODE_PADDING;
    } else {
        vision->decode_mode = VISION_DECODE_HEADER;
    }
    return APROXY_OK;
}

static void finish_decoded_block(vless_vision_t *vision,
                                 int *switch_to_direct)
{
    if (vision->current_command == VLESS_VISION_COMMAND_END) {
        vision->decode_mode = VISION_DECODE_PASSTHROUGH;
    } else if (vision->current_command == VLESS_VISION_COMMAND_DIRECT) {
        vision->direct_read = 1;
        vision->decode_mode = VISION_DECODE_DIRECT;
        *switch_to_direct = 1;
    } else {
        vision->decode_mode = VISION_DECODE_HEADER;
    }
}

int vless_vision_decode(vless_vision_t *vision,
                        const uint8_t *input,
                        size_t input_len,
                        aproxy_buffer_t *output,
                        int *switch_to_direct)
{
    if (vision == NULL || output == NULL || switch_to_direct == NULL ||
        (input == NULL && input_len > 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *switch_to_direct = 0;
    size_t offset = 0u;
    while (offset < input_len) {
        if (vision->decode_mode == VISION_DECODE_PASSTHROUGH ||
            vision->decode_mode == VISION_DECODE_DIRECT) {
            if (vision->decode_mode == VISION_DECODE_PASSTHROUGH) {
                const int filter_rc =
                    filter_tls(vision, input + offset, input_len - offset, 1);
                if (filter_rc != APROXY_OK) {
                    return filter_rc;
                }
            }
            const int rc = aproxy_buffer_append(output, input + offset,
                                                input_len - offset);
            if (rc == APROXY_OK) {
                offset = input_len;
            }
            return rc;
        }
        if (vision->decode_mode == VISION_DECODE_INITIAL) {
            size_t copy_len = VISION_INITIAL_HEADER_LEN -
                              vision->initial_header_len;
            if (copy_len > input_len - offset) {
                copy_len = input_len - offset;
            }
            memcpy(vision->initial_header + vision->initial_header_len,
                   input + offset, copy_len);
            vision->initial_header_len += copy_len;
            offset += copy_len;
            if (vision->initial_header_len < VISION_INITIAL_HEADER_LEN) {
                break;
            }
            if (memcmp(vision->initial_header, vision->uuid,
                       VISION_UUID_LEN) != 0) {
                vision->decode_mode = VISION_DECODE_PASSTHROUGH;
                int rc = filter_tls(vision, vision->initial_header,
                                    VISION_INITIAL_HEADER_LEN, 1);
                if (rc != APROXY_OK) {
                    return rc;
                }
                rc = aproxy_buffer_append(output, vision->initial_header,
                                          VISION_INITIAL_HEADER_LEN);
                if (rc == APROXY_OK && offset < input_len) {
                    rc = filter_tls(vision, input + offset,
                                    input_len - offset, 1);
                }
                if (rc == APROXY_OK && offset < input_len) {
                    rc = aproxy_buffer_append(output, input + offset,
                                              input_len - offset);
                }
                return rc;
            }
            const int rc = load_header(
                vision, vision->initial_header + VISION_UUID_LEN);
            if (rc != APROXY_OK) {
                return rc;
            }
            if (vision->remaining_content == 0u &&
                vision->remaining_padding == 0u) {
                finish_decoded_block(vision, switch_to_direct);
            }
            continue;
        }
        if (vision->decode_mode == VISION_DECODE_HEADER) {
            size_t copy_len = VISION_HEADER_LEN - vision->padding_header_len;
            if (copy_len > input_len - offset) {
                copy_len = input_len - offset;
            }
            memcpy(vision->padding_header + vision->padding_header_len,
                   input + offset, copy_len);
            vision->padding_header_len += copy_len;
            offset += copy_len;
            if (vision->padding_header_len < VISION_HEADER_LEN) {
                break;
            }
            vision->padding_header_len = 0u;
            const int rc = load_header(vision, vision->padding_header);
            if (rc != APROXY_OK) {
                return rc;
            }
            if (vision->remaining_content == 0u &&
                vision->remaining_padding == 0u) {
                finish_decoded_block(vision, switch_to_direct);
            }
            continue;
        }
        if (vision->decode_mode == VISION_DECODE_CONTENT) {
            size_t copy_len = vision->remaining_content;
            if (copy_len > input_len - offset) {
                copy_len = input_len - offset;
            }
            int rc = filter_tls(vision, input + offset, copy_len, 1);
            if (rc != APROXY_OK) {
                return rc;
            }
            rc = aproxy_buffer_append(output, input + offset, copy_len);
            if (rc != APROXY_OK) {
                return rc;
            }
            vision->remaining_content -= copy_len;
            offset += copy_len;
            if (vision->remaining_content == 0u) {
                if (vision->remaining_padding > 0u) {
                    vision->decode_mode = VISION_DECODE_PADDING;
                } else {
                    finish_decoded_block(vision, switch_to_direct);
                }
            }
            continue;
        }
        if (vision->decode_mode == VISION_DECODE_PADDING) {
            size_t skip = vision->remaining_padding;
            if (skip > input_len - offset) {
                skip = input_len - offset;
            }
            vision->remaining_padding -= skip;
            offset += skip;
            if (vision->remaining_padding == 0u) {
                finish_decoded_block(vision, switch_to_direct);
            }
        }
    }
    return APROXY_OK;
}

int vless_vision_direct_write(const vless_vision_t *vision)
{
    return vision != NULL && vision->direct_write;
}

int vless_vision_direct_read(const vless_vision_t *vision)
{
    return vision != NULL && vision->direct_read;
}
