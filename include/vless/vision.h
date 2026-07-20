#ifndef VLESS_VISION_H
#define VLESS_VISION_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/buffer.h"
#include "aproxy/error.h"

#define VLESS_VISION_FLOW "xtls-rprx-vision"

typedef enum vless_vision_command {
    VLESS_VISION_COMMAND_CONTINUE = 0,
    VLESS_VISION_COMMAND_END = 1,
    VLESS_VISION_COMMAND_DIRECT = 2,
} vless_vision_command_t;

typedef struct vless_vision vless_vision_t;

int vless_vision_new(const uint8_t uuid[16],
                     int allow_direct,
                     vless_vision_t **out);

void vless_vision_free(vless_vision_t *vision);

/*
 * Appends the framed portion to output. consumed is the number of input bytes
 * carried by that portion. If switch_to_direct is set, bytes after consumed
 * and all later writes must bypass the outer VLESS/TLS stack.
 */
int vless_vision_encode(vless_vision_t *vision,
                        const uint8_t *input,
                        size_t input_len,
                        aproxy_buffer_t *output,
                        size_t *consumed,
                        int *switch_to_direct);

/* Removes Vision framing from an arbitrary fragment and appends content. */
int vless_vision_decode(vless_vision_t *vision,
                        const uint8_t *input,
                        size_t input_len,
                        aproxy_buffer_t *output,
                        int *switch_to_direct);

int vless_vision_direct_write(const vless_vision_t *vision);
int vless_vision_direct_read(const vless_vision_t *vision);

#endif
