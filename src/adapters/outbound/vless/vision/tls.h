#ifndef SOLARIS_VLESS_VISION_TLS_H
#define SOLARIS_VLESS_VISION_TLS_H

#include <stddef.h>
#include <stdint.h>

typedef struct solaris_vless_tls_records {
    uint8_t header[5];
    size_t header_size, remaining, record_length;
    unsigned int application_records;
    uint8_t last_type;
    int invalid, tls;
} solaris_vless_tls_records_t;
/* The largest syntactically valid ServerHello fits its uint16 extension block
 * plus fixed fields. This bounded capture is owned by the Vision channel. */
typedef struct solaris_vless_tls_hello {
    uint8_t bytes[65792];
    size_t used, expected;
    unsigned int retries;
    uint16_t cipher;
    int done, tls13;
} solaris_vless_tls_hello_t;

void solaris_vless_tls_observe(solaris_vless_tls_records_t *records,
    solaris_vless_tls_hello_t *server_hello, const uint8_t *data, size_t size);
int solaris_vless_tls_application_boundary(const solaris_vless_tls_records_t *records);

#endif
