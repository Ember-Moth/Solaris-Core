#ifndef SOLARIS_HTTP_PROXY_CODEC_H
#define SOLARIS_HTTP_PROXY_CODEC_H
#include "contracts/io/address.h"
#include "contracts/io/buffer.h"
typedef struct solaris_http_request solaris_http_request_t;
typedef struct solaris_http_metadata {
    solaris_address_t destination;
    int connect, credentials, websocket;
    uint8_t username[256], password[256];
    size_t username_length, password_length;
} solaris_http_metadata_t;
/* Header bytes include the final CRLFCRLF and no body. All output is owned. */
solaris_status_t solaris_http_request_create(solaris_budget_t *budget, const uint8_t *data, size_t length, size_t limit,
                                             solaris_http_metadata_t *metadata, solaris_buffer_t **header,
                                             solaris_http_request_t **out);
/* Validates raw body framing, stops at the first message, and withholds trailers
 * until validated. Output may be NULL. consumed excludes a pipelined message. */
solaris_status_t solaris_http_request_body(solaris_http_request_t *request, const uint8_t *data, size_t length,
                                           size_t *consumed, solaris_buffer_t **out);
int solaris_http_request_complete(const solaris_http_request_t *request);
solaris_status_t solaris_http_request_eof(solaris_http_request_t *request);
void solaris_http_request_destroy(solaris_http_request_t *request);
void solaris_http_credentials_clear(solaris_http_metadata_t *metadata);
/* Upgrade responses are bounded across informational headers. Rejections retain
 * HTTP body framing; accepted responses include any coalesced tunnel bytes.
 * The caller switches to raw I/O only after the accepted output drains. */
typedef struct solaris_http_upgrade_response solaris_http_upgrade_response_t;
enum { SOLARIS_HTTP_UPGRADE_PENDING, SOLARIS_HTTP_UPGRADE_ACCEPTED, SOLARIS_HTTP_UPGRADE_REJECTED };
solaris_status_t solaris_http_upgrade_response_create(solaris_budget_t *budget, size_t limit,
                                                      solaris_http_upgrade_response_t **out);
solaris_status_t solaris_http_upgrade_response_feed(solaris_http_upgrade_response_t *response, const uint8_t *data,
                                                    size_t length, solaris_buffer_t **out);
int solaris_http_upgrade_response_state(const solaris_http_upgrade_response_t *response);
int solaris_http_upgrade_response_complete(const solaris_http_upgrade_response_t *response);
solaris_status_t solaris_http_upgrade_response_eof(solaris_http_upgrade_response_t *response);
void solaris_http_upgrade_response_destroy(solaris_http_upgrade_response_t *response);
#endif
