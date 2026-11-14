#include "codec/http/proxy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                                                                       \
    do {                                                                                                               \
        if (!(x)) {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                                    \
            abort();                                                                                                   \
        }                                                                                                              \
    } while (0)
static solaris_budget_t *budget;
static void invalid(const char *header)
{
    solaris_http_metadata_t meta;
    solaris_buffer_t *output;
    solaris_http_request_t *request;
    CHECK(solaris_http_request_create(budget, (const uint8_t *)header, strlen(header), 32768, &meta, &output,
                                      &request) != SOLARIS_OK);
    CHECK(!request && !output);
}
static void body(const char *header, const char *wire, const char *expected, int valid)
{
    size_t n = strlen(wire);
    for (size_t step = 1; step <= n + 1; ++step) {
        solaris_http_metadata_t meta;
        solaris_buffer_t *output;
        solaris_http_request_t *request;
        CHECK(solaris_http_request_create(budget, (const uint8_t *)header, strlen(header), 32768, &meta, &output,
                                          &request) == SOLARIS_OK);
        solaris_buffer_release(output);
        uint8_t result[1024];
        size_t length = 0, offset = 0;
        solaris_status_t rc = SOLARIS_OK;
        while (!solaris_http_request_complete(request) && offset < n && rc == SOLARIS_OK) {
            size_t count = n - offset;
            if (count > step)
                count = step;
            size_t used;
            rc = solaris_http_request_body(request, (const uint8_t *)wire + offset, count, &used, &output);
            if (output) {
                CHECK(length + solaris_buffer_length(output) <= sizeof(result));
                memcpy(result + length, solaris_buffer_data(output), solaris_buffer_length(output));
                length += solaris_buffer_length(output);
                solaris_buffer_release(output);
            }
            offset += used;
            if (rc == SOLARIS_OK)
                CHECK(used || solaris_http_request_complete(request));
        }
        if (valid)
            CHECK(rc == SOLARIS_OK && solaris_http_request_complete(request) && length == strlen(expected) &&
                  !memcmp(result, expected, length));
        else
            CHECK(rc != SOLARIS_OK || solaris_http_request_eof(request) != SOLARIS_OK);
        solaris_http_request_destroy(request);
    }
}
static void upgrade_response(const char *wire, int valid, int state, const char *suffix)
{
    size_t n = strlen(wire);
    for (size_t step = 1; step <= n + 1; ++step) {
        solaris_http_upgrade_response_t *response;
        CHECK(solaris_http_upgrade_response_create(budget, 32768, &response) == SOLARIS_OK);
        uint8_t collected[2048];
        size_t total = 0;
        solaris_status_t rc = SOLARIS_OK;
        for (size_t offset = 0; offset < n && rc == SOLARIS_OK;) {
            size_t count = n - offset;
            if (count > step)
                count = step;
            solaris_buffer_t *output = NULL;
            rc = solaris_http_upgrade_response_feed(response, (const uint8_t *)wire + offset, count, &output);
            if (output) {
                size_t length = solaris_buffer_length(output);
                CHECK(total + length < sizeof(collected));
                memcpy(collected + total, solaris_buffer_data(output), length);
                total += length;
                solaris_buffer_release(output);
            }
            offset += count;
        }
        if (valid) {
            CHECK(rc == SOLARIS_OK && solaris_http_upgrade_response_state(response) == state);
            CHECK(solaris_http_upgrade_response_eof(response) == SOLARIS_OK);
            size_t length = strlen(suffix);
            CHECK(total >= length && !memcmp(collected + total - length, suffix, length));
        } else
            CHECK(rc != SOLARIS_OK || solaris_http_upgrade_response_eof(response) != SOLARIS_OK);
        solaris_http_upgrade_response_destroy(response);
    }
}
static void websocket(void)
{
    const char *header = "GET ws://example.com/chat HTTP/1.1\r\nHost: example.com\r\n"
                         "Connection: keep-alive, Upgrade, X-Remove\r\nUpgrade: WebSocket\r\n"
                         "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
                         "Sec-WebSocket-Extensions: permessage-deflate\r\nSec-WebSocket-Protocol: chat\r\n"
                         "Proxy-Authorization: Basic dXNlcjpwYXNz\r\nX-Remove: secret\r\nContent-Length: 0\r\n\r\n";
    solaris_http_metadata_t meta;
    solaris_http_request_t *request;
    solaris_buffer_t *output;
    CHECK(solaris_http_request_create(budget, (const uint8_t *)header, strlen(header), 32768, &meta, &output,
                                      &request) == SOLARIS_OK);
    CHECK(meta.websocket && !meta.connect && meta.credentials && meta.destination.port == 80);
    char text[2048];
    size_t length = solaris_buffer_length(output);
    CHECK(length < sizeof(text));
    memcpy(text, solaris_buffer_data(output), length);
    text[length] = 0;
    CHECK(strstr(text, "GET /chat HTTP/1.1") && strstr(text, "Connection: Upgrade\r\nUpgrade: websocket"));
    CHECK(strstr(text, "Sec-WebSocket-Extensions:permessage-deflate") && strstr(text, "Sec-WebSocket-Protocol:chat"));
    CHECK(!strstr(text, "Proxy-Authorization") && !strstr(text, "X-Remove") && !strstr(text, "Content-Length"));
    solaris_http_credentials_clear(&meta);
    solaris_buffer_release(output);
    solaris_http_request_destroy(request);
    const char *accepted = "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n"
                           "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n"
                           "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\nFRAME";
    upgrade_response(accepted, 1, SOLARIS_HTTP_UPGRADE_ACCEPTED, "\r\n\r\nFRAME");
    upgrade_response("HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\nno!PIPELINED", 1,
                     SOLARIS_HTTP_UPGRADE_REJECTED, "\r\n\r\nno!");
    upgrade_response("HTTP/1.1 403 Forbidden\r\n\r\nclosed body", 1, SOLARIS_HTTP_UPGRADE_REJECTED, "closed body");
    upgrade_response("HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\nx", 0, 0, "");
    upgrade_response("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", 0, 0, "");
    upgrade_response("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nContent-Length: "
                     "0\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
                     0, 0, "");
    upgrade_response("HTTP/1.1 103 Early Hints\r\n\r\n", 0, 0, "");
}
int main(void)
{
    CHECK(solaris_budget_create(1024 * 1024, NULL, &budget) == SOLARIS_OK);
    const char *invalid_headers[] = {
        "GET / HTTP/1.1\r\n\r\n",
        "GET / HTTP/2.0\r\nHost: example.com\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nHost: a\r\n\r\n",
        "GET http://a/ HTTP/1.1\r\nHost: b\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
        "GET / HTTP/1.1\r\nHost : a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nConnection: Host\r\n\r\n",
        "CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\nContent-Length: 0\r\n\r\n",
        "CONNECT a HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET http://user@a/ HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET http://a:0/ HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET http://a:65536/ HTTP/1.1\r\nHost: a\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: [a]:80\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nUpgrade: websocket\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic dTo=\r\nProxy-Authorization: Basic dTo=\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: a\r\nProxy-Authorization: Basic dTp=\r\n\r\n",
        "GET / HTTP/1.1\nHost: a\n\r\n\r\n"};
    for (size_t i = 0; i < sizeof(invalid_headers) / sizeof(*invalid_headers); ++i)
        invalid(invalid_headers[i]);
    char many[4096] = "GET / HTTP/1.1\r\nHost: example.com\r\n";
    size_t used = strlen(many);
    CHECK(used + 700 * 5 + 3 <= sizeof(many));
    for (unsigned i = 0; i < 700; ++i) {
        memcpy(many + used, "X:y\r\n", 5);
        used += 5;
    }
    memcpy(many + used, "\r\n", 3);
    invalid(many);
    const char *chunked =
        "POST http://example.com/a HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\n\r\n";
    const char *content = "3;x=1\r\nabc\r\n2\r\nde\r\n0\r\nX-Test: value\r\n\r\n";
    char pipeline[200];
    snprintf(pipeline, sizeof(pipeline), "%sGET /private HTTP/1.1\r\nHost: secret\r\n\r\n", content);
    body(chunked, pipeline, content, 1);
    body(chunked, "3\r\nabc\r\n0\r\nProxy-Authorization: leaked\r\n\r\n", "", 0);
    body(chunked, "3\r\nabc\r\n0\r\nHost: evil\r\n\r\n", "", 0);
    body(chunked, "3\r\nab", "", 0);
    body("POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 3\r\n\r\n", "abcGET / HTTP/1.1\r\n\r\n", "abc", 1);
    body("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "GET /other HTTP/1.1\r\n\r\n", "", 1);
    websocket();
    CHECK(!solaris_budget_used(budget));
    solaris_budget_release(budget);
    puts("HTTP strict framing: header ambiguity, credentials, split chunk trailers, pipeline and truncation passed");
    return 0;
}
