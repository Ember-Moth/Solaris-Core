#include "transport/tls/tls.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct test_case {
    solaris_executor_t *owner;
    solaris_budget_t *budget;
    solaris_tls_context_t *trust;
    solaris_scope_t parent;
    solaris_stream_t *stream;
    solaris_address_t peer;
    solaris_test_event_t done;
    const char *mode;
    uintptr_t handle;
    solaris_status_t status;
    unsigned opens, closes, policy;
    size_t selected;
} test_case_t;
static int closed_socket(test_case_t *test)
{
    if (!test->policy) return 1;
    int value = 0;
#ifdef _WIN32
    int size = (int)sizeof(value);
    return getsockopt((SOCKET)test->handle, SOL_SOCKET, SO_TYPE, (char *)&value, &size) != 0;
#else
    socklen_t size = (socklen_t)sizeof(value);
    return getsockopt((int)test->handle, SOL_SOCKET, SO_TYPE, &value, &size) != 0;
#endif
}
static solaris_status_t policy(void *context, uintptr_t handle, uint32_t family, uint32_t kind)
{
    test_case_t *test = context; CHECK(family == test->peer.family && kind == SOLARIS_SOCKET_TCP);
    test->handle = handle; ++test->policy;
    return !strcmp(test->mode, "deny") ? SOLARIS_EACCESS : SOLARIS_OK;
}
static void parent_closed(void *context)
{
    test_case_t *test = context;
    CHECK(!test->stream && !test->trust && closed_socket(test));
    CHECK(solaris_budget_used(test->budget) == 0);
    solaris_test_event_signal(&test->done);
}
static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    test_case_t *test = context; CHECK(stream == test->stream && ++test->opens == 1);
    test->status = status;
    if (status == SOLARIS_OK) {
        size_t length = 99; uint8_t result[256]; memset(result, 0xcc, sizeof(result));
        solaris_status_t rc = solaris_tls_selected_alpn(stream, NULL, 0, &length);
        if (!strcmp(test->mode, "legacy") || !strcmp(test->mode, "optional")) CHECK(rc == SOLARIS_OK && length == 0);
        else {
            CHECK(rc == SOLARIS_EMSGSIZE && length == 2);
            CHECK(solaris_tls_selected_alpn(stream, result, 1, &length) == SOLARIS_EMSGSIZE && length == 2 && result[0] == 0xcc);
        }
        CHECK(solaris_tls_selected_alpn(stream, result, sizeof(result), &length) == SOLARIS_OK);
        if (length) CHECK(length == 2 && !memcmp(result, "h2", 2) && result[2] == 0xcc);
        test->selected = length;
        CHECK(solaris_stream_close(stream) == SOLARIS_OK);
    }
}
static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{ (void)context; (void)stream; (void)buffer; CHECK(0); }
static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    test_case_t *test = context; (void)status;
    CHECK(test->stream == stream && ++test->closes == 1 && closed_socket(test));
    test->stream = NULL; solaris_scope_cancel(&test->parent);
}
static const solaris_stream_callbacks_t callbacks = {opened, data, NULL, NULL, closed};
static void start(void *context, solaris_status_t status)
{
    test_case_t *test = context; CHECK(status == SOLARIS_OK);
    CHECK(solaris_scope_init(&test->parent, test->owner, NULL, parent_closed, test) == SOLARIS_OK);
    solaris_dialer_options_t dialer; solaris_dialer_options_init(&dialer);
    dialer.parent_scope = &test->parent; dialer.prepare_socket = policy; dialer.policy_context = test;
    uint8_t *offer = malloc(1025); char *identity = malloc(16); CHECK(offer && identity);
    const uint8_t protocols[] = {2,'h','2',8,'h','t','t','p','/','1','.','1'};
    memcpy(offer, protocols, sizeof(protocols)); memcpy(identity, "localhost", 10);
    solaris_tls_open_options_t extra = {.alpn = offer, .alpn_length = sizeof(protocols),
        .require_alpn = strcmp(test->mode, "optional") != 0,
        .deadline_ns = solaris_executor_now_ns(test->owner) + UINT64_C(1000000000)};
    if (!strcmp(test->mode, "invalid_zero")) { offer[0] = 0; extra.alpn_length = 1; }
    if (!strcmp(test->mode, "invalid_truncated")) { offer[0] = 3; extra.alpn_length = 3; }
    if (!strcmp(test->mode, "invalid_oversize")) extra.alpn_length = 1025;
    if (!strcmp(test->mode, "invalid_null")) extra.alpn = NULL;
    if (!strcmp(test->mode, "invalid_required")) extra.alpn_length = 0;
    if (!strcmp(test->mode, "expired")) extra.deadline_ns = 1;
    if (!strcmp(test->mode, "parent_closed")) solaris_scope_cancel(&test->parent);
    solaris_status_t rc = !strcmp(test->mode, "legacy") ?
        solaris_tls_open(test->owner, test->trust, identity, SOLARIS_TLS_1_2, NULL, &dialer, &test->peer, &callbacks, test, &test->stream) :
        solaris_tls_open_ex(test->owner, test->trust, identity, SOLARIS_TLS_1_2, &extra, NULL, &dialer, &test->peer, &callbacks, test, &test->stream);
    memset(offer, 0, 1025); memset(identity, 0, 16); free(offer); free(identity);
    solaris_tls_context_release(test->trust); test->trust = NULL;
    if (rc != SOLARIS_OK) {
        CHECK(!test->stream); test->status = rc; solaris_scope_cancel(&test->parent);
    } else {
        size_t length = 99;
        CHECK(solaris_tls_selected_alpn(test->stream, NULL, 0, &length) == SOLARIS_EAGAIN && length == 0);
    }
}
int main(int argc, char **argv)
{
    CHECK(argc == 5); test_case_t test = {.mode = argv[4]};
    CHECK(solaris_budget_create(4u * 1024u * 1024u, NULL, &test.budget) == SOLARIS_OK);
    FILE *file = fopen(argv[3], "rb"); CHECK(file); char pem[16384];
    size_t length = fread(pem, 1, sizeof(pem), file); CHECK(feof(file) && length); fclose(file);
    CHECK(solaris_tls_context_create(test.budget, pem, length, &test.trust) == SOLARIS_OK); memset(pem, 0, length);
    CHECK(solaris_address_parse(argv[1], (uint16_t)strtoul(argv[2], NULL, 10), &test.peer) == SOLARIS_OK);
    CHECK(solaris_test_event_init(&test.done, 0) == 0);
    solaris_executor_options_t options = {.id = 0, .queue_capacity = 16, .resource_limit = 64, .budget = test.budget};
    CHECK(solaris_executor_create(&options, &test.owner) == SOLARIS_OK && solaris_executor_activate(test.owner, 1) == SOLARIS_OK);
    CHECK(solaris_executor_post(test.owner, start, &test) == SOLARIS_OK); solaris_test_event_wait(&test.done);
    CHECK(solaris_executor_quiesce(test.owner) == SOLARIS_OK && solaris_executor_destroy(test.owner) == SOLARIS_OK);
    CHECK(solaris_budget_used(test.budget) == 0); solaris_budget_release(test.budget); solaris_test_event_destroy(&test.done);
    printf("{\"status\":%d,\"opens\":%u,\"closes\":%u,\"policy\":%u,\"alpn_length\":%zu}\n",
        test.status, test.opens, test.closes, test.policy, test.selected);
    return 0;
}
