#include "support/runtime/files.h"
#include "contracts/module/module.h"
#include "support/runtime/event.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
#define COUNT 4u
typedef struct recovery_test {
    solaris_executor_t *owner;
    solaris_module_config_t *config;
    solaris_datagram_t *channel;
    solaris_address_t target;
    solaris_deadline_t *next;
    solaris_test_event_t ready, done;
    unsigned int opened, closed, received, completed, sent, worker, waiting;
    uint16_t mapping;
} recovery_test_t;
static void send_next(recovery_test_t *test);
static void sent(void *context, solaris_status_t status)
{ recovery_test_t *test = context; CHECK(status == SOLARIS_OK); test->completed++; }
static void timer(void *context, solaris_status_t status)
{
    recovery_test_t *test = context; test->next = NULL;
    CHECK(status == SOLARIS_OK); send_next(test);
}
static void opened(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    recovery_test_t *test = context;
    CHECK(channel == test->channel && status == SOLARIS_OK && ++test->opened == 1u); send_next(test);
}
static void packet(void *context, solaris_datagram_t *channel, const solaris_address_t *source, const solaris_buffer_t *buffer)
{
    recovery_test_t *test = context;
    CHECK(channel == test->channel && solaris_address_equal(source, &test->target));
    CHECK(solaris_buffer_length(buffer) == 18u);
    const uint8_t *bytes = solaris_buffer_data(buffer);
    uint16_t port = (uint16_t)(((uint16_t)bytes[0] << 8u) | bytes[1]);
    CHECK(port != 0u);
    if (test->received == 0u) test->mapping = port;
    CHECK(port == test->mapping && bytes[2] == test->worker && bytes[3] == test->received);
    for (size_t i = 4u; i < 18u; ++i) CHECK(bytes[i] == (uint8_t)(i + test->received));
    test->received++;
    if (test->received == COUNT) { CHECK(solaris_datagram_close(channel) == SOLARIS_OK); return; }
    /* The loopback TCP bridge drops this carrier after delivering the reply.
     * The next packet is new application data, never a retransmitted packet. */
    CHECK(solaris_deadline_start(test->owner, 350u, timer, test, &test->next) == SOLARIS_OK);
}
static void writable(void *context, solaris_datagram_t *channel)
{
    recovery_test_t *test = context; CHECK(channel == test->channel);
    if (test->waiting) send_next(test);
}
static void closed(void *context, solaris_datagram_t *channel, solaris_status_t status)
{
    recovery_test_t *test = context;
    CHECK(channel == test->channel && status == SOLARIS_OK && ++test->closed == 1u);
    CHECK(test->received == COUNT && test->sent == COUNT && test->completed == COUNT && test->next == NULL);
    solaris_io_snapshot_t stats; CHECK(solaris_datagram_get_snapshot(channel, &stats) == SOLARIS_OK);
    CHECK(stats.packets_read == COUNT && stats.packets_written == COUNT && stats.bytes_read == 18u * COUNT &&
        stats.bytes_written == 16u * COUNT && stats.pending_requests == 0u && stats.pending_bytes == 0u);
    printf("worker=%u stable-udp-source=%u packets=%u opens=%u closes=%u\n", test->worker, test->mapping,
        test->received, test->opened, test->closed);
    solaris_test_event_signal(&test->done);
}
static const solaris_datagram_callbacks_t callbacks = {opened, packet, writable, closed};
static void send_next(recovery_test_t *test)
{
    uint8_t bytes[16]; bytes[0] = (uint8_t)test->worker; bytes[1] = (uint8_t)test->sent;
    for (size_t i = 2u; i < sizeof(bytes); ++i) bytes[i] = (uint8_t)(i + 2u + test->sent);
    solaris_buffer_t *buffer; CHECK(solaris_buffer_copy(solaris_executor_budget(test->owner), bytes, sizeof(bytes), &buffer) == SOLARIS_OK);
    solaris_slice_t slice = {buffer, 0u, sizeof(bytes)};
    solaris_status_t rc = solaris_datagram_send(test->channel, &test->target, &slice, sent, test);
    solaris_buffer_release(buffer);
    CHECK(rc == SOLARIS_OK || rc == SOLARIS_EAGAIN);
    test->waiting = rc == SOLARIS_EAGAIN;
    if (rc == SOLARIS_OK) test->sent++;
}
static void start(void *context, solaris_status_t status)
{
    recovery_test_t *test = context; CHECK(status == SOLARIS_OK);
    solaris_module_services_t services = {.owner = test->owner}; solaris_module_instance_t *instance;
    CHECK(solaris_module_create(test->config, &services, NULL, NULL, &instance, NULL) == SOLARIS_OK);
    solaris_dial_plan_t plan; CHECK(solaris_module_plan_acquire(instance, 1u, &plan) == SOLARIS_OK);
    CHECK(solaris_outbound_open_datagram(plan.outbound, SOLARIS_ADDRESS_IPV4, &callbacks, test, &test->channel) == SOLARIS_OK);
    CHECK(solaris_dial_plan_release(&plan) == SOLARIS_OK);
    CHECK(solaris_module_retire(instance) == SOLARIS_OK);
    solaris_test_event_signal(&test->ready);
}
static solaris_config_field_t text(const char *name, const char *value)
{
    solaris_config_field_t f = {.name = name, .value = {.kind = SOLARIS_CONFIG_STRING}};
    f.value.value.string.data = value; f.value.value.string.length = strlen(value); return f;
}
static solaris_config_field_t number(const char *name, int64_t value)
{ solaris_config_field_t f = {.name = name, .value = {.kind = SOLARIS_CONFIG_INTEGER}}; f.value.value.integer = value; return f; }
int main(int argc, char **argv)
{
    CHECK(argc == 7); /* carrier port, UDP target port, CA or -, encryption, flow or -, worker */
    solaris_budget_t *budget; CHECK(solaris_budget_create(16u * 1024u * 1024u, NULL, &budget) == SOLARIS_OK);
    solaris_registry_t *registry; CHECK(solaris_builtin_registry_create(budget, &registry, NULL) == SOLARIS_OK);
    solaris_config_field_t fields[12]; size_t count = 0u; char pem[16384];
    fields[count++] = text("server", "127.0.0.1"); fields[count++] = number("port", atoi(argv[1]));
    fields[count++] = text("uuid", "7b4bb031-41b5-4d1d-b062-1ea0cab957c1");
    fields[count++] = number("pending-requests", 1u); fields[count++] = number("open-timeout-ms", 3000u);
    fields[count++] = text("encryption", argv[4]);
    if (strcmp(argv[5], "-") != 0) fields[count++] = text("flow", argv[5]);
    if (strcmp(argv[3], "-") != 0) {
        FILE *file = solaris_test_fopen(argv[3], "rb"); CHECK(file != NULL);
        size_t size = fread(pem, 1u, sizeof(pem) - 1u, file); fclose(file); CHECK(size > 0u); pem[size] = '\0';
        fields[count++] = (solaris_config_field_t){.name = "tls", .value = {.kind = SOLARIS_CONFIG_BOOL, .value.boolean = 1}};
        fields[count++] = text("servername", "localhost"); fields[count++] = text("ca-pem", pem);
    }
    solaris_config_view_t view = {.kind = SOLARIS_CONFIG_MAP, .value.map = {.fields = fields, .count = count}};
    recovery_test_t test = {.worker = (unsigned int)atoi(argv[6])};
    solaris_error_t error;
    solaris_status_t rc = solaris_registry_compile(registry, "vless", &view, &test.config, &error);
    if (rc != SOLARIS_OK) fprintf(stderr, "compile status=%d\n", rc);
    CHECK(rc == SOLARIS_OK); solaris_registry_destroy(registry);
    CHECK(solaris_address_parse("127.0.0.1", (uint16_t)atoi(argv[2]), &test.target) == SOLARIS_OK);
    CHECK(solaris_test_event_init(&test.ready, 0u) == 0 && solaris_test_event_init(&test.done, 0u) == 0);
    solaris_executor_options_t options = {.id = test.worker, .queue_capacity = 16u, .resource_limit = 128u, .budget = budget};
    CHECK(solaris_executor_create(&options, &test.owner) == SOLARIS_OK);
    CHECK(solaris_executor_activate(test.owner, 1u) == SOLARIS_OK && solaris_executor_post(test.owner, start, &test) == SOLARIS_OK);
    solaris_test_event_wait(&test.ready); solaris_module_config_release(test.config);
    solaris_test_event_wait(&test.done);
    CHECK(solaris_executor_quiesce(test.owner) == SOLARIS_OK && solaris_executor_destroy(test.owner) == SOLARIS_OK);
    solaris_test_event_destroy(&test.ready); solaris_test_event_destroy(&test.done);
    CHECK(solaris_budget_used(budget) == 0u); solaris_budget_release(budget); return 0;
}
