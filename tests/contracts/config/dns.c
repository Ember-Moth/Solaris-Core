#include "contracts/config/dns.h"
#include "config/image/internal.h"
#include <solaris/core.h>
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
#define DIRECT "[General]\nconfig-version=1\nmode=direct\n"
static const char sample[] =
    DIRECT "[Host]\napi.test = 127.0.0.2, ::1\nalias.test = api.test\n"
           "[DNS]\nenabled=true\nipv6=true\nipv6-wait-ms=75\nuse-hosts=false\nuse-system-hosts=false\n"
           "upstream = 127.0.0.1:5353, tcp://[::1]:5354\nproxy-upstream=udp://127.0.0.3:5355\n"
           "direct-upstream=tcp://127.0.0.4:5356\nbootstrap-upstream=127.0.0.5\n";
static solaris_config_t *valid(const char *text) {
    solaris_config_t *image = NULL;
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_error_t error;
    solaris_status_t status = solaris_config_compile_bytes(text, strlen(text), NULL, &image, &diagnostics, &error);
    if (status != SOLARIS_OK)
        fprintf(stderr, "compile: %d %s\n", status, error.message);
    CHECK(status == SOLARIS_OK && image);
    solaris_diagnostics_release(diagnostics);
    return image;
}
static void invalid(const char *text, solaris_status_t expected) {
    solaris_config_t *image = (void *)1;
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_error_t error;
    solaris_status_t status = solaris_config_compile_bytes(text, strlen(text), NULL, &image, &diagnostics, &error);
    CHECK(status == expected && !image && error.code == status);
    CHECK(!strstr(error.message, "synthetic-secret"));
    CHECK(solaris_diagnostics_count(diagnostics) > 0);
    for (size_t i = 0; i < solaris_diagnostics_count(diagnostics); ++i) {
        solaris_config_diagnostic_t item;
        CHECK(solaris_diagnostics_get(diagnostics, i, &item) == SOLARIS_OK);
        CHECK(item.line > 0 && item.column > 0 && !strstr(item.message, "synthetic-secret"));
    }
    solaris_diagnostics_release(diagnostics);
}
typedef struct allocation {
    size_t calls, fail, live;
} allocation_t;
static void *allocate(void *context, size_t size) {
    allocation_t *a = context;
    if (++a->calls == a->fail)
        return NULL;
    void *p = malloc(size);
    if (p)
        ++a->live;
    return p;
}
static void deallocate(void *context, void *pointer) {
    allocation_t *a = context;
    CHECK(a->live);
    --a->live;
    free(pointer);
}
static size_t allocation_case(size_t failure) {
    allocation_t a = {.fail = failure};
    solaris_runtime_services_t services;
    solaris_runtime_services_init(&services);
    services.context = &a;
    services.allocate = allocate;
    services.deallocate = deallocate;
    solaris_config_t *image = NULL;
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_error_t error;
    solaris_status_t status =
        solaris_config_compile_bytes_services(sample, strlen(sample), NULL, &services, &image, &diagnostics, &error);
    if (!failure)
        CHECK(status == SOLARIS_OK && image);
    else
        CHECK(status != SOLARIS_OK && !image);
    solaris_config_release(image);
    solaris_diagnostics_release(diagnostics);
    CHECK(!a.live);
    return a.calls;
}
int main(void) {
    solaris_config_t *image = valid(DIRECT);
    CHECK(!solaris_config_dns(image));
    solaris_config_release(image);
    image = valid(DIRECT "[DNS]\n[Host]\n");
    const solaris_config_dns_t *dns = solaris_config_dns(image);
    CHECK(dns && !dns->enabled && dns->use_hosts && dns->use_system_hosts && dns->ipv6_wait_ms == 100);
    CHECK(!dns->host_count && !dns->upstream_count[0]);
    solaris_config_release(image);
    char input[sizeof(sample)];
    memcpy(input, sample, sizeof(sample));
    image = valid(input);
    memset(input, 'X', sizeof(input));
    dns = solaris_config_dns(image);
    CHECK(dns->enabled && dns->ipv6 && !dns->use_hosts && !dns->use_system_hosts && dns->ipv6_wait_ms == 75);
    CHECK(dns->host_count == 2 && dns->upstream_count[SOLARIS_DNS_ROUTE_TARGET - 1] == 2);
    CHECK(dns->upstreams[0][0].address.port == 5353 && dns->upstreams[0][1].address.family == SOLARIS_ADDRESS_IPV6);
    CHECK(dns->upstreams[SOLARIS_DNS_PROXY_SERVER - 1][0].address.port == 5355);
    CHECK(dns->upstreams[SOLARIS_DNS_DIRECT_TARGET - 1][0].transport == SOLARIS_DNS_TRANSPORT_TCP);
    CHECK(dns->upstreams[SOLARIS_DNS_BOOTSTRAP - 1][0].address.port == 53);
    solaris_hosts_result_t result;
    CHECK(solaris_hosts_lookup(dns->validated_hosts, "ALIAS.TEST.", 0, &result) == SOLARIS_OK &&
          result.address_count == 2);
    solaris_config_release(image);
    image = valid(DIRECT "[Host]\nexternal.test=other.test\n");
    CHECK(solaris_hosts_lookup(solaris_config_dns(image)->validated_hosts, "external.test", 0, &result) == SOLARIS_OK);
    CHECK(result.kind == SOLARIS_HOSTS_ALIAS && !strcmp(result.terminal_name, "other.test"));
    solaris_config_release(image);
    const char *unsupported[] = {DIRECT
                                 "[DNS]\nenabled=true\nupstream=https://user:synthetic-secret@example.test/dns-query\n",
                                 DIRECT "[DNS]\nupstream=dns.example.test\n",
                                 DIRECT "[DNS]\nlisten=127.0.0.1:53\n",
                                 DIRECT "[DNS]\nmode=fake-ip\n",
                                 DIRECT "[DNS]\ncache-algorithm=arc\n",
                                 DIRECT "[DNS]\ncache-size=128\n",
                                 DIRECT "[DNS]\npolicy=example.test\n",
                                 DIRECT "[DNS]\nmode=redir-host\n"};
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(*unsupported); ++i)
        invalid(unsupported[i], SOLARIS_ENOTSUP);
    const char *bad[] = {DIRECT "[DNS]\nenabled=true\n",
                         DIRECT "[Host]\na.test=b.test\nb.test=a.test\n",
                         DIRECT "[Host]\na.test=alias.test,127.0.0.1\n",
                         DIRECT "[DNS]\nipv6-wait-ms=-1\n",
                         DIRECT "[DNS]\nipv6-wait-ms=0x10\n",
                         DIRECT "[DNS]\nenabled=1\n"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); ++i)
        invalid(bad[i], SOLARIS_EINVAL);
    image = valid(DIRECT "[Host]\ninternal.test=lan\n");
    CHECK(solaris_hosts_lookup(solaris_config_dns(image)->validated_hosts, "internal.test", 0, &result) == SOLARIS_OK);
    CHECK(result.kind == SOLARIS_HOSTS_ALIAS && !strcmp(result.terminal_name, "lan"));
    solaris_config_release(image);
    size_t calls = allocation_case(0);
    for (size_t i = 1; i <= calls; ++i)
        (void)allocation_case(i);
    printf("DNS image: owned roles/hosts, exact supported subset, failures and %zu allocation points passed\n", calls);
    return 0;
}
