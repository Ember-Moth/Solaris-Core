/* Public-SDK-only process driven by independent Python socket peers. */
#include <solaris/core.h>
#include <stdatomic.h>
#include <stdio.h>
#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#include <stdlib.h>
#include <string.h>
#define CHECK(x)                                                                                             \
    do                                                                                                       \
    {                                                                                                        \
        if (!(x))                                                                                            \
        {                                                                                                    \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x);                                          \
            abort();                                                                                         \
        }                                                                                                    \
    } while (0)
typedef struct completion
{
    solaris_status_t status;
    solaris_prepared_config_t *prepared;
    uint64_t revision;
    atomic_int done;
} completion_t;
static void prepared(void *context, solaris_status_t status, solaris_prepared_config_t *result,
                     const solaris_error_t *error)
{
    completion_t *c = context;
    (void)error;
    c->status = status;
    c->prepared = result;
    atomic_store_explicit(&c->done, 1, memory_order_release);
}
static void committed(void *context, solaris_status_t status, uint64_t revision, const solaris_error_t *error)
{
    completion_t *c = context;
    (void)error;
    c->status = status;
    c->revision = revision;
    atomic_store_explicit(&c->done, 1, memory_order_release);
}
typedef struct control_completion
{
    solaris_status_t status;
    solaris_control_result_t result;
    uint64_t matched;
    atomic_int done;
} control_completion_t;
typedef struct probe_completion
{
    solaris_probe_result_t result;
    atomic_int done;
} probe_completion_t;
static void controlled(void *context, solaris_status_t status, const solaris_control_result_t *result,
                       const solaris_error_t *error)
{
    control_completion_t *c = context;
    (void)error;
    c->status = status;
    c->result = *result;
    atomic_store_explicit(&c->done, 1, memory_order_release);
}
static void connections_closed(void *context, solaris_status_t status, uint64_t matched,
                               const solaris_error_t *error)
{
    control_completion_t *c = context;
    (void)error;
    c->status = status;
    c->matched = matched;
    atomic_store_explicit(&c->done, 1, memory_order_release);
}
static void probed(void *context, const solaris_probe_result_t *result)
{
    probe_completion_t *c = context;
    c->result = *result;
    atomic_store_explicit(&c->done, 1, memory_order_release);
}
static void quote(const char *text)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
    {
        if (*p == '"' || *p == '\\')
        {
            putchar('\\');
            putchar(*p);
        }
        else if (*p < 32)
            printf("\\u%04x", *p);
        else
            putchar(*p);
    }
    putchar('"');
}
static void listener(const solaris_config_listener_info_t *info)
{
    printf("{\"id\":%llu,\"port\":%u,\"worker\":%u,\"protocol\":%u,\"udp\":%u,"
           "\"auth\":%u,\"name\":",
           (unsigned long long)info->id, info->port, info->worker_id, info->protocol, info->udp_enabled,
           info->authentication_required);
    quote(info->name);
    printf(",\"address\":");
    quote(info->address);
    printf(",\"configured_port\":%u,\"requested_port\":%u,\"overridden\":%u}", info->configured_port,
           info->requested_port, info->binding_overridden);
}
static unsigned read32(const unsigned char *p)
{
    return (unsigned)p[0] << 24 | (unsigned)p[1] << 16 | (unsigned)p[2] << 8 | p[3];
}
static uint64_t read64(const unsigned char *p) { return (uint64_t)read32(p) << 32 | read32(p + 4); }
static void endpoint(const solaris_endpoint_t *p)
{
    printf("{\"host\":");
    quote(p->host);
    printf(",\"port\":%u}", p->port);
}
static void connection(const solaris_connection_info_t *p)
{
    printf("{\"id\":%llu,\"generation\":%llu,\"revision\":%llu,\"selection\":%llu,"
           "\"inbound\":%llu,\"rule\":%llu,\"node\":%llu,\"worker\":%u,"
           "\"kind\":%u,\"purpose\":%u,\"state\":%u,\"status\":%d,"
           "\"read\":%llu,\"written\":%llu,\"packets_read\":%llu,\"packets_written\":%llu,"
           "\"pending_bytes\":%zu,\"pending_requests\":%zu,\"channels\":%zu,\"source\":",
           (unsigned long long)p->key.id, (unsigned long long)p->key.generation,
           (unsigned long long)p->config_revision, (unsigned long long)p->selection_revision,
           (unsigned long long)p->inbound_id, (unsigned long long)p->rule_index,
           (unsigned long long)p->node_id, p->worker_id, p->kind, p->purpose, p->state, p->status,
           (unsigned long long)p->bytes_read, (unsigned long long)p->bytes_written,
           (unsigned long long)p->packets_read, (unsigned long long)p->packets_written, p->pending_bytes,
           p->pending_requests, p->active_channels);
    endpoint(&p->source);
    printf(",\"target\":");
    endpoint(&p->logical_target);
    printf(",\"dial\":");
    endpoint(&p->dial_target);
    printf("}");
}
/* Optional private acceptance harness extensions. The ordinary and installed
 * SDK consumer leave both macros undefined and use only public headers/APIs. */
#ifndef SOLARIS_RUNTIME_DRIVER_CREATE
#define SOLARIS_RUNTIME_DRIVER_CREATE solaris_engine_create
#endif
#ifndef SOLARIS_RUNTIME_DRIVER_COMMAND
#define SOLARIS_RUNTIME_DRIVER_COMMAND(engine, kind, payload, length) 0
#endif
int main(void)
{
#ifdef _WIN32
    /* Length-prefixed frames must preserve LF and Ctrl-Z on Windows pipes. */
    CHECK(_setmode(_fileno(stdin), _O_BINARY) != -1);
    CHECK(_setmode(_fileno(stdout), _O_BINARY) != -1);
#endif
    solaris_engine_t *engine = NULL;
    solaris_prepared_config_t *handles[16] = {0};
    void *trust = NULL;
    size_t trust_length = 0;
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.io_workers = 2;
    options.io_resource_limit = 8192;
    options.buffer_limit_bytes = 64u * 1024u * 1024u;
    CHECK(SOLARIS_RUNTIME_DRIVER_CREATE(&options, NULL, &engine, NULL) == SOLARIS_OK);
    uint64_t id;
    uint64_t probe_id = 0;
    probe_completion_t probe = {0};
    atomic_init(&probe.done, 0);
    solaris_control_snapshot_t *held_control = NULL;
    solaris_connection_list_t *held_connections = NULL;
    solaris_log_snapshot_t *held_logs = NULL;
    CHECK(solaris_engine_start(engine, &id, NULL) == SOLARIS_OK);
    CHECK(solaris_engine_flush(engine, 10000, NULL) == SOLARIS_OK);
    printf("{\"ready\":true}\n");
    fflush(stdout);
    for (;;)
    {
        unsigned char header[5];
        if (!fread(header, 1, sizeof(header), stdin))
            break;
        unsigned length = read32(header + 1);
        CHECK(length <= 2u * 1024u * 1024u);
        unsigned char *payload = calloc((size_t)length + 1, 1);
        CHECK(payload);
        CHECK(fread(payload, 1, length, stdin) == length);
        unsigned slot = length ? payload[0] : 0;
        solaris_status_t status = SOLARIS_OK;
        if (SOLARIS_RUNTIME_DRIVER_COMMAND(engine, header[0], payload, length))
        {
        }
        else if (header[0] == 'P')
        {
            CHECK(length >= 2 && slot < 16 && !handles[slot]);
            solaris_config_t *image = NULL;
            solaris_diagnostics_t *diagnostics = NULL;
            solaris_config_options_t compile;
            solaris_config_options_init(&compile);
            compile.source_name = "runtime-integration.conf";
            status =
                solaris_config_compile_bytes(payload + 2, length - 2, &compile, &image, &diagnostics, NULL);
            solaris_diagnostics_release(diagnostics);
            completion_t completion = {0};
            atomic_init(&completion.done, 0);
            if (status == SOLARIS_OK)
            {
                solaris_config_snapshot_t snapshot;
                CHECK(solaris_config_get_snapshot(image, &snapshot) == SOLARIS_OK);
                solaris_config_bind_override_t *bindings =
                    calloc(snapshot.listener_count + 1, sizeof(*bindings));
                CHECK(bindings);
                if (payload[1])
                    for (size_t i = 0; i < snapshot.listener_count; ++i)
                    {
                        solaris_config_listener_info_t info;
                        CHECK(solaris_config_get_listener(image, i, &info) == SOLARIS_OK);
                        bindings[i].listener_id = info.id;
                        bindings[i].port = 0;
                    }
                solaris_config_prepare_options_t prepare_options;
                solaris_config_prepare_options_init(&prepare_options);
                void *borrowed_trust = NULL;
                if (trust_length)
                {
                    borrowed_trust = malloc(trust_length);
                    CHECK(borrowed_trust);
                    memcpy(borrowed_trust, trust, trust_length);
                }
                prepare_options.trust_pem = borrowed_trust;
                prepare_options.trust_length = trust_length;
                prepare_options.bindings = payload[1] ? bindings : NULL;
                prepare_options.binding_count = payload[1] ? snapshot.listener_count : 0;
                status = solaris_engine_prepare_config(engine, image, &prepare_options, prepared, &completion,
                                                       &id, NULL);
                /* Input lifetime ends before the asynchronous prepare work. */
                memset(bindings, 0xff, (snapshot.listener_count + 1) * sizeof(*bindings));
                free(bindings);
                if (borrowed_trust)
                {
                    memset(borrowed_trust, 0xff, trust_length);
                    free(borrowed_trust);
                }
                solaris_config_release(image);
                if (status == SOLARIS_OK)
                {
                    CHECK(solaris_engine_flush(engine, 20000, NULL) == SOLARIS_OK);
                    CHECK(atomic_load_explicit(&completion.done, memory_order_acquire));
                    status = completion.status;
                    handles[slot] = completion.prepared;
                }
            }
            printf("{\"status\":%d,\"listeners\":[", status);
            solaris_prepared_config_snapshot_t snapshot = {0};
            if (handles[slot])
            {
                CHECK(solaris_prepared_config_get_snapshot(handles[slot], &snapshot) == SOLARIS_OK);
                for (size_t i = 0; i < snapshot.listener_count; ++i)
                {
                    solaris_config_listener_info_t info;
                    CHECK(solaris_prepared_config_get_listener(handles[slot], i, &info) == SOLARIS_OK);
                    if (i)
                        putchar(',');
                    listener(&info);
                }
            }
            printf("],\"base\":%llu}\n", (unsigned long long)snapshot.base_revision);
        }
        else if (header[0] == 'C' || header[0] == 'c')
        {
            CHECK(length == 1 && slot < 16 && handles[slot]);
            completion_t completion = {0};
            atomic_init(&completion.done, 0);
            status = solaris_engine_commit_config(engine, handles[slot], committed, &completion, &id, NULL);
            if (status == SOLARIS_OK)
            {
                if (header[0] == 'c')
                {
                    unsigned attempts = 0;
                    while (!atomic_load_explicit(&completion.done, memory_order_acquire) &&
                           attempts++ < 20000)
                    {
                        solaris_status_t wait = solaris_engine_flush(engine, 1, NULL);
                        CHECK(wait == SOLARIS_OK || wait == SOLARIS_ETIMEDOUT);
                    }
                }
                else
                    CHECK(solaris_engine_flush(engine, 20000, NULL) == SOLARIS_OK);
                CHECK(atomic_load_explicit(&completion.done, memory_order_acquire));
                status = completion.status;
            }
            printf("{\"status\":%d,\"revision\":%llu}\n", status, (unsigned long long)completion.revision);
        }
        else if (header[0] == 'Q')
        {
            solaris_active_config_snapshot_t snapshot;
            status = solaris_engine_get_config_snapshot(engine, &snapshot, NULL);
            printf("{\"status\":%d,\"revision\":%llu,\"publication\":%llu,"
                   "\"listeners\":[",
                   status, (unsigned long long)snapshot.active_revision,
                   (unsigned long long)snapshot.publication_revision);
            for (size_t i = 0; status == SOLARIS_OK && i < snapshot.listener_count; ++i)
            {
                solaris_config_listener_info_t info;
                CHECK(solaris_engine_get_bound_listener(engine, snapshot.active_revision, i, &info, NULL) ==
                      SOLARIS_OK);
                if (i)
                    putchar(',');
                listener(&info);
            }
            printf("]}\n");
        }
        else if (header[0] == 'M' || header[0] == 'X')
        {
            CHECK(length == (header[0] == 'M' ? 12u : 24u));
            control_completion_t c = {0};
            atomic_init(&c.done, 0);
            if (header[0] == 'M')
                status = solaris_engine_set_mode(engine, read64(payload), read32(payload + 8), controlled, &c,
                                                 &id, NULL);
            else
                status = solaris_engine_select(engine, read64(payload), read64(payload + 8),
                                               read64(payload + 16), controlled, &c, &id, NULL);
            if (status == SOLARIS_OK)
            {
                CHECK(solaris_engine_flush(engine, 20000, NULL) == SOLARIS_OK);
                CHECK(atomic_load_explicit(&c.done, memory_order_acquire));
                status = c.status;
            }
            printf("{\"status\":%d,\"revision\":%llu,\"selection\":%llu,\"mode\":%u,\"group\":%llu,\"node\":%"
                   "llu}\n",
                   status, (unsigned long long)c.result.config_revision,
                   (unsigned long long)c.result.selection_revision, c.result.mode,
                   (unsigned long long)c.result.group_id, (unsigned long long)c.result.selected_id);
        }
        else if (header[0] == 'G')
        {
            solaris_control_snapshot_release(held_control);
            held_control = NULL;
            status = solaris_engine_get_control_snapshot(engine, &held_control, NULL);
            solaris_control_info_t info = {0};
            if (status == SOLARIS_OK)
                CHECK(solaris_control_snapshot_get_info(held_control, &info) == SOLARIS_OK);
            printf("{\"status\":%d,\"revision\":%llu,\"selection\":%llu,\"generation\":%llu,\"mode\":%u,"
                   "\"nodes\":[",
                   status, (unsigned long long)info.config_revision,
                   (unsigned long long)info.selection_revision, (unsigned long long)info.runtime_generation,
                   info.mode);
            for (size_t i = 0; i < info.node_count; ++i)
            {
                solaris_config_node_info_t node;
                CHECK(solaris_control_snapshot_get_node(held_control, i, &node) == SOLARIS_OK);
                if (i)
                    putchar(',');
                printf("{\"id\":%llu,\"udp\":%u,\"name\":", (unsigned long long)node.id, node.udp_enabled);
                quote(node.name);
                printf(",\"type\":");
                quote(node.type);
                putchar('}');
            }
            printf("],\"groups\":[");
            for (size_t i = 0; i < info.group_count; ++i)
            {
                solaris_group_info_t group;
                CHECK(solaris_control_snapshot_get_group(held_control, i, &group) == SOLARIS_OK);
                if (i)
                    putchar(',');
                printf("{\"id\":%llu,\"selected\":%llu,\"previous\":%llu,\"reason_revision\":%llu,\"reason\":"
                       "%u,\"name\":",
                       (unsigned long long)group.id, (unsigned long long)group.selected_id,
                       (unsigned long long)group.previous_selected_id,
                       (unsigned long long)group.reason_revision, group.selection_reason);
                quote(group.name);
                printf(",\"members\":[");
                for (size_t j = 0; j < group.member_count; ++j)
                {
                    uint64_t member;
                    CHECK(solaris_control_snapshot_get_group_member(held_control, i, j, &member) ==
                          SOLARIS_OK);
                    if (j)
                        putchar(',');
                    printf("%llu", (unsigned long long)member);
                }
                printf("]}");
            }
            printf("]}\n");
        }
        else if (header[0] == 'L')
        {
            solaris_connection_list_release(held_connections);
            held_connections = NULL;
            status = solaris_engine_get_connections(engine, length && payload[0], &held_connections, NULL);
            printf("{\"status\":%d,\"connections\":[", status);
            size_t count = solaris_connection_list_count(held_connections);
            for (size_t i = 0; i < count; ++i)
            {
                solaris_connection_info_t info;
                CHECK(solaris_connection_list_get(held_connections, i, &info) == SOLARIS_OK);
                if (i)
                    putchar(',');
                connection(&info);
            }
            printf("]}\n");
        }
        else if (header[0] == 'I')
        {
            CHECK(length == 16);
            solaris_connection_id_t key = {read64(payload), read64(payload + 8)};
            solaris_connection_info_t info = {0};
            status = solaris_engine_get_connection(engine, &key, &info, NULL);
            printf("{\"status\":%d,\"connection\":", status);
            connection(&info);
            printf("}\n");
        }
        else if (header[0] == 'D')
        {
            CHECK(length == 0 || length == 16);
            control_completion_t c = {0};
            atomic_init(&c.done, 0);
            if (length)
            {
                solaris_connection_id_t key = {read64(payload), read64(payload + 8)};
                status = solaris_engine_close_connection(engine, &key, connections_closed, &c, &id, NULL);
            }
            else
                status = solaris_engine_close_connections(engine, connections_closed, &c, &id, NULL);
            if (status == SOLARIS_OK)
            {
                CHECK(solaris_engine_flush(engine, 20000, NULL) == SOLARIS_OK);
                CHECK(atomic_load_explicit(&c.done, memory_order_acquire));
                status = c.status;
            }
            printf("{\"status\":%d,\"matched\":%llu}\n", status, (unsigned long long)c.matched);
        }
        else if (header[0] == 'F')
        {
            solaris_traffic_info_t info = {0};
            status = solaris_engine_get_traffic(engine, &info, NULL);
            printf("{\"status\":%d,\"logical\":[", status);
            for (unsigned i = 0; i < SOLARIS_FLOW_PURPOSE_COUNT; ++i)
            {
                const solaris_logical_traffic_t *p = &info.logical[i];
                if (i)
                    putchar(',');
                printf("{\"created\":%llu,\"opened\":%llu,\"closed\":%llu,\"active\":%llu,"
                       "\"read\":%llu,\"written\":%llu,\"packets_read\":%llu,\"packets_written\":%llu}",
                       (unsigned long long)p->created, (unsigned long long)p->opened,
                       (unsigned long long)p->closed, (unsigned long long)p->active,
                       (unsigned long long)p->bytes_read, (unsigned long long)p->bytes_written,
                       (unsigned long long)p->packets_read, (unsigned long long)p->packets_written);
            }
            printf("],\"physical\":{\"stream_read\":%llu,\"stream_written\":%llu,\"datagram_read\":%llu,"
                   "\"datagram_written\":%llu},\"sampled\":%llu}\n",
                   (unsigned long long)info.physical.stream_read,
                   (unsigned long long)info.physical.stream_written,
                   (unsigned long long)info.physical.datagram_read,
                   (unsigned long long)info.physical.datagram_written, (unsigned long long)info.sampled_ns);
        }
        else if (header[0] == 'B')
        {
            CHECK(length > 24);
            CHECK(!probe_id || atomic_load_explicit(&probe.done, memory_order_acquire));
            memset(&probe.result, 0, sizeof(probe.result));
            atomic_store_explicit(&probe.done, 0, memory_order_release);
            solaris_probe_options_t p;
            solaris_probe_options_init(&p);
            p.config_revision = read64(payload);
            p.target_id = read64(payload + 8);
            p.timeout_ms = read64(payload + 16);
            p.url = (const char *)payload + 24;
            void *copy = NULL;
            if (trust_length)
            {
                copy = malloc(trust_length);
                CHECK(copy);
                memcpy(copy, trust, trust_length);
            }
            p.trust_pem = copy;
            p.trust_length = trust_length;
            status = solaris_engine_probe(engine, &p, probed, &probe, &probe_id, NULL);
            if (copy)
            {
                memset(copy, 0xff, trust_length);
                free(copy);
            }
            memset(payload, 0xff, length);
            printf("{\"status\":%d,\"operation\":%llu}\n", status, (unsigned long long)probe_id);
        }
        else if (header[0] == 'H')
        {
            CHECK(probe_id);
            CHECK(solaris_engine_flush(engine, 20000, NULL) == SOLARIS_OK);
            CHECK(atomic_load_explicit(&probe.done, memory_order_acquire));
            const solaris_probe_result_t *p = &probe.result;
            printf("{\"status\":%d,\"http\":%u,\"revision\":%llu,\"selection\":%llu,\"node\":%llu,"
                   "\"connection\":%llu,"
                   "\"duration\":%llu,\"read\":%llu,\"written\":%llu}\n",
                   p->status, p->http_status, (unsigned long long)p->config_revision,
                   (unsigned long long)p->selection_revision, (unsigned long long)p->node_id,
                   (unsigned long long)p->connection_id, (unsigned long long)p->duration_ns,
                   (unsigned long long)p->bytes_read, (unsigned long long)p->bytes_written);
        }
        else if (header[0] == 'K')
        {
            CHECK(length == 8);
            status = solaris_engine_cancel(engine, read64(payload), NULL);
            printf("{\"status\":%d}\n", status);
        }
        else if (header[0] == 'J')
        {
            CHECK(length == 12);
            solaris_log_snapshot_release(held_logs);
            held_logs = NULL;
            status = solaris_engine_get_logs(engine, read64(payload), read32(payload + 8), &held_logs, NULL);
            solaris_log_info_t info = {0};
            if (status == SOLARIS_OK)
                CHECK(solaris_log_snapshot_get_info(held_logs, &info) == SOLARIS_OK);
            printf("{\"status\":%d,\"cursor\":%llu,\"oldest\":%llu,\"latest\":%llu,\"overwritten\":%llu,"
                   "\"dropped\":%llu,\"missed\":%llu,\"records\":[",
                   status, (unsigned long long)info.cursor, (unsigned long long)info.oldest_sequence,
                   (unsigned long long)info.latest_sequence, (unsigned long long)info.overwritten,
                   (unsigned long long)info.dropped, (unsigned long long)info.missed);
            for (size_t i = 0; i < info.count; ++i)
            {
                solaris_log_record_t r;
                CHECK(solaris_log_snapshot_get_record(held_logs, i, &r) == SOLARIS_OK);
                if (i)
                    putchar(',');
                printf("{\"sequence\":%llu,\"event\":%u,\"status\":%d,\"component\":",
                       (unsigned long long)r.sequence, r.event, r.status);
                quote(r.component);
                putchar('}');
            }
            printf("]}\n");
        }
        else if (header[0] == 'R')
        {
            CHECK(length == 1 && slot < 16);
            solaris_prepared_config_release(handles[slot]);
            handles[slot] = NULL;
            printf("{\"status\":0}\n");
        }
        else if (header[0] == 'Y')
        {
            free(trust);
            trust = payload;
            trust_length = length;
            payload = NULL;
            printf("{\"status\":0}\n");
        }
        else if (header[0] == 'S' || header[0] == 'N')
        {
            status = header[0] == 'S' ? solaris_engine_stop(engine, &id, NULL)
                                      : solaris_engine_start(engine, &id, NULL);
            if (status == SOLARIS_OK)
                CHECK(solaris_engine_flush(engine, 20000, NULL) == SOLARIS_OK);
            printf("{\"status\":%d}\n", status);
        }
        else if (header[0] == 'T')
        {
            CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
            engine = NULL;
            if (held_control)
            {
                solaris_control_info_t info;
                CHECK(solaris_control_snapshot_get_info(held_control, &info) == SOLARIS_OK);
            }
            if (held_connections && solaris_connection_list_count(held_connections))
            {
                solaris_connection_info_t info;
                CHECK(solaris_connection_list_get(held_connections, 0, &info) == SOLARIS_OK);
            }
            if (held_logs)
            {
                solaris_log_info_t info;
                CHECK(solaris_log_snapshot_get_info(held_logs, &info) == SOLARIS_OK);
            }
            for (unsigned i = 0; i < 16; ++i)
                if (handles[i])
                {
                    solaris_prepared_config_snapshot_t snapshot;
                    CHECK(solaris_prepared_config_get_snapshot(handles[i], &snapshot) == SOLARIS_OK);
                    CHECK(snapshot.state == SOLARIS_PREPARED_COMMITTED ||
                          snapshot.state == SOLARIS_PREPARED_CLOSED);
                    solaris_prepared_config_release(handles[i]);
                    handles[i] = NULL;
                }
            free(payload);
            printf("{\"status\":0}\n");
            fflush(stdout);
            break;
        }
        else
            CHECK(0);
        free(payload);
        fflush(stdout);
    }
    if (engine)
        CHECK(solaris_engine_destroy(engine, NULL) == SOLARIS_OK);
    for (unsigned i = 0; i < 16; ++i)
        solaris_prepared_config_release(handles[i]);
    solaris_control_snapshot_release(held_control);
    solaris_connection_list_release(held_connections);
    solaris_log_snapshot_release(held_logs);
    free(trust);
    return 0;
}
