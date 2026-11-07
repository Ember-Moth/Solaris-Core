/* A small embedding host using only installed Solaris public headers and C11.
 * Commands run on the host thread; callbacks only copy results. The host keeps
 * every callback context alive until flush/destroy has completed. */
#include <solaris/core.h>
#include <errno.h>
#include <inttypes.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct host {
    solaris_engine_t *engine;
    solaris_event_t event;
    atomic_uint_fast64_t completed;
    void *trust;
    size_t trust_length;
    char *configuration;
    int ephemeral;
} host_t;
typedef struct completion {
    atomic_int done;
    solaris_status_t status;
    solaris_error_t error;
    solaris_prepared_config_t *prepared;
    uint64_t revision, matched;
    solaris_probe_result_t probe;
} completion_t;
static void quote(const char *text)
{
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') {
            putchar('\\');
            putchar(*p);
        } else if (*p < 32)
            printf("\\u%04x", *p);
        else
            putchar(*p);
    }
    putchar('"');
}
static void response(const char *command, solaris_status_t status, const char *message)
{
    printf("{\"command\":");
    quote(command);
    printf(",\"status\":%d", (int)status);
    if (message && *message) {
        printf(",\"message\":");
        quote(message);
    }
    puts("}");
    fflush(stdout);
}
static char *copy_string(const char *text)
{
    size_t length = strlen(text) + 1;
    char *copy = malloc(length);
    if (copy)
        memcpy(copy, text, length);
    return copy;
}
static FILE *open_file(const char *path)
{
    FILE *file = NULL;
#ifdef _MSC_VER
    if (fopen_s(&file, path, "rb"))
        return NULL;
#else
    file = fopen(path, "rb");
#endif
    return file;
}
static int number(const char *text, uint64_t *out)
{
    if (!text || !*text || *text == '-')
        return 0;
    errno = 0;
    char *end;
    unsigned long long value = strtoull(text, &end, 10);
    if (errno || *end)
        return 0;
    *out = (uint64_t)value;
    return 1;
}
static void event(void *context, const solaris_event_t *result)
{
    host_t *host = context;
    host->event = *result;
    atomic_store_explicit(&host->completed, result->operation_id, memory_order_release);
}
static void done(completion_t *completion, solaris_status_t status, const solaris_error_t *error)
{
    completion->status = status;
    if (error)
        completion->error = *error;
    atomic_store_explicit(&completion->done, 1, memory_order_release);
}
static void prepared(void *context, solaris_status_t status, solaris_prepared_config_t *prepared,
                     const solaris_error_t *error)
{
    completion_t *c = context;
    c->prepared = prepared;
    done(c, status, error);
}
static void committed(void *context, solaris_status_t status, uint64_t revision, const solaris_error_t *error)
{
    completion_t *c = context;
    c->revision = revision;
    done(c, status, error);
}
static void controlled(void *context, solaris_status_t status, const solaris_control_result_t *result,
                       const solaris_error_t *error)
{
    completion_t *c = context;
    c->revision = result ? result->selection_revision : 0;
    done(c, status, error);
}
static void closed(void *context, solaris_status_t status, uint64_t matched, const solaris_error_t *error)
{
    completion_t *c = context;
    c->matched = matched;
    done(c, status, error);
}
static void probed(void *context, const solaris_probe_result_t *result)
{
    completion_t *c = context;
    c->probe = *result;
    done(c, result->status, NULL);
}
static void completion_init(completion_t *completion)
{
    memset(completion, 0, sizeof(*completion));
    atomic_init(&completion->done, 0);
}
static solaris_status_t wait_operation(host_t *host, solaris_status_t accepted, uint64_t operation,
                                       completion_t *completion)
{
    if (accepted != SOLARIS_OK)
        return accepted;
    solaris_status_t rc = solaris_engine_flush(host->engine, 30000, NULL);
    if (rc == SOLARIS_ETIMEDOUT) {
        (void)solaris_engine_cancel(host->engine, operation, NULL);
        /* A timeout cannot release the callback context. Drain the accepted
         * operation and report its actual final outcome, including publication. */
        rc = solaris_engine_flush(host->engine, SOLARIS_TIMEOUT_INFINITE, NULL);
    }
    if (rc != SOLARIS_OK) {
        /* Never return with stack callback storage still in use. */
        if (solaris_engine_destroy(host->engine, NULL) != SOLARIS_OK)
            abort();
        host->engine = NULL;
        return rc;
    }
    if (atomic_load_explicit(&host->completed, memory_order_acquire) != operation)
        return SOLARIS_EIO;
    if (completion) {
        if (!atomic_load_explicit(&completion->done, memory_order_acquire))
            return SOLARIS_EIO;
        return completion->status;
    }
    return host->event.status;
}
static solaris_status_t compile_file(const char *path, solaris_config_t **image, solaris_error_t *error)
{
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_status_t rc = solaris_config_compile_file(path, NULL, image, &diagnostics, error);
    for (size_t i = 0; i < solaris_diagnostics_count(diagnostics); ++i) {
        solaris_config_diagnostic_t item;
        if (solaris_diagnostics_get(diagnostics, i, &item) == SOLARIS_OK)
            fprintf(stderr, "%s:%u:%u %s: %s\n", item.source, item.line, item.column, item.path, item.message);
    }
    solaris_diagnostics_release(diagnostics);
    return rc;
}
static void print_listener(const solaris_config_listener_info_t *listener)
{
    printf("{\"name\":");
    quote(listener->name);
    printf(",\"address\":");
    quote(listener->address);
    printf(",\"port\":%u,\"id\":%" PRIu64 ",\"protocol\":%u,\"udp\":%u,\"worker\":%u,"
           "\"configured_port\":%u,\"requested_port\":%u,\"overridden\":%u}",
           (unsigned)listener->port, listener->id, listener->protocol, listener->udp_enabled, listener->worker_id,
           (unsigned)listener->configured_port, (unsigned)listener->requested_port, listener->binding_overridden);
}
static void status(host_t *host, const char *command)
{
    solaris_engine_snapshot_t runtime;
    solaris_active_config_snapshot_t active;
    solaris_status_t rc = solaris_engine_get_snapshot(host->engine, &runtime, NULL);
    if (rc == SOLARIS_OK)
        rc = solaris_engine_get_config_snapshot(host->engine, &active, NULL);
    if (rc != SOLARIS_OK) {
        response(command, rc, NULL);
        return;
    }
    printf("{\"command\":");
    quote(command);
    printf(",\"status\":0,\"state\":%u,\"generation\":%" PRIu64 ",\"revision\":%" PRIu64 ",\"publication\":%" PRIu64
           ",\"listeners\":[",
           runtime.state, runtime.generation, active.active_revision, active.publication_revision);
    for (size_t i = 0; i < active.listener_count; ++i) {
        solaris_config_listener_info_t listener;
        if (solaris_engine_get_bound_listener(host->engine, active.active_revision, i, &listener, NULL) != SOLARIS_OK)
            break;
        if (i)
            putchar(',');
        print_listener(&listener);
    }
    puts("]}");
    fflush(stdout);
}
static solaris_status_t activate(host_t *host, solaris_config_t *image, solaris_error_t *error)
{
    solaris_config_snapshot_t info;
    solaris_status_t rc = solaris_config_get_snapshot(image, &info);
    if (rc != SOLARIS_OK)
        return rc;
    solaris_config_bind_override_t *bindings = NULL;
    if (host->ephemeral && info.listener_count) {
        bindings = calloc(info.listener_count, sizeof(*bindings));
        if (!bindings)
            return SOLARIS_ENOMEM;
        for (size_t i = 0; i < info.listener_count; ++i) {
            solaris_config_listener_info_t listener;
            rc = solaris_config_get_listener(image, i, &listener);
            if (rc != SOLARIS_OK) {
                free(bindings);
                return rc;
            }
            bindings[i].listener_id = listener.id;
            bindings[i].port = 0;
        }
    }
    solaris_config_prepare_options_t options;
    solaris_config_prepare_options_init(&options);
    options.trust_pem = host->trust;
    options.trust_length = host->trust_length;
    options.bindings = bindings;
    options.binding_count = bindings ? info.listener_count : 0;
    completion_t completion;
    completion_init(&completion);
    uint64_t operation = 0;
    rc = solaris_engine_prepare_config(host->engine, image, &options, prepared, &completion, &operation, error);
    free(bindings);
    rc = wait_operation(host, rc, operation, &completion);
    if (rc != SOLARIS_OK) {
        if (completion.error.code)
            *error = completion.error;
        solaris_prepared_config_release(completion.prepared);
        return rc;
    }
    solaris_prepared_config_t *candidate = completion.prepared;
    completion_init(&completion);
    rc = solaris_engine_commit_config(host->engine, candidate, committed, &completion, &operation, error);
    rc = wait_operation(host, rc, operation, &completion);
    solaris_prepared_config_release(candidate);
    if (rc != SOLARIS_OK && completion.error.code)
        *error = completion.error;
    return rc;
}
static solaris_status_t load(host_t *host, const char *path, solaris_error_t *error)
{
    solaris_config_t *image = NULL;
    solaris_status_t rc = compile_file(path, &image, error);
    if (rc != SOLARIS_OK)
        return rc;
    char *saved = copy_string(path);
    if (!saved) {
        solaris_config_release(image);
        return SOLARIS_ENOMEM;
    }
    rc = activate(host, image, error);
    solaris_config_release(image);
    if (rc == SOLARIS_OK) {
        free(host->configuration);
        host->configuration = saved;
    } else
        free(saved);
    return rc;
}
static uint64_t node_id(solaris_control_snapshot_t *snapshot, const solaris_control_info_t *info, const char *name)
{
    for (size_t i = 0; i < info->node_count; ++i) {
        solaris_config_node_info_t node;
        if (solaris_control_snapshot_get_node(snapshot, i, &node) == SOLARIS_OK && !strcmp(node.name, name))
            return node.id;
    }
    return 0;
}
static uint64_t group_id(solaris_control_snapshot_t *snapshot, const solaris_control_info_t *info, const char *name)
{
    for (size_t i = 0; i < info->group_count; ++i) {
        solaris_group_info_t group;
        if (solaris_control_snapshot_get_group(snapshot, i, &group) == SOLARIS_OK && !strcmp(group.name, name))
            return group.id;
    }
    return 0;
}
static void controls(host_t *host)
{
    solaris_control_snapshot_t *snapshot = NULL;
    solaris_control_info_t info;
    solaris_status_t rc = solaris_engine_get_control_snapshot(host->engine, &snapshot, NULL);
    if (rc == SOLARIS_OK)
        rc = solaris_control_snapshot_get_info(snapshot, &info);
    if (rc != SOLARIS_OK) {
        solaris_control_snapshot_release(snapshot);
        response("nodes", rc, NULL);
        return;
    }
    printf("{\"command\":\"nodes\",\"status\":0,\"revision\":%" PRIu64 ",\"selection\":%" PRIu64
           ",\"mode\":%u,\"nodes\":[",
           info.config_revision, info.selection_revision, info.mode);
    for (size_t i = 0; i < info.node_count; ++i) {
        solaris_config_node_info_t node;
        (void)solaris_control_snapshot_get_node(snapshot, i, &node);
        if (i)
            putchar(',');
        printf("{\"id\":%" PRIu64 ",\"name\":", node.id);
        quote(node.name);
        printf(",\"type\":");
        quote(node.type);
        putchar('}');
    }
    printf("],\"groups\":[");
    for (size_t i = 0; i < info.group_count; ++i) {
        solaris_group_info_t group;
        (void)solaris_control_snapshot_get_group(snapshot, i, &group);
        if (i)
            putchar(',');
        printf("{\"id\":%" PRIu64 ",\"name\":", group.id);
        quote(group.name);
        printf(",\"selected\":%" PRIu64 ",\"members\":[", group.selected_id);
        for (size_t j = 0; j < group.member_count; ++j) {
            uint64_t id;
            (void)solaris_control_snapshot_get_group_member(snapshot, i, j, &id);
            if (j)
                putchar(',');
            printf("%" PRIu64, id);
        }
        printf("]}");
    }
    puts("]}");
    fflush(stdout);
    solaris_control_snapshot_release(snapshot);
}
static void select_or_probe(host_t *host, int count, char **words)
{
    solaris_control_snapshot_t *snapshot = NULL;
    solaris_control_info_t info;
    solaris_error_t error = {0};
    solaris_status_t rc = solaris_engine_get_control_snapshot(host->engine, &snapshot, &error);
    if (rc == SOLARIS_OK)
        rc = solaris_control_snapshot_get_info(snapshot, &info);
    completion_t completion;
    completion_init(&completion);
    uint64_t operation = 0;
    if (rc == SOLARIS_OK && !strcmp(words[0], "select")) {
        uint64_t group = group_id(snapshot, &info, words[1]), node = node_id(snapshot, &info, words[2]);
        rc = group && node ? solaris_engine_select(host->engine, info.config_revision, group, node, controlled,
                                                   &completion, &operation, &error)
                           : SOLARIS_EINVAL;
    } else if (rc == SOLARIS_OK) {
        uint64_t target = node_id(snapshot, &info, words[1]);
        if (!target)
            target = group_id(snapshot, &info, words[1]);
        solaris_probe_options_t options;
        solaris_probe_options_init(&options);
        options.target_id = target;
        options.config_revision = info.config_revision;
        options.url = words[2];
        options.trust_pem = host->trust;
        options.trust_length = host->trust_length;
        if (!target || (count == 4 && (!number(words[3], &options.timeout_ms) || !options.timeout_ms)))
            rc = SOLARIS_EINVAL;
        else
            rc = solaris_engine_probe(host->engine, &options, probed, &completion, &operation, &error);
    }
    solaris_control_snapshot_release(snapshot);
    rc = wait_operation(host, rc, operation, &completion);
    if (!strcmp(words[0], "probe")) {
        printf("{\"command\":\"probe\",\"status\":%d,\"http_status\":%u,\"revision\":%" PRIu64 ",\"node\":%" PRIu64
               ",\"duration_ns\":%" PRIu64 "}\n",
               (int)rc, completion.probe.http_status, completion.probe.config_revision, completion.probe.node_id,
               completion.probe.duration_ns);
        fflush(stdout);
    } else
        response("select", rc, rc == SOLARIS_OK ? NULL : error.message);
}
static void connections(host_t *host)
{
    solaris_connection_list_t *list = NULL;
    solaris_status_t rc = solaris_engine_get_connections(host->engine, 1, &list, NULL);
    if (rc != SOLARIS_OK) {
        response("connections", rc, NULL);
        return;
    }
    printf("{\"command\":\"connections\",\"status\":0,\"connections\":[");
    for (size_t i = 0; i < solaris_connection_list_count(list); ++i) {
        solaris_connection_info_t connection;
        (void)solaris_connection_list_get(list, i, &connection);
        if (i)
            putchar(',');
        printf("{\"id\":%" PRIu64 ",\"generation\":%" PRIu64 ",\"revision\":%" PRIu64
               ",\"kind\":%u,\"purpose\":%u,\"state\":%u,\"node\":%" PRIu64 "}",
               connection.key.id, connection.key.generation, connection.config_revision, connection.kind,
               connection.purpose, connection.state, connection.node_id);
    }
    puts("]}");
    fflush(stdout);
    solaris_connection_list_release(list);
}
static void traffic(host_t *host)
{
    solaris_traffic_info_t info;
    solaris_status_t rc = solaris_engine_get_traffic(host->engine, &info, NULL);
    if (rc != SOLARIS_OK) {
        response("traffic", rc, NULL);
        return;
    }
    printf("{\"command\":\"traffic\",\"status\":0,\"user_read\":%" PRIu64 ",\"user_written\":%" PRIu64
           ",\"probe_read\":%" PRIu64 ",\"probe_written\":%" PRIu64 ",\"physical_read\":%" PRIu64
           ",\"physical_written\":%" PRIu64 "}\n",
           info.logical[SOLARIS_FLOW_USER].bytes_read, info.logical[SOLARIS_FLOW_USER].bytes_written,
           info.logical[SOLARIS_FLOW_PROBE].bytes_read, info.logical[SOLARIS_FLOW_PROBE].bytes_written,
           info.physical.stream_read, info.physical.stream_written);
    fflush(stdout);
}
static void logs(host_t *host, uint64_t cursor)
{
    solaris_log_snapshot_t *snapshot = NULL;
    solaris_status_t rc = solaris_engine_get_logs(host->engine, cursor, 0, &snapshot, NULL);
    if (rc != SOLARIS_OK) {
        response("logs", rc, NULL);
        return;
    }
    solaris_log_info_t info;
    (void)solaris_log_snapshot_get_info(snapshot, &info);
    printf("{\"command\":\"logs\",\"status\":0,\"cursor\":%" PRIu64 ",\"missed\":%" PRIu64 ",\"overwritten\":%" PRIu64
           ",\"dropped\":%" PRIu64 ",\"records\":[",
           info.cursor, info.missed, info.overwritten, info.dropped);
    for (size_t i = 0; i < info.count; ++i) {
        solaris_log_record_t record;
        (void)solaris_log_snapshot_get_record(snapshot, i, &record);
        if (i)
            putchar(',');
        printf("{\"sequence\":%" PRIu64 ",\"status\":%d,\"component\":", record.sequence, (int)record.status);
        quote(record.component);
        putchar('}');
    }
    puts("]}");
    fflush(stdout);
    solaris_log_snapshot_release(snapshot);
}
/* In-place whitespace/quote parser for paths and names; no shell execution. */
static int split(char *line, char **words, int capacity)
{
    char *read = line, *write = line;
    int count = 0;
    while (*read) {
        while (*read == ' ' || *read == '\t' || *read == '\r' || *read == '\n')
            ++read;
        if (!*read)
            break;
        if (count == capacity)
            return -1;
        words[count++] = write;
        char quote_char = 0;
        while (*read) {
            char ch = *read++;
            if (quote_char) {
                if (ch == quote_char) {
                    quote_char = 0;
                    continue;
                }
            } else {
                if (ch == '"' || ch == '\'') {
                    quote_char = ch;
                    continue;
                }
                if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
                    break;
            }
            if (ch == '\\' && (*read == '\\' || *read == '"' || *read == '\''))
                ch = *read++;
            *write++ = ch;
        }
        if (quote_char)
            return -1;
        *write++ = 0;
    }
    return count;
}
static int command(host_t *host, int count, char **words)
{
    if (!count)
        return 1;
    if (count == 1 && (!strcmp(words[0], "quit") || !strcmp(words[0], "exit")))
        return 0;
    if (count == 1 && (!strcmp(words[0], "status") || !strcmp(words[0], "listeners")))
        status(host, words[0]);
    else if (count == 1 && !strcmp(words[0], "nodes"))
        controls(host);
    else if (count == 1 && !strcmp(words[0], "connections"))
        connections(host);
    else if (count == 1 && !strcmp(words[0], "traffic"))
        traffic(host);
    else if ((count == 1 || count == 2) && !strcmp(words[0], "logs")) {
        uint64_t cursor = 0;
        if (count == 2 && !number(words[1], &cursor))
            response("logs", SOLARIS_EINVAL, NULL);
        else
            logs(host, cursor);
    } else if (count == 2 && !strcmp(words[0], "load")) {
        solaris_error_t error = {0};
        solaris_status_t rc = load(host, words[1], &error);
        if (rc == SOLARIS_OK)
            status(host, "load");
        else
            response("load", rc, error.message);
    } else if ((count == 3 && !strcmp(words[0], "select")) ||
               ((count == 3 || count == 4) && !strcmp(words[0], "probe")))
        select_or_probe(host, count, words);
    else if (count == 2 && !strcmp(words[0], "mode")) {
        solaris_mode_t mode = !strcmp(words[1], "rule")     ? SOLARIS_MODE_RULE
                              : !strcmp(words[1], "global") ? SOLARIS_MODE_GLOBAL
                              : !strcmp(words[1], "direct") ? SOLARIS_MODE_DIRECT
                                                            : 0;
        solaris_active_config_snapshot_t active;
        solaris_error_t error = {0};
        completion_t c;
        completion_init(&c);
        uint64_t id = 0;
        solaris_status_t rc = mode ? solaris_engine_get_config_snapshot(host->engine, &active, &error) : SOLARIS_EINVAL;
        if (rc == SOLARIS_OK)
            rc = solaris_engine_set_mode(host->engine, active.active_revision, mode, controlled, &c, &id, &error);
        response("mode", wait_operation(host, rc, id, &c), error.message);
    } else if ((count == 2 || count == 3) && !strcmp(words[0], "close")) {
        solaris_connection_id_t key;
        solaris_error_t error = {0};
        completion_t c;
        completion_init(&c);
        uint64_t id = 0;
        solaris_status_t rc = SOLARIS_EINVAL;
        if (count == 2 && !strcmp(words[1], "all"))
            rc = solaris_engine_close_connections(host->engine, closed, &c, &id, &error);
        else if (count == 3 && number(words[1], &key.generation) && number(words[2], &key.id))
            rc = solaris_engine_close_connection(host->engine, &key, closed, &c, &id, &error);
        rc = wait_operation(host, rc, id, &c);
        printf("{\"command\":\"close\",\"status\":%d,\"matched\":%" PRIu64 "}\n", (int)rc, c.matched);
        fflush(stdout);
    } else if (count == 1 && !strcmp(words[0], "stop")) {
        uint64_t id = 0;
        solaris_status_t rc = solaris_engine_stop(host->engine, &id, NULL);
        response("stop", wait_operation(host, rc, id, NULL), NULL);
    } else if (count == 1 && !strcmp(words[0], "start")) {
        solaris_engine_snapshot_t runtime;
        solaris_status_t rc = solaris_engine_get_snapshot(host->engine, &runtime, NULL);
        if (rc == SOLARIS_OK && runtime.state != SOLARIS_ENGINE_RUNNING) {
            uint64_t id = 0;
            rc = solaris_engine_start(host->engine, &id, NULL);
            rc = wait_operation(host, rc, id, NULL);
        }
        solaris_active_config_snapshot_t active;
        solaris_error_t error = {0};
        if (rc == SOLARIS_OK)
            rc = solaris_engine_get_config_snapshot(host->engine, &active, &error);
        if (rc == SOLARIS_OK && !active.active_revision)
            rc = load(host, host->configuration, &error);
        if (rc == SOLARIS_OK)
            status(host, "start");
        else
            response("start", rc, error.message);
    } else if (count == 1 && !strcmp(words[0], "help"))
        response("help", SOLARIS_OK,
                 "status | listeners | nodes | mode rule|global|direct | select GROUP NODE | probe TARGET URL [MS] | "
                 "connections | close GENERATION ID | close all | traffic | logs [CURSOR] | load PATH | stop | start | "
                 "quit");
    else
        response(words[0], SOLARIS_EINVAL, "unknown command or invalid arguments; use help");
    return 1;
}
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "usage: %s CONFIG.yaml [--trust CA.pem] [--workers N] [--ephemeral] [--check]\n", argv[0]);
        return 2;
    }
    const char *path = argv[1], *trust_file = NULL;
    uint64_t workers = 2;
    int ephemeral = 0, check = 0;
    for (int i = 2; i < argc; ++i) {
        if (!strcmp(argv[i], "--ephemeral"))
            ephemeral = 1;
        else if (!strcmp(argv[i], "--check"))
            check = 1;
        else if (!strcmp(argv[i], "--trust") && i + 1 < argc)
            trust_file = argv[++i];
        else if (!strcmp(argv[i], "--workers") && i + 1 < argc && number(argv[i + 1], &workers))
            ++i;
        else {
            fprintf(stderr, "invalid argument: %s\n", argv[i]);
            return 2;
        }
    }
    if (!workers || workers > SOLARIS_MAX_IO_WORKERS) {
        fputs("worker count is outside the supported range\n", stderr);
        return 2;
    }
    solaris_config_t *image = NULL;
    solaris_error_t error = {0};
    solaris_status_t rc = compile_file(path, &image, &error);
    if (check || rc != SOLARIS_OK) {
        response("check", rc, error.message);
        solaris_config_release(image);
        return rc == SOLARIS_OK ? 0 : 2;
    }
    host_t host = {.ephemeral = ephemeral};
    atomic_init(&host.completed, 0);
    host.configuration = copy_string(path);
    if (!host.configuration) {
        solaris_config_release(image);
        return 2;
    }
    if (trust_file) {
        FILE *file = open_file(trust_file);
        long length = -1;
        if (file && !fseek(file, 0, SEEK_END))
            length = ftell(file);
        if (!file || length <= 0 || length > 262144 || fseek(file, 0, SEEK_SET)) {
            if (file)
                fclose(file);
            free(host.configuration);
            solaris_config_release(image);
            fputs("cannot read bounded trust file\n", stderr);
            return 2;
        }
        host.trust = malloc((size_t)length);
        host.trust_length = (size_t)length;
        if (!host.trust || fread(host.trust, 1, host.trust_length, file) != host.trust_length) {
            fclose(file);
            free(host.trust);
            free(host.configuration);
            solaris_config_release(image);
            return 2;
        }
        fclose(file);
    }
    solaris_engine_options_t options;
    solaris_engine_options_init(&options);
    options.io_workers = (uint32_t)workers;
    solaris_host_t callbacks = {&host, event};
    rc = solaris_engine_create(&options, &callbacks, &host.engine, &error);
    if (rc == SOLARIS_OK) {
        uint64_t id = 0;
        rc = solaris_engine_start(host.engine, &id, &error);
        rc = wait_operation(&host, rc, id, NULL);
    }
    if (rc == SOLARIS_OK)
        rc = activate(&host, image, &error);
    solaris_config_release(image);
    int exit_code = rc == SOLARIS_OK ? 0 : 2;
    if (rc == SOLARIS_OK) {
        status(&host, "ready");
        char line[4096];
        while (fgets(line, sizeof(line), stdin)) {
            if (!strchr(line, '\n') && !feof(stdin)) {
                int ch;
                while ((ch = getchar()) != '\n' && ch != EOF) {
                }
                response("input", SOLARIS_EMSGSIZE, "command line is too long");
                continue;
            }
            char *words[8];
            int count = split(line, words, 8);
            if (count < 0) {
                response("input", SOLARIS_EINVAL, "invalid quoting or too many arguments");
                continue;
            }
            if (!command(&host, count, words) || !host.engine) {
                if (!host.engine)
                    exit_code = 2;
                break;
            }
        }
    } else
        response("ready", rc, error.message);
    if (host.engine) {
        uint64_t id = 0;
        solaris_status_t stopped = solaris_engine_stop(host.engine, &id, NULL);
        stopped = wait_operation(&host, stopped, id, NULL);
        solaris_status_t destroyed = solaris_engine_destroy(host.engine, NULL);
        if (stopped != SOLARIS_OK || destroyed != SOLARIS_OK)
            exit_code = 2;
        response("quit", destroyed != SOLARIS_OK ? destroyed : stopped, NULL);
    }
    if (host.trust)
        for (size_t i = 0; i < host.trust_length; ++i)
            ((volatile unsigned char *)host.trust)[i] = 0;
    free(host.trust);
    free(host.configuration);
    return exit_code;
}
