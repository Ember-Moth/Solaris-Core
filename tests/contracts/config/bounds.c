#include <solaris/config.h>
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
static const char secret[] = "SYNTHETIC-CREDENTIAL-DO-NOT-DISCLOSE";
static solaris_status_t compile(const char *input, solaris_config_options_t *options, size_t *diagnostics_count) {
    solaris_config_t *image = (void *)1;
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_error_t error;
    solaris_status_t status = solaris_config_compile_bytes(input, strlen(input), options, &image, &diagnostics, &error);
    CHECK(error.code == status && (status == SOLARIS_OK) == (image != NULL));
    CHECK(memchr(error.message, 0, sizeof(error.message)) && !strstr(error.message, secret));
    size_t count = solaris_diagnostics_count(diagnostics);
    CHECK(count <= (options && options->diagnostic_limit ? options->diagnostic_limit : 64));
    for (size_t i = 0; i < count; ++i) {
        solaris_config_diagnostic_t item;
        CHECK(solaris_diagnostics_get(diagnostics, i, &item) == SOLARIS_OK);
        CHECK(memchr(item.source, 0, sizeof(item.source)) && memchr(item.path, 0, sizeof(item.path)) &&
              memchr(item.message, 0, sizeof(item.message)));
        CHECK(!strstr(item.source, secret) && !strstr(item.path, secret) && !strstr(item.message, secret));
        if (options && options->source_name)
            CHECK(!strcmp(item.source, options->source_name));
    }
    if (diagnostics_count)
        *diagnostics_count = count;
    solaris_config_release(image);
    solaris_diagnostics_release(diagnostics);
    return status;
}
#define DIRECT "[General]\nconfig-version = 1\nmode = direct\n"
static void limits(void) {
    solaris_config_options_t o;
    solaris_config_options_init(&o);
    o.input_limit_bytes = sizeof(DIRECT) - 1;
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_OK);
    CHECK(compile(DIRECT "\n", &o, NULL) == SOLARIS_EOVERFLOW);
    solaris_config_options_init(&o);
    o.node_limit = 7;
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_OK);
    o.node_limit = 6;
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_EOVERFLOW);
    solaris_config_options_init(&o);
    o.line_limit_bytes = 18;
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_OK);
    o.line_limit_bytes = 17;
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_EOVERFLOW);
    solaris_config_options_init(&o);
    o.string_limit_bytes = 14;
    CHECK(compile(DIRECT "[Proxy]\nabcdefghijklmn=direct\n", &o, NULL) == SOLARIS_OK);
    CHECK(compile(DIRECT "[Proxy]\nabcdefghijklmno=direct\n", &o, NULL) == SOLARIS_EOVERFLOW);
    solaris_config_options_init(&o);
    o.entry_limit = 3;
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_OK);
    o.entry_limit = 2;
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_EOVERFLOW);
    memset(&o, 0, sizeof(o));
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_OK);
    o.memory_limit_bytes = 1;
    CHECK(compile(DIRECT, &o, NULL) == SOLARIS_ENOMEM);
}
static void invalid_options(void) {
    solaris_config_options_t o;
    for (unsigned i = 0; i < 6; ++i) {
        solaris_config_options_init(&o);
        switch (i) {
        case 0:
            o.input_limit_bytes = 67108865;
            break;
        case 1:
            o.string_limit_bytes = 67108865;
            break;
        case 2:
            o.line_limit_bytes = 67108865;
            break;
        case 3:
            o.node_limit = 1048577;
            break;
        case 4:
            o.entry_limit = 1048577;
            break;
        default:
            o.diagnostic_limit = 1025;
            break;
        }
        CHECK(compile("{}", &o, NULL) == SOLARIS_EINVAL);
    }
    char source[513];
    memset(source, 's', sizeof(source));
    source[512] = 0;
    solaris_config_options_init(&o);
    o.source_name = source;
    CHECK(compile("{}", &o, NULL) == SOLARIS_EINVAL);
    char base[4097];
    memset(base, 'b', sizeof(base));
    base[4096] = 0;
    solaris_config_options_init(&o);
    o.base_directory = base;
    CHECK(compile("{}", &o, NULL) == SOLARIS_EINVAL);
}
static void diagnostics(void) {
    solaris_config_options_t o;
    solaris_config_options_init(&o);
    o.source_name = "diagnostics.conf";
    o.diagnostic_limit = 2;
    size_t count;
    CHECK(compile(DIRECT "unimplemented-a=1\nunimplemented-b=2\nunimplemented-c=3\n", &o, &count) == SOLARIS_ENOTSUP);
    CHECK(count == 2);
    CHECK(compile(DIRECT "SYNTHETIC-CREDENTIAL-DO-NOT-DISCLOSE=1\n", &o, NULL) == SOLARIS_ENOTSUP);
    solaris_config_t *image = NULL;
    solaris_diagnostics_t *items = NULL;
    solaris_error_t error;
    const char *input = DIRECT "mode = global\n";
    CHECK(solaris_config_compile_bytes(input, strlen(input), &o, &image, &items, &error) == SOLARIS_EINVAL);
    solaris_config_diagnostic_t item;
    CHECK(!image && solaris_diagnostics_count(items) == 1 && solaris_diagnostics_get(items, 0, &item) == SOLARIS_OK);
    CHECK(item.stage == SOLARIS_CONFIG_PARSE && item.line == 4 && item.column == 1 && item.related_line == 3 &&
          item.related_column == 1);
    solaris_diagnostics_release(items);
    input = DIRECT "[Proxy]\np = socks5, x, bad\n";
    CHECK(solaris_config_compile_bytes(input, strlen(input), &o, &image, &items, &error) == SOLARIS_EINVAL);
    CHECK(solaris_diagnostics_get(items, 0, &item) == SOLARIS_OK && item.line == 5 && item.column == 16 &&
          strstr(item.path, "port"));
    solaris_diagnostics_release(items);
}
static void retained_input(void) {
    char input[] = DIRECT "[Proxy]\nkept-node = direct\n";
    char source[] = "caller-source.conf";
    char base[] = "/compiler-does-not-read-this-path";
    solaris_config_options_t options;
    solaris_config_options_init(&options);
    options.source_name = source;
    options.base_directory = base;
    solaris_config_t *image;
    solaris_diagnostics_t *diagnostics;
    CHECK(solaris_config_compile_bytes(input, strlen(input), &options, &image, &diagnostics, NULL) == SOLARIS_OK);
    memset(input, 0xff, sizeof(input));
    memset(source, 0xff, sizeof(source));
    memset(base, 0xff, sizeof(base));
    solaris_diagnostics_release(diagnostics);
    solaris_config_retain(image);
    solaris_config_release(image);
    solaris_config_snapshot_t info;
    solaris_config_node_info_t node;
    CHECK(solaris_config_get_snapshot(image, &info) == SOLARIS_OK && info.mode == SOLARIS_MODE_DIRECT &&
          info.node_count == 3);
    CHECK(solaris_config_get_node(image, 2, &node) == SOLARIS_OK && !strcmp(node.name, "kept-node"));
    solaris_config_release(image);
}
int main(void) {
    limits();
    invalid_options();
    diagnostics();
    retained_input();
    puts("Configuration boundaries: exact parser budgets, bounded safe "
         "diagnostics and owned input passed");
    return 0;
}
