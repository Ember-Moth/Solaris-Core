#include "solaris_builtin_modules.h"
#include <solaris/core.h>
#include <stdio.h>
#include <string.h>

static int module_capabilities(void) {
  static const struct {
    const char *type, *fields;
    int enabled;
  } cases[] = {{"direct", "", SOLARIS_HAS_DIRECT},
               {"reject", "", SOLARIS_HAS_BLOCK},
               {"socks5", ", server: 127.0.0.1, port: 1080, udp: true",
                SOLARIS_HAS_SOCKS5},
               {"ss",
                ", server: 127.0.0.1, port: 1080, cipher: aes-128-gcm, "
                "password: fixture",
                SOLARIS_HAS_SHADOWSOCKS},
               {"vless",
                ", server: 127.0.0.1, port: 1080, uuid: "
                "00112233-4455-6677-8899-aabbccddeeff",
                SOLARIS_HAS_VLESS},
               {"anytls", ", server: 127.0.0.1, port: 1080, password: fixture",
                SOLARIS_HAS_ANYTLS}};
  for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); ++i) {
    char input[512];
    int length = snprintf(input, sizeof(input),
                          "proxies: [{name: capability, type: %s%s}]",
                          cases[i].type, cases[i].fields);
    if (length < 0 || (size_t)length >= sizeof(input))
      return 1;
    solaris_config_t *image = NULL;
    solaris_diagnostics_t *diagnostics = NULL;
    solaris_error_t error;
    solaris_status_t status = solaris_config_compile_bytes(
        input, (size_t)length, NULL, &image, &diagnostics, &error);
    int supported = SOLARIS_HAS_DIRECT && SOLARIS_HAS_BLOCK && cases[i].enabled;
    int failed = status != (supported ? SOLARIS_OK : SOLARIS_ENOTSUP) ||
                 error.code != status || (image != NULL) != supported ||
                 (!supported && !solaris_diagnostics_count(diagnostics));
    solaris_config_release(image);
    solaris_diagnostics_release(diagnostics);
    if (failed) {
      fprintf(stderr, "Public YAML capability rejection failed for %s: %d\n",
              cases[i].type, status);
      return 1;
    }
  }
  return 0;
}

int main(void) {
  if (module_capabilities())
    return 1;
  solaris_config_t *config = NULL;
  solaris_diagnostics_t *diagnostics = NULL;
  solaris_error_t error;
  solaris_status_t status = solaris_config_compile_bytes("{}", 2, NULL, &config,
                                                         &diagnostics, &error);
  int available = SOLARIS_HAS_DIRECT && SOLARIS_HAS_BLOCK;
  int failed = status != (available ? SOLARIS_OK : SOLARIS_ENOTSUP) ||
               error.code != status;
  if (available) {
    solaris_config_snapshot_t snapshot;
    solaris_config_node_info_t node;
    failed |=
        !config || solaris_config_get_snapshot(config, &snapshot) != SOLARIS_OK;
    if (!failed)
      failed |= snapshot.node_count != 2 || snapshot.listener_count != 0;
    solaris_config_retain(config);
    solaris_config_release(config);
    failed |= solaris_config_get_node(config, 0, &node) != SOLARIS_OK;
    if (!failed)
      failed |= strcmp(node.name, "DIRECT") != 0 || node.id == 0;
  } else
    failed |= config != NULL || solaris_diagnostics_count(diagnostics) == 0;
  solaris_config_release(config);
  solaris_diagnostics_release(diagnostics);
  if (failed)
    fprintf(stderr,
            "Public YAML compiler/default-module capability contract failed\n");
  return failed;
}
