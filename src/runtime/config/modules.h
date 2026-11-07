#ifndef SOLARIS_CONFIG_MODULES_H
#define SOLARIS_CONFIG_MODULES_H
#include "contracts/config/image.h"
#include "contracts/module/module.h"

typedef struct solaris_config_module_set solaris_config_module_set_t;
/* Synchronous prepare stage, with no resolver/socket/listener operations. Image
 * is retained. Host PEM bytes are borrowed only until return and injected only
 * into TLS-enabled node views; the immutable image is never modified. Failure
 * leaves out=NULL and releases every partial compiled configuration. */
solaris_status_t solaris_config_module_set_create(solaris_budget_t *budget, solaris_config_t *image,
                                                  const void *trust_pem, size_t trust_length,
                                                  solaris_config_module_set_t **out, solaris_error_t *error);
void solaris_config_module_set_retain(solaris_config_module_set_t *set);
void solaris_config_module_set_release(solaris_config_module_set_t *set);
/* Borrowed immutable records require a retained set. */
solaris_config_t *solaris_config_module_set_image(const solaris_config_module_set_t *set);
size_t solaris_config_module_set_count(const solaris_config_module_set_t *set);
solaris_module_config_t *solaris_config_module_set_at(const solaris_config_module_set_t *set, size_t index);
#endif
