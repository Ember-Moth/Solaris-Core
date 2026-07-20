#ifndef SOLARIS_CORE_H
#define SOLARIS_CORE_H

#include "aproxy/engine.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SOLARIS_CORE_ENGINE_ABI_VERSION APROXY_ENGINE_ABI_VERSION
#define SOLARIS_CORE_CONFIG_SCHEMA "aproxy.proxy-config"
#define SOLARIS_CORE_CONFIG_SCHEMA_VERSION 2u

typedef aproxy_engine_t solaris_core_engine_t;
typedef aproxy_engine_config_v2_t solaris_core_config_t;
typedef aproxy_engine_host_v2_t solaris_core_host_t;
typedef aproxy_engine_api_v2_t solaris_core_api_t;
typedef aproxy_engine_event_v2_t solaris_core_event_t;
typedef aproxy_engine_status_v2_t solaris_core_status_t;
typedef aproxy_value_t solaris_core_value_t;
typedef aproxy_string_view_t solaris_core_string_view_t;
typedef aproxy_bytes_view_t solaris_core_bytes_view_t;

static inline int solaris_core_get_api(const solaris_core_api_t **out_api)
{
    return aproxy_engine_get_api(SOLARIS_CORE_ENGINE_ABI_VERSION, out_api);
}

#ifdef __cplusplus
}
#endif

#endif
