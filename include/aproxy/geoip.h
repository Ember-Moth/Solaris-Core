#ifndef APROXY_GEOIP_H
#define APROXY_GEOIP_H

#include <stddef.h>

#include "aproxy/address.h"

typedef struct aproxy_geoip_db aproxy_geoip_db_t;
typedef struct aproxy_geoip_set aproxy_geoip_set_t;

typedef struct aproxy_geoip_stats {
    size_t ipv4_count;
    size_t ipv6_count;
} aproxy_geoip_stats_t;

/* Keeps one V2Ray geoip.dat-compatible file mapped while entries are loaded. */
int aproxy_geoip_db_open_v2ray_dat(const char *path,
                                   aproxy_geoip_db_t **out);

void aproxy_geoip_db_free(aproxy_geoip_db_t *db);

int aproxy_geoip_db_load(const aproxy_geoip_db_t *db,
                         const char *country_code,
                         aproxy_geoip_set_t **out);

/* Convenience wrapper for loading one entry without retaining a database. */
int aproxy_geoip_set_load_v2ray_dat(const char *path,
                                    const char *country_code,
                                    aproxy_geoip_set_t **out);

void aproxy_geoip_set_free(aproxy_geoip_set_t *set);

const char *aproxy_geoip_set_code(const aproxy_geoip_set_t *set);

void aproxy_geoip_set_stats(const aproxy_geoip_set_t *set,
                            aproxy_geoip_stats_t *out);

int aproxy_geoip_set_match(const aproxy_geoip_set_t *set,
                           const aproxy_addr_t *addr);

#endif
