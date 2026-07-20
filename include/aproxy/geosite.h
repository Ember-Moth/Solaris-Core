#ifndef APROXY_GEOSITE_H
#define APROXY_GEOSITE_H

#include <stddef.h>

#include "aproxy/address.h"
#include "aproxy/error.h"

typedef struct aproxy_geosite_db aproxy_geosite_db_t;
typedef struct aproxy_geosite_set aproxy_geosite_set_t;

typedef struct aproxy_geosite_stats {
    size_t exact_count;
    size_t suffix_count;
    size_t keyword_count;
    size_t regex_count;
    size_t string_bytes;
} aproxy_geosite_stats_t;

/* Keeps the V2Ray geosite.dat file in a read-only mmap. */
int aproxy_geosite_db_open_v2ray_dat(const char *path,
                                     aproxy_geosite_db_t **out);

void aproxy_geosite_db_free(aproxy_geosite_db_t *db);

/* selector accepts CODE and CODE@attribute forms. */
int aproxy_geosite_db_load(const aproxy_geosite_db_t *db,
                           const char *selector,
                           aproxy_geosite_set_t **out);

int aproxy_geosite_set_load_v2ray_dat(const char *path,
                                      const char *selector,
                                      aproxy_geosite_set_t **out);

void aproxy_geosite_set_free(aproxy_geosite_set_t *set);

const char *aproxy_geosite_set_selector(const aproxy_geosite_set_t *set);

void aproxy_geosite_set_stats(const aproxy_geosite_set_t *set,
                              aproxy_geosite_stats_t *out);

int aproxy_geosite_set_match_domain(const aproxy_geosite_set_t *set,
                                    const char *domain,
                                    size_t domain_len);

/* Fast path for an ASCII-lowercase, NUL-terminated domain. */
int aproxy_geosite_set_match_domain_lower(const aproxy_geosite_set_t *set,
                                          const char *lower_domain,
                                          size_t domain_len);

int aproxy_geosite_set_match(const aproxy_geosite_set_t *set,
                             const aproxy_addr_t *addr);

#endif
