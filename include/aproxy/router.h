#ifndef APROXY_ROUTER_H
#define APROXY_ROUTER_H

#include <stddef.h>
#include <stdint.h>

#include "aproxy/address.h"
#include "aproxy/geoip.h"
#include "aproxy/geosite.h"
#include "aproxy/outbound.h"

typedef struct aproxy_router aproxy_router_t;

int aproxy_router_new(aproxy_router_t **out);
void aproxy_router_free(aproxy_router_t *router);

/* Releases unused builder capacity without changing rule order or indices. */
void aproxy_router_compact(aproxy_router_t *router);

int aproxy_router_set_default(aproxy_router_t *router,
                              aproxy_outbound_t *outbound);

/*
 * Logical proxy targets are resolved to the currently selected proxy when a
 * new flow is routed. Already-open flows retain the concrete outbound they
 * received from the router.
 */
int aproxy_router_set_selected_proxy(aproxy_router_t *router,
                                     aproxy_outbound_t *outbound);
int aproxy_router_set_default_proxy(aproxy_router_t *router);

/* Takes ownership of `profile` on success. */
int aproxy_router_add_profile(aproxy_router_t *router,
                              const char *profile_id,
                              aproxy_router_t *profile);
int aproxy_router_select_profile(aproxy_router_t *router,
                                 const char *profile_id);
const char *aproxy_router_active_profile(const aproxy_router_t *router);

int aproxy_router_add_domain_suffix(aproxy_router_t *router,
                                    const char *suffix,
                                    aproxy_outbound_t *outbound);
int aproxy_router_add_domain_suffix_proxy(aproxy_router_t *router,
                                          const char *suffix);

int aproxy_router_add_domain_exact(aproxy_router_t *router,
                                   const char *domain,
                                   aproxy_outbound_t *outbound);
int aproxy_router_add_domain_exact_proxy(aproxy_router_t *router,
                                         const char *domain);

int aproxy_router_add_ipv4_cidr(aproxy_router_t *router,
                                const uint8_t network[4],
                                uint8_t prefix_len,
                                aproxy_outbound_t *outbound);
int aproxy_router_add_ipv4_cidr_proxy(aproxy_router_t *router,
                                      const uint8_t network[4],
                                      uint8_t prefix_len);

int aproxy_router_add_ipv6_cidr(aproxy_router_t *router,
                                const uint8_t network[16],
                                uint8_t prefix_len,
                                aproxy_outbound_t *outbound);
int aproxy_router_add_ipv6_cidr_proxy(aproxy_router_t *router,
                                      const uint8_t network[16],
                                      uint8_t prefix_len);

/* The router borrows `set`; keep it alive until the router is freed. */
int aproxy_router_add_geoip(aproxy_router_t *router,
                            const aproxy_geoip_set_t *set,
                            aproxy_outbound_t *outbound);
int aproxy_router_add_geoip_proxy(aproxy_router_t *router,
                                  const aproxy_geoip_set_t *set);

/* The router borrows `set`; keep it alive until the router is freed. */
int aproxy_router_add_geosite(aproxy_router_t *router,
                              const aproxy_geosite_set_t *set,
                              aproxy_outbound_t *outbound);
int aproxy_router_add_geosite_proxy(aproxy_router_t *router,
                                    const aproxy_geosite_set_t *set);

aproxy_outbound_t *aproxy_router_pick(const aproxy_router_t *router,
                                      const aproxy_addr_t *destination);

/* True when an FQDN needs A/AAAA results to evaluate IP rules correctly. */
int aproxy_router_needs_resolution(const aproxy_router_t *router,
                                   const aproxy_addr_t *destination);

/* True when sniffed domains can affect an outbound decision. */
int aproxy_router_has_domain_rules(const aproxy_router_t *router);

/* Evaluates domain and resolved-IP rules in their original priority order. */
aproxy_outbound_t *aproxy_router_pick_resolved(
    const aproxy_router_t *router,
    const aproxy_addr_t *destination,
    const aproxy_addr_t *addresses,
    size_t address_count);

#endif
