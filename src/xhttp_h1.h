#ifndef APROXY_XHTTP_H1_H
#define APROXY_XHTTP_H1_H

#include "aproxy/xhttp.h"

typedef struct xhttp_h1_client xhttp_h1_client_t;

int xhttp_h1_client_new(const aproxy_xhttp_config_t *config,
                        xhttp_h1_client_t **out);

int xhttp_h1_client_open_stream(xhttp_h1_client_t *client,
                                aproxy_stream_data_cb on_data,
                                aproxy_stream_event_cb on_open,
                                aproxy_stream_event_cb on_close,
                                void *user_data,
                                aproxy_stream_t **out);

void xhttp_h1_client_close(xhttp_h1_client_t *client);
void xhttp_h1_client_free(xhttp_h1_client_t *client);

#endif
