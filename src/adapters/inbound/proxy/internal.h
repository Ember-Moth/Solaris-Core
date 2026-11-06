#ifndef SOLARIS_PROXY_INTERNAL_H
#define SOLARIS_PROXY_INTERNAL_H
#include "contracts/inbound/proxy.h"
#include "contracts/flow/tcp.h"
#include "contracts/flow/udp.h"
#include "transport/socket/tcp.h"
#include "codec/http/proxy.h"
#include "codec/address/socks.h"

typedef enum proxy_state {
    PROXY_DETECT,
    PROXY_METHOD,
    PROXY_AUTH,
    PROXY_REQUEST,
    PROXY_HTTP,
    PROXY_CONNECTING,
    PROXY_STREAM,
    PROXY_UDP_OPEN,
    PROXY_UDP,
    PROXY_ERROR
} proxy_state_t;
typedef struct proxy_connection proxy_connection_t;
struct solaris_proxy_inbound {
    solaris_scope_t scope;
    solaris_proxy_inbound_options_t options;
    solaris_proxy_inbound_snapshot_t stats;
    solaris_tcp_listener_t *listener;
    solaris_udp_dispatcher_t *udp;
    solaris_deadline_t *timer;
    proxy_connection_t *connections;
    uint64_t serial;
    solaris_status_t status;
    int accepted;
};
struct proxy_connection {
    solaris_scope_t scope;
    solaris_proxy_inbound_t *inbound;
    proxy_connection_t *next;
    solaris_stream_t *native, stream;
    solaris_stream_callbacks_t callbacks;
    void *callback_context;
    solaris_tcp_relay_t *relay;
    solaris_deferred_t deferred;
    solaris_http_request_t *http;
    solaris_http_upgrade_response_t *upgrade;
    solaris_buffer_t *upgrade_output;
    solaris_io_done_fn upgrade_done;
    void *upgrade_context;
    size_t upgrade_offset;
    int upgrade_writing, upgrade_settled, http_upgraded;
    solaris_buffer_t *header, *reply;
    uint8_t *input;
    size_t input_length, input_capacity;
    uint8_t username[256];
    size_t username_length;
    solaris_address_t peer, local, destination, udp_peer;
    solaris_datagram_t *datagram;
    solaris_udp_key_t udp_key;
    uint64_t association_id, id, created_ns, activity_ns;
    solaris_status_t status;
    proxy_state_t state, after_reply;
    uint32_t protocol;
    int native_open, native_eof, eof_delivered, virtual_open, virtual_close;
    int reading, replying, http_connect, wrapper, draining, associated;
    solaris_io_done_fn shutdown_done;
    void *shutdown_context;
};
void solaris_proxy_schedule(proxy_connection_t *connection);
void solaris_proxy_cancel(proxy_connection_t *connection, solaris_status_t status);
void solaris_proxy_consume(proxy_connection_t *connection, size_t length);
void solaris_proxy_reply(proxy_connection_t *connection, const void *data, size_t length, proxy_state_t next);
void solaris_proxy_socks_reply(proxy_connection_t *connection, uint8_t code, const solaris_address_t *bound,
                               proxy_state_t next);
void solaris_proxy_http_error(proxy_connection_t *connection, unsigned code);
void solaris_proxy_connect(proxy_connection_t *connection);
void solaris_proxy_socks_parse(proxy_connection_t *connection);
solaris_status_t solaris_proxy_udp_create(solaris_proxy_inbound_t *inbound);
void solaris_proxy_udp_open(proxy_connection_t *connection);
void solaris_proxy_udp_cancel(proxy_connection_t *connection);
solaris_status_t solaris_proxy_select(proxy_connection_t *connection, uint32_t network,
                                      const solaris_address_t *destination, solaris_dial_plan_t *out);
solaris_status_t solaris_proxy_upgrade_write(proxy_connection_t *connection, const solaris_slice_t *data,
                                             solaris_io_done_fn done, void *context);
void solaris_proxy_upgrade_pump(proxy_connection_t *connection);
#endif
