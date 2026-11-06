#include "adapters/inbound/proxy/internal.h"
#include <string.h>

void solaris_proxy_socks_reply(proxy_connection_t *c, uint8_t code, const solaris_address_t *bound, proxy_state_t next)
{
    uint8_t bytes[262] = {5, code, 0};
    size_t n;
    solaris_address_t zero = {.family = SOLARIS_ADDRESS_IPV4};
    if (solaris_socks_address_encode(bound ? bound : &zero, bytes + 3, sizeof(bytes) - 3, &n) != SOLARIS_OK) {
        solaris_proxy_cancel(c, SOLARIS_EINVAL);
        return;
    }
    solaris_proxy_reply(c, bytes, n + 3, next);
}
void solaris_proxy_socks_parse(proxy_connection_t *c)
{
    const uint8_t *p = c->input;
    size_t n = c->input_length;
    if (c->state == PROXY_METHOD) {
        if (n < 2)
            return;
        if (p[0] != 5 || !p[1]) {
            c->inbound->stats.protocol_failed++;
            solaris_proxy_cancel(c, SOLARIS_EINVAL);
            return;
        }
        size_t size = (size_t)p[1] + 2;
        if (n < size)
            return;
        uint8_t wanted = c->inbound->options.authenticate ? 2 : 0;
        int offered = memchr(p + 2, wanted, p[1]) != NULL;
        uint8_t reply[2] = {5, offered ? wanted : 255};
        solaris_proxy_consume(c, size);
        if (!offered)
            c->inbound->stats.authentication_failed++;
        solaris_proxy_reply(c, reply, sizeof(reply), offered ? (wanted ? PROXY_AUTH : PROXY_REQUEST) : PROXY_ERROR);
    } else if (c->state == PROXY_AUTH) {
        if (n < 2)
            return;
        if (p[0] != 1 || !p[1]) {
            uint8_t reply[] = {1, 1};
            solaris_proxy_reply(c, reply, 2, PROXY_ERROR);
            return;
        }
        size_t user = p[1];
        if (n < 3 + user)
            return;
        size_t pass = p[2 + user];
        if (n < 3 + user + pass)
            return;
        solaris_status_t rc =
            pass ? c->inbound->options.authenticate(c->inbound->options.context, p + 2, user, p + 3 + user, pass)
                 : SOLARIS_EINVAL;
        if (rc == SOLARIS_OK) {
            memcpy(c->username, p + 2, user);
            c->username_length = user;
        }
        /* Clear the complete credentials before moving any pipelined request. */
        for (size_t i = 0; i < 3 + user + pass; ++i)
            ((volatile uint8_t *)c->input)[i] = 0;
        solaris_proxy_consume(c, 3 + user + pass);
        if (c->scope.cancelled)
            return;
        uint8_t reply[] = {1, rc == SOLARIS_OK ? 0 : 1};
        if (rc != SOLARIS_OK)
            c->inbound->stats.authentication_failed++;
        solaris_proxy_reply(c, reply, 2, rc == SOLARIS_OK ? PROXY_REQUEST : PROXY_ERROR);
    } else if (c->state == PROXY_REQUEST) {
        if (n < 4)
            return;
        if (p[0] != 5 || p[2] != 0) {
            solaris_proxy_socks_reply(c, 1, NULL, PROXY_ERROR);
            return;
        }
        if (p[3] != 1 && p[3] != 3 && p[3] != 4) {
            solaris_proxy_socks_reply(c, 8, NULL, PROXY_ERROR);
            return;
        }
        size_t used;
        solaris_address_t target;
        solaris_status_t rc = solaris_socks_address_decode(p + 3, n - 3, &target, &used);
        if (rc == SOLARIS_EAGAIN)
            return;
        if (rc != SOLARIS_OK) {
            solaris_proxy_socks_reply(c, 8, NULL, PROXY_ERROR);
            return;
        }
        uint8_t command = p[1];
        solaris_proxy_consume(c, used + 3);
        if (command == 1 && target.family == SOLARIS_ADDRESS_DOMAIN) {
            solaris_address_t normalized;
            if (solaris_address_parse(target.host, target.port, &normalized) != SOLARIS_OK) {
                solaris_proxy_socks_reply(c, 8, NULL, PROXY_ERROR);
                return;
            }
            target = normalized;
        }
        if (command == 1 && target.port) {
            c->destination = target;
            solaris_proxy_connect(c);
        } else if (command == 3 && c->inbound->options.udp) {
            if (target.family == SOLARIS_ADDRESS_DOMAIN) {
                solaris_proxy_socks_reply(c, 8, NULL, PROXY_ERROR);
                return;
            }
            uint8_t zero[16] = {0};
            size_t bytes = target.family == SOLARIS_ADDRESS_IPV4 ? 4 : 16;
            if (memcmp(target.ip, zero, bytes) &&
                (target.family != c->peer.family || memcmp(target.ip, c->peer.ip, bytes))) {
                solaris_proxy_socks_reply(c, 2, NULL, PROXY_ERROR);
                return;
            }
            c->udp_peer = c->peer;
            c->udp_peer.port = target.port;
            if (c->input_length) {
                solaris_proxy_socks_reply(c, 1, NULL, PROXY_ERROR);
                return;
            }
            solaris_proxy_udp_open(c);
        } else
            solaris_proxy_socks_reply(c, command == 1 ? 8 : 7, NULL, PROXY_ERROR);
    }
}
