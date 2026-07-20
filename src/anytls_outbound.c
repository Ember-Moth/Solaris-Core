#include "anytls/outbound.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aproxy/buffer.h"
#include "aproxy/limits.h"
#include "aproxy/uot.h"
#include "framework/stream_internal.h"

#define ANYTLS_DEFAULT_IDLE_CHECK_MS 30000u
#define ANYTLS_DEFAULT_IDLE_TIMEOUT_MS 30000u
#define ANYTLS_DEFAULT_MAX_IDLE_SESSIONS 64

typedef struct anytls_outbound_impl anytls_outbound_impl_t;
typedef struct anytls_session_node anytls_session_node_t;
typedef struct anytls_stream_impl anytls_stream_impl_t;

struct anytls_stream_impl {
    anytls_outbound_impl_t *outbound;
    anytls_stream_t *native;
    aproxy_stream_t *owner;
    anytls_session_node_t *session;
    aproxy_addr_t destination;
    aproxy_buffer_t pending_write;
    aproxy_stream_data_cb on_data;
    aproxy_stream_event_cb on_open;
    aproxy_stream_event_cb on_close;
    void *user_data;
    int closed;
    int opening;
    int session_released;
    anytls_stream_impl_t *pending_next;
    anytls_stream_impl_t *prev;
    anytls_stream_impl_t *next;
};

struct anytls_session_node {
    anytls_outbound_impl_t *outbound;
    anytls_client_t *client;
    uint64_t seq;
    uint64_t idle_since_ms;
    size_t active_streams;
    int ready;
    int closed;
    int report_ready;
    int in_idle;
    anytls_stream_impl_t *pending_streams;
    anytls_session_node_t *next_all;
    anytls_session_node_t *prev_idle;
    anytls_session_node_t *next_idle;
};

struct anytls_outbound_impl {
    anytls_client_config_t client_config;
    aproxy_tls_context_t *tls_context;
    anytls_client_ready_cb user_on_ready;
    anytls_client_close_cb user_on_close;
    void *user_data;
    anytls_padding_store_t *padding_store;
    char *tag;
    anytls_session_node_t *sessions;
    anytls_stream_impl_t *streams;
    anytls_session_node_t *idle_head;
    anytls_session_node_t *idle_tail;
    size_t idle_count;
    uint64_t next_seq;
    uint64_t idle_check_ms;
    uint64_t idle_timeout_ms;
    int min_idle_sessions;
    int max_idle_sessions;
    int connected;
    int closing;
    int ready_reported;
    int close_reported;
    int owns_padding_store;
    uv_timer_t idle_timer;
    int idle_timer_initialized;
    int idle_timer_closed;
    int free_pending;
};

static char *copy_string(const char *s)
{
    if (s == NULL) {
        return NULL;
    }
    const size_t len = strlen(s);
    char *copy = (char *)malloc(len + 1u);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, s, len + 1u);
    return copy;
}

static uint64_t outbound_now_ms(const anytls_outbound_impl_t *outbound)
{
    if (outbound == NULL || outbound->client_config.loop == NULL) {
        return 0u;
    }
    uv_update_time(outbound->client_config.loop);
    return uv_now(outbound->client_config.loop);
}

static void remove_idle_session(anytls_session_node_t *session)
{
    if (session == NULL || !session->in_idle) {
        return;
    }
    anytls_outbound_impl_t *outbound = session->outbound;
    if (session->prev_idle != NULL) {
        session->prev_idle->next_idle = session->next_idle;
    } else {
        outbound->idle_head = session->next_idle;
    }
    if (session->next_idle != NULL) {
        session->next_idle->prev_idle = session->prev_idle;
    } else {
        outbound->idle_tail = session->prev_idle;
    }
    session->prev_idle = NULL;
    session->next_idle = NULL;
    session->in_idle = 0;
    if (outbound->idle_count > 0u) {
        outbound->idle_count--;
    }
}

static void put_idle_session(anytls_session_node_t *session);
static void close_session(anytls_session_node_t *session);
static void session_release_stream(anytls_stream_impl_t *stream);
static void outbound_maybe_destroy(anytls_outbound_impl_t *outbound);
static int create_session(anytls_outbound_impl_t *outbound,
                          size_t active_streams,
                          int report_ready,
                          anytls_session_node_t **out);

static void stream_list_add(anytls_stream_impl_t *stream)
{
    stream->prev = NULL;
    stream->next = stream->outbound->streams;
    if (stream->next != NULL) {
        stream->next->prev = stream;
    }
    stream->outbound->streams = stream;
}

static void stream_list_remove(anytls_stream_impl_t *stream)
{
    if (stream->prev != NULL) {
        stream->prev->next = stream->next;
    } else if (stream->outbound != NULL &&
               stream->outbound->streams == stream) {
        stream->outbound->streams = stream->next;
    }
    if (stream->next != NULL) {
        stream->next->prev = stream->prev;
    }
    stream->prev = NULL;
    stream->next = NULL;
}

static anytls_session_node_t *take_idle_session(anytls_outbound_impl_t *outbound)
{
    if (outbound == NULL) {
        return NULL;
    }
    anytls_session_node_t *session = outbound->idle_head;
    if (session != NULL) {
        remove_idle_session(session);
    }
    return session;
}

static size_t count_connecting_idle_sessions(
    const anytls_outbound_impl_t *outbound)
{
    size_t count = 0u;
    for (const anytls_session_node_t *session = outbound->sessions;
         session != NULL; session = session->next_all) {
        if (!session->closed && !session->ready &&
            session->active_streams == 0u) {
            count++;
        }
    }
    return count;
}

static void maybe_report_close(anytls_outbound_impl_t *outbound, int status)
{
    if (outbound == NULL || outbound->close_reported ||
        outbound->user_on_close == NULL) {
        return;
    }
    outbound->close_reported = 1;
    outbound->user_on_close(NULL, status, outbound->user_data);
}

static void stream_fail_open(anytls_stream_impl_t *stream, int status)
{
    if (stream == NULL || stream->closed) {
        return;
    }
    if (stream->on_open != NULL) {
        stream->on_open(stream->owner, status, stream->user_data);
    }
}

static void pending_remove(anytls_session_node_t *session,
                           anytls_stream_impl_t *stream)
{
    if (session == NULL || stream == NULL || !stream->opening) {
        return;
    }
    anytls_stream_impl_t **cursor = &session->pending_streams;
    while (*cursor != NULL) {
        if (*cursor == stream) {
            *cursor = stream->pending_next;
            stream->pending_next = NULL;
            stream->opening = 0;
            return;
        }
        cursor = &(*cursor)->pending_next;
    }
    stream->pending_next = NULL;
    stream->opening = 0;
}

static void pending_add(anytls_session_node_t *session,
                        anytls_stream_impl_t *stream)
{
    stream->pending_next = session->pending_streams;
    stream->opening = 1;
    session->pending_streams = stream;
}

static void fail_pending_streams(anytls_session_node_t *session, int status)
{
    while (session != NULL && session->pending_streams != NULL) {
        anytls_stream_impl_t *stream = session->pending_streams;
        session->pending_streams = stream->pending_next;
        stream->pending_next = NULL;
        stream->opening = 0;
        session_release_stream(stream);
        stream_fail_open(stream, status);
    }
}

static int anytls_proxy_stream_write(void *impl,
                                     const uint8_t *data,
                                     size_t len)
{
    anytls_stream_impl_t *stream = (anytls_stream_impl_t *)impl;
    if (stream == NULL || (data == NULL && len > 0u) || stream->closed) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (stream->native == NULL) {
        if (stream->session == NULL) {
            return APROXY_ERR_INVALID_ARGUMENT;
        }
        if (aproxy_size_add_exceeds(
                stream->pending_write.len, len,
                stream->session->outbound->client_config.max_pending_bytes)) {
            return APROXY_ERR_FRAME_TOO_LARGE;
        }
        return aproxy_buffer_append(&stream->pending_write, data, len);
    }
    return anytls_stream_write(stream->native, data, len);
}

static int anytls_proxy_stream_close(void *impl)
{
    anytls_stream_impl_t *stream = (anytls_stream_impl_t *)impl;
    if (stream == NULL || stream->closed) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    stream->closed = 1;
    if (stream->native != NULL) {
        return anytls_stream_close(stream->native);
    }
    if (stream->session != NULL) {
        pending_remove(stream->session, stream);
    }
    session_release_stream(stream);
    if (stream->on_close != NULL) {
        stream->on_close(stream->owner, APROXY_OK, stream->user_data);
    }
    return APROXY_OK;
}

static uint32_t anytls_proxy_stream_id(const void *impl)
{
    const anytls_stream_impl_t *stream = (const anytls_stream_impl_t *)impl;
    return stream == NULL || stream->native == NULL
               ? 0u
               : anytls_stream_id(stream->native);
}

static void *anytls_proxy_stream_native(const void *impl)
{
    const anytls_stream_impl_t *stream = (const anytls_stream_impl_t *)impl;
    return stream == NULL ? NULL : stream->native;
}

static void anytls_proxy_stream_free(void *impl)
{
    anytls_stream_impl_t *stream = (anytls_stream_impl_t *)impl;
    if (stream == NULL) {
        return;
    }
    stream_list_remove(stream);
    stream->owner = NULL;
    stream->on_data = NULL;
    stream->on_open = NULL;
    stream->on_close = NULL;
    stream->user_data = NULL;
    if (stream->opening && stream->session != NULL) {
        pending_remove(stream->session, stream);
    }
    if (stream->native != NULL) {
        (void)anytls_stream_close(stream->native);
    }
    session_release_stream(stream);
    aproxy_buffer_free(&stream->pending_write);
    free(stream);
}

static const aproxy_stream_vtable_t anytls_proxy_stream_vtable = {
    .write = anytls_proxy_stream_write,
    .close = anytls_proxy_stream_close,
    .id = anytls_proxy_stream_id,
    .native = anytls_proxy_stream_native,
    .free = anytls_proxy_stream_free,
};

static void anytls_adapter_on_data(anytls_stream_t *native,
                                   const uint8_t *data,
                                   size_t len,
                                   void *user_data)
{
    (void)native;
    anytls_stream_impl_t *stream = (anytls_stream_impl_t *)user_data;
    if (stream != NULL && stream->on_data != NULL) {
        stream->on_data(stream->owner, data, len, stream->user_data);
    }
}

static void anytls_adapter_on_open(anytls_stream_t *native,
                                   int status,
                                   void *user_data)
{
    (void)native;
    anytls_stream_impl_t *stream = (anytls_stream_impl_t *)user_data;
    if (stream == NULL || stream->closed) {
        return;
    }
    if (status == APROXY_OK && stream->pending_write.len > 0u) {
        status = anytls_stream_write(stream->native,
                                     stream->pending_write.data,
                                     stream->pending_write.len);
        aproxy_buffer_clear(&stream->pending_write);
    }
    if (stream->on_open != NULL) {
        stream->on_open(stream->owner, status, stream->user_data);
    }
}

static void anytls_adapter_on_close(anytls_stream_t *native,
                                    int status,
                                    void *user_data)
{
    (void)native;
    anytls_stream_impl_t *stream = (anytls_stream_impl_t *)user_data;
    if (stream == NULL) {
        return;
    }
    stream->native = NULL;
    stream->closed = 1;
    session_release_stream(stream);
    if (stream->on_close != NULL) {
        stream->on_close(stream->owner, status, stream->user_data);
    }
}

static int bind_stream_to_session(anytls_stream_impl_t *stream,
                                  anytls_session_node_t *session)
{
    stream->session = session;
    return anytls_client_open_stream(session->client, &stream->destination,
                                     anytls_adapter_on_data,
                                     anytls_adapter_on_open,
                                     anytls_adapter_on_close, stream,
                                     &stream->native);
}

static void session_release_stream(anytls_stream_impl_t *stream)
{
    if (stream == NULL || stream->session == NULL ||
        stream->session_released) {
        return;
    }
    anytls_session_node_t *session = stream->session;
    stream->session_released = 1;
    if (session->active_streams > 0u) {
        session->active_streams--;
    }
    if (session->active_streams == 0u && session->ready &&
        !session->closed && !session->outbound->closing) {
        put_idle_session(session);
    }
}

static void put_idle_session(anytls_session_node_t *session)
{
    if (session == NULL || session->closed || !session->ready ||
        session->active_streams != 0u || session->in_idle) {
        return;
    }
    anytls_outbound_impl_t *outbound = session->outbound;
    if (outbound->closing) {
        close_session(session);
        return;
    }
    if (outbound->max_idle_sessions >= 0 &&
        outbound->idle_count >= (size_t)outbound->max_idle_sessions) {
        close_session(session);
        return;
    }

    session->idle_since_ms = outbound_now_ms(outbound);
    session->prev_idle = NULL;
    session->next_idle = outbound->idle_head;
    if (outbound->idle_head != NULL) {
        outbound->idle_head->prev_idle = session;
    } else {
        outbound->idle_tail = session;
    }
    outbound->idle_head = session;
    outbound->idle_count++;
    session->in_idle = 1;
}

static void session_ready_cb(anytls_client_t *client,
                             int status,
                             void *user_data)
{
    anytls_session_node_t *session = (anytls_session_node_t *)user_data;
    anytls_outbound_impl_t *outbound =
        session == NULL ? NULL : session->outbound;
    if (session == NULL || outbound == NULL) {
        return;
    }

    if (status != APROXY_OK) {
        session->closed = 1;
        fail_pending_streams(session, status);
        if (session->report_ready && !outbound->ready_reported &&
            outbound->user_on_ready != NULL) {
            outbound->ready_reported = 1;
            outbound->user_on_ready(client, status, outbound->user_data);
        }
        return;
    }

    session->ready = 1;
    while (session->pending_streams != NULL) {
        anytls_stream_impl_t *stream = session->pending_streams;
        session->pending_streams = stream->pending_next;
        stream->pending_next = NULL;
        stream->opening = 0;
        if (stream->closed) {
            session_release_stream(stream);
            continue;
        }
        const int rc = bind_stream_to_session(stream, session);
        if (rc != APROXY_OK) {
            session_release_stream(stream);
            stream_fail_open(stream, rc);
        }
    }

    if (session->active_streams == 0u) {
        put_idle_session(session);
    }
    if (session->report_ready && !outbound->ready_reported &&
        outbound->user_on_ready != NULL) {
        outbound->ready_reported = 1;
        outbound->user_on_ready(client, APROXY_OK, outbound->user_data);
    }
}

static void session_close_cb(anytls_client_t *client,
                             int status,
                             void *user_data)
{
    (void)client;
    anytls_session_node_t *session = (anytls_session_node_t *)user_data;
    if (session == NULL || session->closed) {
        return;
    }
    session->closed = 1;
    remove_idle_session(session);
    fail_pending_streams(session, status);
    if (session->outbound->closing) {
        maybe_report_close(session->outbound, status);
    }
}

static int create_session(anytls_outbound_impl_t *outbound,
                          size_t active_streams,
                          int report_ready,
                          anytls_session_node_t **out)
{
    if (out == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;
    anytls_session_node_t *session =
        (anytls_session_node_t *)calloc(1u, sizeof(*session));
    if (session == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    session->outbound = outbound;
    session->seq = ++outbound->next_seq;
    session->active_streams = active_streams;
    session->report_ready = report_ready;

    anytls_client_config_t client_config = outbound->client_config;
    client_config.on_ready = session_ready_cb;
    client_config.on_close = session_close_cb;
    client_config.user_data = session;
    int rc = anytls_client_new(&client_config, &session->client);
    if (rc != APROXY_OK) {
        free(session);
        return rc;
    }

    rc = anytls_client_connect(session->client);
    if (rc != APROXY_OK) {
        anytls_client_free(session->client);
        free(session);
        return rc;
    }
    session->next_all = outbound->sessions;
    outbound->sessions = session;
    *out = session;
    return APROXY_OK;
}

static void close_session(anytls_session_node_t *session)
{
    if (session == NULL || session->closed) {
        return;
    }
    session->closed = 1;
    remove_idle_session(session);
    fail_pending_streams(session, APROXY_ERR_INVALID_ARGUMENT);
    anytls_client_close(session->client);
}

static void maintain_min_idle_sessions(anytls_outbound_impl_t *outbound)
{
    if (outbound == NULL || outbound->closing ||
        outbound->min_idle_sessions <= 0) {
        return;
    }
    size_t available = outbound->idle_count +
                       count_connecting_idle_sessions(outbound);
    while (available < (size_t)outbound->min_idle_sessions) {
        anytls_session_node_t *session = NULL;
        const int rc = create_session(outbound, 0u, 0, &session);
        if (rc != APROXY_OK || session == NULL) {
            return;
        }
        available++;
    }
}

static void cleanup_idle_sessions(anytls_outbound_impl_t *outbound)
{
    if (outbound == NULL || outbound->closing) {
        return;
    }
    const uint64_t now = outbound_now_ms(outbound);
    const uint64_t expire_before =
        now > outbound->idle_timeout_ms ? now - outbound->idle_timeout_ms : 0u;
    size_t kept = 0u;

    anytls_session_node_t *session = outbound->idle_head;
    while (session != NULL) {
        anytls_session_node_t *next = session->next_idle;
        if (session->idle_since_ms >= expire_before) {
            kept++;
            session = next;
            continue;
        }
        if (kept < (size_t)outbound->min_idle_sessions) {
            session->idle_since_ms = now;
            kept++;
            session = next;
            continue;
        }
        close_session(session);
        session = next;
    }
}

static void idle_timer_cb(uv_timer_t *timer)
{
    anytls_outbound_impl_t *outbound =
        (anytls_outbound_impl_t *)timer->data;
    cleanup_idle_sessions(outbound);
    maintain_min_idle_sessions(outbound);
}

static void idle_timer_close_cb(uv_handle_t *handle)
{
    anytls_outbound_impl_t *outbound =
        (anytls_outbound_impl_t *)handle->data;
    if (outbound != NULL) {
        outbound->idle_timer_closed = 1;
        outbound_maybe_destroy(outbound);
    }
}

static int start_idle_timer(anytls_outbound_impl_t *outbound)
{
    if (outbound == NULL || outbound->idle_timer_initialized) {
        return APROXY_OK;
    }
    const int init_rc =
        uv_timer_init(outbound->client_config.loop, &outbound->idle_timer);
    if (init_rc != 0) {
        return init_rc;
    }
    outbound->idle_timer_initialized = 1;
    outbound->idle_timer_closed = 0;
    outbound->idle_timer.data = outbound;
    const int start_rc = uv_timer_start(&outbound->idle_timer, idle_timer_cb,
                                        outbound->idle_check_ms,
                                        outbound->idle_check_ms);
    return start_rc == 0 ? APROXY_OK : start_rc;
}

static int start_pending_stream(anytls_outbound_impl_t *outbound,
                                anytls_stream_impl_t *stream)
{
    anytls_session_node_t *session = NULL;
    int rc = create_session(outbound, 1u, 0, &session);
    if (rc != APROXY_OK) {
        return rc;
    }
    stream->session = session;
    pending_add(session, stream);
    return APROXY_OK;
}

static int create_proxy_stream(anytls_outbound_impl_t *outbound,
                               const aproxy_addr_t *destination,
                               aproxy_stream_data_cb on_data,
                               aproxy_stream_event_cb on_open,
                               aproxy_stream_event_cb on_close,
                               void *user_data,
                               anytls_stream_impl_t **stream_out,
                               aproxy_stream_t **out)
{
    anytls_stream_impl_t *stream =
        (anytls_stream_impl_t *)calloc(1u, sizeof(*stream));
    if (stream == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    stream->outbound = outbound;
    stream->destination = *destination;
    stream->on_data = on_data;
    stream->on_open = on_open;
    stream->on_close = on_close;
    stream->user_data = user_data;
    aproxy_buffer_init(&stream->pending_write);

    int rc = aproxy_stream_new(&anytls_proxy_stream_vtable, stream,
                               &stream->owner);
    if (rc != APROXY_OK) {
        aproxy_buffer_free(&stream->pending_write);
        free(stream);
        return rc;
    }
    stream_list_add(stream);
    *stream_out = stream;
    *out = stream->owner;
    return APROXY_OK;
}

static int anytls_outbound_connect_impl(void *impl)
{
    anytls_outbound_impl_t *outbound = (anytls_outbound_impl_t *)impl;
    if (outbound == NULL) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    if (outbound->connected) {
        return APROXY_OK;
    }
    outbound->connected = 1;

    int rc = start_idle_timer(outbound);
    if (rc != APROXY_OK) {
        return rc;
    }
    anytls_session_node_t *session = NULL;
    rc = create_session(outbound, 0u, 1, &session);
    if (rc != APROXY_OK) {
        return rc;
    }
    maintain_min_idle_sessions(outbound);
    return APROXY_OK;
}

static int anytls_outbound_open_stream_impl(void *impl,
                                            const aproxy_addr_t *destination,
                                            aproxy_stream_data_cb on_data,
                                            aproxy_stream_event_cb on_open,
                                            aproxy_stream_event_cb on_close,
                                            void *user_data,
                                            aproxy_stream_t **out)
{
    anytls_outbound_impl_t *outbound = (anytls_outbound_impl_t *)impl;
    if (outbound == NULL || destination == NULL || out == NULL ||
        outbound->closing) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    anytls_stream_impl_t *stream = NULL;
    int rc = create_proxy_stream(outbound, destination, on_data, on_open, on_close,
                                 user_data, &stream, out);
    if (rc != APROXY_OK) {
        return rc;
    }

    anytls_session_node_t *session = take_idle_session(outbound);
    if (session != NULL) {
        session->active_streams++;
        stream->session = session;
        rc = bind_stream_to_session(stream, session);
        if (rc == APROXY_OK) {
            return APROXY_OK;
        }
        session_release_stream(stream);
        close_session(session);
    }

    rc = start_pending_stream(outbound, stream);
    if (rc != APROXY_OK) {
        aproxy_stream_free(*out);
        *out = NULL;
        return rc;
    }
    return APROXY_OK;
}

static void anytls_outbound_close_impl(void *impl)
{
    anytls_outbound_impl_t *outbound = (anytls_outbound_impl_t *)impl;
    if (outbound == NULL || outbound->closing) {
        return;
    }
    outbound->closing = 1;
    if (outbound->idle_timer_initialized &&
        !uv_is_closing((uv_handle_t *)&outbound->idle_timer)) {
        uv_timer_stop(&outbound->idle_timer);
        uv_close((uv_handle_t *)&outbound->idle_timer,
                 idle_timer_close_cb);
    }
    for (anytls_session_node_t *session = outbound->sessions;
         session != NULL; session = session->next_all) {
        close_session(session);
    }
}

static void free_sessions(anytls_outbound_impl_t *outbound)
{
    anytls_session_node_t *session = outbound->sessions;
    while (session != NULL) {
        anytls_session_node_t *next = session->next_all;
        fail_pending_streams(session, APROXY_ERR_INVALID_ARGUMENT);
        anytls_client_free(session->client);
        free(session);
        session = next;
    }
    outbound->sessions = NULL;
    outbound->idle_head = NULL;
    outbound->idle_tail = NULL;
    outbound->idle_count = 0u;
}

static void outbound_destroy(anytls_outbound_impl_t *outbound)
{
    if (outbound->owns_padding_store) {
        anytls_padding_store_free(outbound->padding_store);
    }
    free((char *)outbound->client_config.server_host);
    free((char *)outbound->client_config.server_port);
    free((char *)outbound->client_config.sni);
    free((char *)outbound->client_config.password);
    free((char *)outbound->client_config.alpn);
    free((uint8_t *)outbound->client_config.ech.config_list);
    aproxy_tls_context_free(outbound->tls_context);
    free(outbound->tag);
    free(outbound);
}

static void outbound_maybe_destroy(anytls_outbound_impl_t *outbound)
{
    if (outbound != NULL && outbound->free_pending &&
        outbound->idle_timer_closed) {
        outbound_destroy(outbound);
    }
}

static void anytls_outbound_free_impl(void *impl)
{
    anytls_outbound_impl_t *outbound = (anytls_outbound_impl_t *)impl;
    if (outbound == NULL || outbound->free_pending) {
        return;
    }
    outbound->free_pending = 1;
    anytls_outbound_close_impl(outbound);
    while (outbound->streams != NULL) {
        anytls_stream_impl_t *stream = outbound->streams;
        if (stream->owner != NULL) {
            aproxy_stream_free(stream->owner);
        } else {
            anytls_proxy_stream_free(stream);
        }
    }
    free_sessions(outbound);
    outbound_maybe_destroy(outbound);
}

static const aproxy_outbound_vtable_t anytls_outbound_vtable = {
    .connect = anytls_outbound_connect_impl,
    .open_stream = anytls_outbound_open_stream_impl,
    .close = anytls_outbound_close_impl,
    .free = anytls_outbound_free_impl,
};

static int copy_client_config(anytls_outbound_impl_t *impl,
                              const anytls_client_config_t *config)
{
    if ((config->ech.config_list == NULL) !=
        (config->ech.config_list_len == 0u)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    impl->client_config = *config;
    impl->user_on_ready = config->on_ready;
    impl->user_on_close = config->on_close;
    impl->user_data = config->user_data;
    impl->client_config.on_ready = NULL;
    impl->client_config.on_close = NULL;
    impl->client_config.user_data = NULL;
    impl->client_config.max_pending_bytes =
        aproxy_stream_pending_limit(config->max_pending_bytes);

    impl->client_config.server_host = copy_string(config->server_host);
    impl->client_config.server_port = copy_string(config->server_port);
    impl->client_config.sni = copy_string(config->sni);
    impl->client_config.password = copy_string(config->password);
    impl->client_config.alpn = copy_string(config->alpn);
    impl->client_config.ech.config_list = NULL;
    if (config->ech.config_list_len > 0u) {
        uint8_t *ech_config =
            (uint8_t *)malloc(config->ech.config_list_len);
        if (ech_config == NULL) {
            return APROXY_ERR_NO_MEMORY;
        }
        memcpy(ech_config, config->ech.config_list,
               config->ech.config_list_len);
        impl->client_config.ech.config_list = ech_config;
    }
    if (impl->client_config.server_host == NULL ||
        impl->client_config.server_port == NULL ||
        impl->client_config.password == NULL ||
        (config->sni != NULL && impl->client_config.sni == NULL) ||
        (config->alpn != NULL && impl->client_config.alpn == NULL)) {
        return APROXY_ERR_NO_MEMORY;
    }
    return APROXY_OK;
}

int anytls_outbound_new(const anytls_outbound_config_t *config,
                        aproxy_outbound_t **out)
{
    if (config == NULL || out == NULL ||
        (config->uot_version != APROXY_UOT_VERSION_DEFAULT &&
         config->uot_version != APROXY_UOT_VERSION_1 &&
         config->uot_version != APROXY_UOT_VERSION_2)) {
        return APROXY_ERR_INVALID_ARGUMENT;
    }
    *out = NULL;

    anytls_outbound_impl_t *impl =
        (anytls_outbound_impl_t *)calloc(1u, sizeof(*impl));
    if (impl == NULL) {
        return APROXY_ERR_NO_MEMORY;
    }
    impl->idle_timer_closed = 1;
    impl->tag = copy_string(config->tag != NULL ? config->tag : "anytls");
    if (impl->tag == NULL) {
        anytls_outbound_free_impl(impl);
        return APROXY_ERR_NO_MEMORY;
    }

    int rc = copy_client_config(impl, &config->client);
    if (rc != APROXY_OK) {
        anytls_outbound_free_impl(impl);
        return rc;
    }
    if (config->client.tls_context != NULL) {
        impl->tls_context = config->client.tls_context;
        aproxy_tls_context_retain(impl->tls_context);
    } else {
        rc = aproxy_tls_context_new(config->client.insecure_skip_verify,
                                    &impl->tls_context);
        if (rc != APROXY_OK) {
            anytls_outbound_free_impl(impl);
            return rc;
        }
    }
    impl->client_config.tls_context = impl->tls_context;
    if (config->client.padding_store != NULL) {
        impl->padding_store = config->client.padding_store;
    } else {
        rc = anytls_padding_store_new_default(&impl->padding_store);
        if (rc != APROXY_OK) {
            anytls_outbound_free_impl(impl);
            return rc;
        }
        impl->owns_padding_store = 1;
    }
    impl->client_config.padding_store = impl->padding_store;

    impl->idle_check_ms =
        config->idle_session_check_interval_ms <= 5000
            ? ANYTLS_DEFAULT_IDLE_CHECK_MS
            : (uint64_t)config->idle_session_check_interval_ms;
    impl->idle_timeout_ms =
        config->idle_session_timeout_ms <= 5000
            ? ANYTLS_DEFAULT_IDLE_TIMEOUT_MS
            : (uint64_t)config->idle_session_timeout_ms;
    impl->min_idle_sessions = config->min_idle_sessions < 0
                                  ? 0
                                  : config->min_idle_sessions;
    impl->max_idle_sessions = config->max_idle_sessions <= 0
                                  ? ANYTLS_DEFAULT_MAX_IDLE_SESSIONS
                                  : config->max_idle_sessions;
    if (impl->max_idle_sessions < impl->min_idle_sessions) {
        impl->max_idle_sessions = impl->min_idle_sessions;
    }

    aproxy_outbound_t *outbound =
        (aproxy_outbound_t *)calloc(1u, sizeof(*outbound));
    if (outbound == NULL) {
        anytls_outbound_free_impl(impl);
        return APROXY_ERR_NO_MEMORY;
    }
    outbound->tag = impl->tag;
    outbound->vtable = &anytls_outbound_vtable;
    outbound->impl = impl;
    outbound->udp_transport = APROXY_OUTBOUND_UDP_UOT;
    outbound->uot_version =
        config->uot_version == APROXY_UOT_VERSION_DEFAULT
            ? APROXY_UOT_VERSION_2
            : config->uot_version;
    *out = outbound;
    return APROXY_OK;
}
