#include "transport/session/pool.h"
#include <assert.h>
#include <string.h>

typedef struct session session_t;
typedef struct child child_t;
enum { REQUEST_CONTROL, REQUEST_OPEN, REQUEST_DATA, REQUEST_END };
typedef struct request {
    struct request *next;
    child_t *child;
    solaris_session_batch_t batch;
    solaris_slice_t plain;
    solaris_io_done_fn done;
    void *context;
    size_t part;
    int kind;
} request_t;
struct solaris_session_pool {
    solaris_scope_t scope;
    solaris_session_pool_options_t options;
    session_t *sessions;
    solaris_deadline_t *idle_check;
    size_t count;
    int retired, accepted;
};
struct session {
    session_t *next;
    solaris_session_pool_t *pool;
    solaris_scope_t scope;
    solaris_deferred_t pump;
    solaris_deadline_t *idle;
    solaris_stream_t *carrier;
    void *codec;
    child_t *children;
    size_t child_count, pending_bytes, pending_requests, control_requests;
    request_t *head, *tail;
    uint8_t *receive;
    size_t begin, end, capacity;
    solaris_session_event_t event;
    int event_pending;
    uint32_t next_id;
    uint64_t idle_expires;
    solaris_status_t status;
    int connected, writing, carrier_eof, close_requested, linked, idle_tracked;
};
struct child {
    child_t *next;
    session_t *session;
    solaris_stream_t stream;
    solaris_scope_t scope;
    solaris_deadline_t *deadline;
    uint64_t expires;
    solaris_stream_callbacks_t callbacks;
    void *context;
    solaris_io_snapshot_t stats;
    solaris_dialer_options_t options;
    int wait_ack;
    uint32_t id;
    size_t requests;
    solaris_status_t status;
    int accepted, reading, opened, ready, sent_open, closing, remote_end, end_queued, writable;
};
static void schedule(session_t *s);
static void fail(session_t *s, solaris_status_t status);
static void child_close(child_t *c, solaris_status_t status, int remote);
static void collect_idle(session_t *s);
static void check_idle_later(solaris_session_pool_t *pool);

void solaris_session_batch_clear(solaris_session_batch_t *batch)
{
    for (size_t i = 0u; i < batch->count; ++i) solaris_buffer_release(batch->buffers[i]);
    memset(batch, 0, sizeof(*batch));
}
static void event_clear(solaris_session_event_t *event)
{ solaris_buffer_release(event->data); solaris_session_batch_clear(&event->reply); memset(event, 0, sizeof(*event)); }
static void enqueue(session_t *s, request_t *r)
{
    if (r->child != NULL) { r->child->requests++; solaris_scope_retain(&r->child->scope); }
    if (r->kind != REQUEST_DATA) s->control_requests++;
    if (s->tail != NULL) s->tail->next = r; else s->head = r;
    s->tail = r;
}
static request_t *new_request(session_t *s, child_t *c, int kind)
{
    request_t *r = solaris_memory_allocate(solaris_executor_budget(s->scope.owner), sizeof(*r));
    if (r != NULL) { memset(r, 0, sizeof(*r)); r->child = c; r->kind = kind; }
    return r;
}
static void complete(session_t *s, solaris_status_t status)
{
    request_t *r = s->head; child_t *c = r->child;
    s->head = r->next; if (s->head == NULL) s->tail = NULL;
    if (r->kind != REQUEST_DATA) s->control_requests--;
    if (c != NULL) {
        if (c->closing && r->kind == REQUEST_DATA) status = c->status == SOLARIS_OK ? SOLARIS_ECANCELLED : c->status;
        if (r->kind == REQUEST_OPEN && status == SOLARIS_OK) {
            c->sent_open = 1; if (!c->wait_ack) c->ready = 1;
        }
        if (r->kind == REQUEST_DATA) {
            s->pending_bytes -= r->plain.length; s->pending_requests--;
            c->stats.pending_bytes -= r->plain.length; c->stats.pending_requests--;
            if (status == SOLARIS_OK) c->stats.bytes_written += r->plain.length;
            r->done(r->context, status);
        }
        c->requests--; solaris_scope_release(&c->scope);
    }
    solaris_session_batch_clear(&r->batch); solaris_buffer_release(r->plain.buffer); solaris_memory_free(r);
}
static void child_destroyed(void *context)
{
    child_t *c = context; session_t *s = c->session;
    if (c->accepted) c->callbacks.on_close(c->context, &c->stream, c->status);
    solaris_memory_free(c); solaris_scope_release(&s->scope);
}
static void child_cancelled(void *context)
{
    child_t *c = context;
    if (!c->closing) { c->closing = 1; c->status = SOLARIS_ECANCELLED; }
    if (c->deadline != NULL) solaris_deadline_cancel(c->deadline);
    schedule(c->session);
}
static void child_close(child_t *c, solaris_status_t status, int remote)
{
    if (c->closing) return;
    c->closing = 1; c->status = status; c->remote_end = remote;
    solaris_scope_cancel(&c->scope);
}
static void open_expired(child_t *c)
{
    if (c->wait_ack && c->session->pool->options.ack_timeout_fails_session)
        fail(c->session, SOLARIS_ETIMEDOUT);
    child_close(c, SOLARIS_ETIMEDOUT, 0);
}
static void expired(void *context, solaris_status_t status)
{
    child_t *c = context; c->deadline = NULL;
    if (status == SOLARIS_OK && !c->opened && !c->closing) open_expired(c);
    solaris_scope_release(&c->scope);
}
static void idle_expired(void *context, solaris_status_t status)
{
    session_t *s = context; s->idle = NULL;
    if (status == SOLARIS_OK && s->children == NULL && s->head == NULL) fail(s, SOLARIS_OK);
    else collect_idle(s);
    solaris_scope_release(&s->scope);
}
static void cancelled(void *context)
{
    session_t *s = context;
    if (!s->close_requested) { s->close_requested = 1; s->status = SOLARIS_ECANCELLED; }
    if (s->idle != NULL) solaris_deadline_cancel(s->idle);
    if (s->carrier != NULL) (void)solaris_stream_close(s->carrier);
    schedule(s);
}
static void destroyed(void *context)
{
    session_t *s = context; solaris_session_pool_t *pool = s->pool;
    assert(s->children == NULL && s->head == NULL && s->carrier == NULL);
    if (s->linked) {
        session_t **p = &pool->sessions; while (*p != s) p = &(*p)->next;
        *p = s->next; pool->count--;
    }
    if (s->codec != NULL) pool->options.codec->destroy(s->codec);
    event_clear(&s->event); solaris_memory_free(s->receive); solaris_memory_free(s);
    if (pool->retired && pool->count == 0u) solaris_scope_cancel(&pool->scope);
    solaris_scope_release(&pool->scope);
}
static void fail(session_t *s, solaris_status_t status)
{
    if (s->close_requested) return;
    s->close_requested = 1; s->status = status; solaris_scope_cancel(&s->scope);
}
static void carrier_opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    (void)stream; session_t *s = context;
    if (s->close_requested) return;
    if (status != SOLARIS_OK) fail(s, status);
    else { s->connected = 1; schedule(s); }
}
static void carrier_data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    session_t *s = context;
    if (s->close_requested) return;
    size_t n = solaris_buffer_length(buffer), remaining = s->end - s->begin;
    if (n > 65536u || n > s->capacity - remaining) { fail(s, SOLARIS_EMSGSIZE); return; }
    if (n > s->capacity - s->end) { memmove(s->receive, s->receive + s->begin, remaining); s->begin = 0u; s->end = remaining; }
    memcpy(s->receive + s->end, solaris_buffer_data(buffer), n); s->end += n;
    (void)solaris_stream_set_reading(stream, 0); schedule(s);
}
static void carrier_eof(void *context, solaris_stream_t *stream)
{ (void)stream; session_t *s = context; s->carrier_eof = 1; if (!s->close_requested) schedule(s); }
static void carrier_writable(void *context, solaris_stream_t *stream)
{ (void)stream; session_t *s = context; if (!s->close_requested) schedule(s); }
static void carrier_closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    (void)stream; session_t *s = context; s->carrier = NULL;
    if (!s->close_requested) {
        if (status == SOLARIS_OK && s->carrier_eof) schedule(s);
        else fail(s, status == SOLARIS_OK ? SOLARIS_EIO : status);
    }
    solaris_scope_release(&s->scope);
}
static const solaris_stream_callbacks_t carrier_callbacks = {carrier_opened, carrier_data, carrier_eof, carrier_writable, carrier_closed};
static void written(void *context, solaris_status_t status)
{
    session_t *s = context; s->writing = 0;
    if (status != SOLARIS_OK) fail(s, status);
    if (!s->close_requested) {
        request_t *r = s->head; r->part++;
        if (r->part == r->batch.count) complete(s, SOLARIS_OK);
    }
    schedule(s); solaris_scope_release(&s->scope);
}
static child_t *find_child(session_t *s, uint32_t id)
{ for (child_t *c = s->children; c != NULL; c = c->next) if (c->id == id) return c; return NULL; }
static void notify_open(child_t *c)
{
    if (c->opened || c->closing || !c->ready || !c->sent_open) return;
    if (solaris_executor_now_ns(c->scope.owner) >= c->expires) { open_expired(c); return; }
    c->opened = 1;
    if (c->deadline != NULL) solaris_deadline_cancel(c->deadline);
    c->callbacks.on_open(c->context, &c->stream, SOLARIS_OK);
}
static void pump(void *context)
{
    session_t *s = context; const solaris_session_codec_t *codec = s->pool->options.codec;
    unsigned int steps = 0u; int needs_input = s->begin == s->end;
    while (!s->close_requested && steps++ < 32u) {
        if (!s->event_pending) {
            if (s->begin == s->end) { needs_input = 1; break; }
            size_t used = 0u;
            solaris_status_t rc = codec->decode(s->codec, s->receive + s->begin, s->end - s->begin, &used, &s->event);
            if (rc == SOLARIS_EAGAIN) { needs_input = 1; if (s->end - s->begin >= codec->frame_limit) fail(s, SOLARIS_EMSGSIZE); break; }
            if (rc != SOLARIS_OK || used == 0u || used > s->end - s->begin) { fail(s, rc == SOLARIS_OK ? SOLARIS_EIO : rc); break; }
            s->begin += used; s->event_pending = 1;
        }
        child_t *c = find_child(s, s->event.id);
        if (c != NULL && !c->opened && !c->closing && solaris_executor_now_ns(c->scope.owner) >= c->expires)
            open_expired(c);
        if (c != NULL && !c->closing) {
            if (s->event.kind == SOLARIS_SESSION_READY) {
                if (s->event.status != SOLARIS_OK) child_close(c, s->event.status, 1);
                else { c->ready = 1; notify_open(c); }
            } else if (s->event.kind == SOLARIS_SESSION_DATA) {
                notify_open(c);
                if (!c->closing && (!c->reading || !c->opened)) { needs_input = 0; break; }
                if (!c->closing && s->event.data != NULL) {
                    solaris_buffer_publish(s->event.data); c->stats.bytes_read += solaris_buffer_length(s->event.data);
                    c->callbacks.on_data(c->context, &c->stream, s->event.data);
                }
            } else if (s->event.kind == SOLARIS_SESSION_END) {
                if (c->opened && !c->reading) { needs_input = 0; break; }
                c->stats.read_eof = 1;
                child_close(c, c->opened ? s->event.status : SOLARIS_EIO, 1);
                if (c->opened && c->callbacks.on_eof != NULL) c->callbacks.on_eof(c->context, &c->stream);
            }
        }
        if (s->event.reply.count != 0u) {
            request_t *r = s->control_requests < 64u ? new_request(s, NULL, REQUEST_CONTROL) : NULL;
            if (r == NULL) { fail(s, SOLARIS_ENOMEM); break; }
            r->batch = s->event.reply; memset(&s->event.reply, 0, sizeof(s->event.reply)); enqueue(s, r);
        }
        event_clear(&s->event); s->event_pending = 0;
    }
    if (!s->close_requested && s->carrier_eof && needs_input && !s->event_pending) fail(s, SOLARIS_EIO);
    for (child_t *c = s->children; c != NULL; c = c->next) {
        if (s->close_requested) child_close(c, s->status == SOLARIS_OK ? SOLARIS_ECANCELLED : s->status, 1);
        if (!c->opened && !c->closing && solaris_executor_now_ns(s->scope.owner) >= c->expires) open_expired(c);
        notify_open(c);
        if (c->closing) {
            if (!c->opened) { c->opened = 1; if (c->accepted) c->callbacks.on_open(c->context, &c->stream, c->status == SOLARIS_OK ? SOLARIS_ECANCELLED : c->status); }
            if (!c->end_queued) {
                c->end_queued = 1;
                if (!s->close_requested && !c->remote_end) {
                    request_t *r = new_request(s, c, REQUEST_END);
                    solaris_status_t rc = r == NULL ? SOLARIS_ENOMEM : codec->end(s->codec, c->id, &r->batch);
                    if (rc != SOLARIS_OK) { if (r != NULL) { solaris_session_batch_clear(&r->batch); solaris_memory_free(r); } fail(s, rc); }
                    else enqueue(s, r);
                }
            }
        }
    }
    /* Leave the in-flight request alive until the carrier's completion. */
    if (!s->writing) {
        while (s->head != NULL && (s->close_requested ||
            (s->head->kind == REQUEST_DATA && s->head->child->closing && s->head->part == 0u)))
            complete(s, s->status == SOLARIS_OK ? SOLARIS_ECANCELLED : s->status);
        if (!s->close_requested && s->connected && s->carrier != NULL && s->head != NULL) {
            request_t *r = s->head;
            if (r->part == r->batch.count) { complete(s, SOLARIS_OK); schedule(s); }
            else {
                solaris_buffer_t *b = r->batch.buffers[r->part]; solaris_slice_t slice = {b, 0u, solaris_buffer_length(b)};
                solaris_status_t rc = solaris_stream_write(s->carrier, &slice, written, s);
                if (rc == SOLARIS_OK) { s->writing = 1; solaris_scope_retain(&s->scope); }
                else if (rc != SOLARIS_EAGAIN) fail(s, rc);
            }
        }
    }
    child_t **p = &s->children;
    while (*p != NULL) {
        child_t *c = *p;
        if (c->closing && c->end_queued && c->requests == 0u) {
            *p = c->next; s->child_count--; solaris_scope_release(&c->scope);
        } else {
            if (c->writable && !c->closing && s->pending_requests < s->pool->options.session_pending_requests &&
                s->pending_bytes < s->pool->options.session_pending_bytes &&
                c->stats.pending_requests < c->options.pending_request_limit && c->stats.pending_bytes < c->options.pending_byte_limit) {
                c->writable = 0; if (c->callbacks.on_writable != NULL) c->callbacks.on_writable(c->context, &c->stream);
            }
            p = &c->next;
        }
    }
    if (!s->close_requested) {
        if (s->begin == s->end) s->begin = s->end = 0u;
        if (s->carrier != NULL && !s->carrier_eof) {
            solaris_status_t rc = solaris_stream_set_reading(s->carrier, needs_input && !s->event_pending);
            if (rc != SOLARIS_OK) fail(s, rc);
        }
        if (steps > 32u) schedule(s);
        collect_idle(s);
    }
    solaris_scope_release(&s->scope);
}
static void schedule(session_t *s)
{
    if (s->pump.queued) return;
    solaris_scope_retain(&s->scope);
    solaris_status_t rc = solaris_executor_defer(s->scope.owner, &s->pump); assert(rc == SOLARIS_OK); (void)rc;
}
static void collect_idle(session_t *s)
{
    if (s->children != NULL || s->head != NULL || s->writing || s->close_requested) return;
    if (s->pool->retired || s->next_id == UINT32_MAX) { fail(s, SOLARIS_OK); return; }
    if (s->pool->options.idle_check_interval_ms != 0u) {
        if (!s->idle_tracked) {
            uint64_t now = solaris_executor_now_ns(s->scope.owner), duration = s->pool->options.idle_timeout_ms * UINT64_C(1000000);
            if (duration > UINT64_MAX - now) { fail(s, SOLARIS_EOVERFLOW); return; }
            s->idle_tracked = 1; s->idle_expires = now + duration;
        }
        check_idle_later(s->pool); return;
    }
    if (s->idle == NULL) {
        uint64_t now = solaris_executor_now_ns(s->scope.owner);
        uint64_t duration = s->pool->options.idle_timeout_ms * UINT64_C(1000000);
        if (duration > UINT64_MAX - now) { fail(s, SOLARIS_EOVERFLOW); return; }
        s->idle_expires = now + duration;
        solaris_scope_retain(&s->scope);
        solaris_status_t rc = solaris_deadline_start(s->scope.owner, s->pool->options.idle_timeout_ms, idle_expired, s, &s->idle);
        if (rc != SOLARIS_OK) { solaris_scope_release(&s->scope); fail(s, rc); }
    }
}
static void idle_checked(void *context, solaris_status_t status)
{
    solaris_session_pool_t *pool = context; pool->idle_check = NULL;
    if (status == SOLARIS_OK && !pool->retired) {
        uint64_t now = solaris_executor_now_ns(pool->scope.owner);
        uint64_t duration = pool->options.idle_timeout_ms * UINT64_C(1000000);
        size_t retained = 0u;
        /* New sessions are inserted at the head, so this is descending Seq. */
        for (session_t *s = pool->sessions; s != NULL; s = s->next) {
            if (s->close_requested || !s->idle_tracked || s->children != NULL || s->head != NULL || s->writing) continue;
            if (now >= s->idle_expires) {
                if (retained >= pool->options.min_idle_sessions) { fail(s, SOLARIS_OK); continue; }
                if (duration > UINT64_MAX - now) { fail(s, SOLARIS_EOVERFLOW); continue; }
                s->idle_expires = now + duration;
            }
            retained++;
        }
        check_idle_later(pool);
    }
    solaris_scope_release(&pool->scope);
}
static void check_idle_later(solaris_session_pool_t *pool)
{
    if (pool->retired || pool->idle_check != NULL || pool->options.idle_check_interval_ms == 0u) return;
    session_t *idle = pool->sessions;
    while (idle != NULL && (idle->close_requested || !idle->idle_tracked)) idle = idle->next;
    if (idle == NULL) return;
    solaris_scope_retain(&pool->scope);
    solaris_status_t rc = solaris_deadline_start(pool->scope.owner, pool->options.idle_check_interval_ms, idle_checked, pool, &pool->idle_check);
    if (rc != SOLARIS_OK) {
        solaris_scope_release(&pool->scope);
        for (session_t *s = pool->sessions; s != NULL; s = s->next)
            if (s->idle_tracked && !s->close_requested) fail(s, rc);
    }
}
static solaris_status_t child_write(void *state, const solaris_slice_t *data, solaris_io_done_fn done, void *context)
{
    child_t *c = state; session_t *s = c->session; const solaris_dialer_options_t *limits = &c->options;
    if (c->closing || s->close_requested || !solaris_executor_accepting(c->scope.owner)) return SOLARIS_ECLOSED;
    if (!c->opened) return SOLARIS_EBUSY;
    if (data->length > limits->pending_byte_limit) return SOLARIS_EMSGSIZE;
    if (c->stats.pending_requests >= limits->pending_request_limit || c->stats.pending_bytes > limits->pending_byte_limit - data->length ||
        s->pending_requests >= s->pool->options.session_pending_requests || s->pending_bytes > s->pool->options.session_pending_bytes - data->length) {
        c->writable = 1; return SOLARIS_EAGAIN;
    }
    request_t *r = new_request(s, c, REQUEST_DATA); if (r == NULL) return SOLARIS_ENOMEM;
    solaris_status_t rc = s->pool->options.codec->write(s->codec, c->id, data, &r->batch);
    if (rc != SOLARIS_OK) { solaris_session_batch_clear(&r->batch); solaris_memory_free(r); return rc; }
    r->plain = *data; solaris_buffer_retain(data->buffer); r->done = done; r->context = context;
    s->pending_requests++; s->pending_bytes += data->length;
    c->stats.pending_requests++; c->stats.pending_bytes += data->length;
    enqueue(s, r); schedule(s); return SOLARIS_OK;
}
static solaris_status_t child_shutdown(void *state, solaris_io_done_fn done, void *context)
{ (void)state; (void)done; (void)context; return SOLARIS_ENOTSUP; }
static solaris_status_t child_reading(void *state, int enabled)
{ child_t *c = state; if (c->closing) return SOLARIS_ECLOSED; c->reading = enabled; schedule(c->session); return SOLARIS_OK; }
static solaris_status_t child_end(void *state) { child_close(state, SOLARIS_OK, 0); return SOLARIS_OK; }
static solaris_status_t child_snapshot(void *state, solaris_io_snapshot_t *out) { *out = ((child_t *)state)->stats; return SOLARIS_OK; }
static const solaris_stream_ops_t child_ops = {child_write, child_shutdown, child_reading, child_end, child_snapshot, NULL};

static solaris_status_t new_session(solaris_session_pool_t *pool, session_t **out)
{
    solaris_executor_t *owner = pool->scope.owner;
    session_t *s = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*s));
    if (s == NULL) return SOLARIS_ENOMEM;
    memset(s, 0, sizeof(*s)); s->pool = pool; s->pump.run = pump; s->pump.context = s;
    s->capacity = pool->options.codec->frame_limit + 65536u;
    s->receive = solaris_memory_allocate(solaris_executor_budget(owner), s->capacity);
    solaris_status_t rc = s->receive == NULL ? SOLARIS_ENOMEM : pool->options.codec->create(pool->options.parameters, solaris_executor_budget(owner), &s->codec);
    if (rc == SOLARIS_OK) rc = solaris_scope_init(&s->scope, owner, cancelled, destroyed, s);
    if (rc != SOLARIS_OK) {
        if (s->codec != NULL) pool->options.codec->destroy(s->codec);
        solaris_memory_free(s->receive); solaris_memory_free(s); return rc;
    }
    solaris_scope_retain(&pool->scope);
    s->linked = 1; s->next = pool->sessions; pool->sessions = s; pool->count++;
    request_t *r = new_request(s, NULL, REQUEST_CONTROL);
    rc = r == NULL ? SOLARIS_ENOMEM : pool->options.codec->start(s->codec, &r->batch);
    if (rc != SOLARIS_OK) {
        if (r != NULL) { solaris_session_batch_clear(&r->batch); solaris_memory_free(r); }
        fail(s, rc); return rc;
    }
    enqueue(s, r);
    solaris_dialer_options_t wire = pool->options.dialer;
    if (wire.pending_byte_limit < 1024u * 1024u) wire.pending_byte_limit = 1024u * 1024u;
    wire.pending_request_limit = 1u; wire.read_chunk_size = 16384u;
    rc = solaris_carrier_open(&pool->options.carrier, owner, &wire, &pool->options.peer, &carrier_callbacks, s, &s->carrier);
    if (rc != SOLARIS_OK) { fail(s, rc); return rc; }
    solaris_scope_retain(&s->scope); *out = s; return SOLARIS_OK;
}
solaris_status_t solaris_session_pool_open(solaris_session_pool_t *pool, const solaris_dialer_options_t *options, const solaris_address_t *peer,
    const solaris_stream_callbacks_t *callbacks, void *context, solaris_stream_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (pool == NULL || peer == NULL || callbacks == NULL || callbacks->on_open == NULL || callbacks->on_data == NULL || callbacks->on_close == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(pool->scope.owner)) return SOLARIS_ETHREAD;
    if (pool->retired || !solaris_executor_accepting(pool->scope.owner)) return SOLARIS_ECLOSED;
    solaris_dialer_options_t limits;
    solaris_status_t normalized = solaris_dialer_options_normalize(options == NULL ? &pool->options.dialer : options, &limits);
    if (normalized != SOLARIS_OK) return normalized;
    if (limits.pending_byte_limit > pool->options.session_pending_bytes) return SOLARIS_EMSGSIZE;
    for (session_t *candidate = pool->options.idle_check_interval_ms == 0u ? pool->sessions : NULL; candidate != NULL; candidate = candidate->next)
        if (!candidate->close_requested && candidate->children == NULL && candidate->idle != NULL &&
            solaris_executor_now_ns(pool->scope.owner) >= candidate->idle_expires) fail(candidate, SOLARIS_OK);
    session_t *s = pool->sessions;
    while (s != NULL && (s->close_requested || s->child_count >= pool->options.streams_per_session || s->next_id == UINT32_MAX ||
        (s->child_count == 0u && s->head != NULL))) s = s->next;
    if (s == NULL) {
        if (pool->count >= pool->options.session_limit) return SOLARIS_EBUSY;
        solaris_status_t rc = new_session(pool, &s); if (rc != SOLARIS_OK) return rc;
    }
    child_t *c = solaris_memory_allocate(solaris_executor_budget(pool->scope.owner), sizeof(*c));
    if (c == NULL) { collect_idle(s); return SOLARIS_ENOMEM; }
    memset(c, 0, sizeof(*c)); c->session = s; c->callbacks = *callbacks; c->context = context; c->reading = 1; c->options = limits;
    c->id = ++s->next_id; c->stream = (solaris_stream_t){&child_ops, c, pool->scope.owner};
    solaris_status_t rc = solaris_scope_init(&c->scope, pool->scope.owner, child_cancelled, child_destroyed, c);
    if (rc != SOLARIS_OK) { solaris_memory_free(c); collect_idle(s); return rc; }
    solaris_scope_retain(&s->scope); solaris_scope_retain(&c->scope); /* list membership */
    c->next = s->children; s->children = c; s->child_count++;
    s->idle_tracked = 0;
    if (s->idle != NULL) solaris_deadline_cancel(s->idle);
    uint64_t now = solaris_executor_now_ns(pool->scope.owner), duration = c->options.open_timeout_ms * UINT64_C(1000000);
    if (duration > UINT64_MAX - now) { child_close(c, SOLARIS_EOVERFLOW, 1); return SOLARIS_EOVERFLOW; }
    c->expires = now + duration;
    solaris_scope_retain(&c->scope);
    rc = solaris_deadline_start(pool->scope.owner, c->options.open_timeout_ms, expired, c, &c->deadline);
    if (rc != SOLARIS_OK) { solaris_scope_release(&c->scope); child_close(c, rc, 1); return rc; }
    request_t *r = new_request(s, c, REQUEST_OPEN);
    rc = r == NULL ? SOLARIS_ENOMEM : pool->options.codec->open(s->codec, c->id, peer, &c->wait_ack, &r->batch);
    if (rc != SOLARIS_OK) {
        if (r != NULL) { solaris_session_batch_clear(&r->batch); solaris_memory_free(r); }
        child_close(c, rc, 1); return rc;
    }
    enqueue(s, r); c->accepted = 1; *out = &c->stream; schedule(s); return SOLARIS_OK;
}
static void pool_cancelled(void *context)
{
    solaris_session_pool_t *pool = context; pool->retired = 1;
    if (pool->idle_check != NULL) solaris_deadline_cancel(pool->idle_check);
    for (session_t *s = pool->sessions; s != NULL; s = s->next) fail(s, SOLARIS_ECANCELLED);
}
static void pool_destroyed(void *context)
{
    solaris_session_pool_t *pool = context; assert(pool->sessions == NULL);
    if (pool->accepted && pool->options.on_close != NULL) pool->options.on_close(pool->options.context);
    solaris_memory_free(pool);
}
solaris_status_t solaris_session_pool_create(solaris_executor_t *owner,
    const solaris_session_pool_options_t *options, solaris_session_pool_t **out)
{
    if (out == NULL) return SOLARIS_EINVAL;
    *out = NULL;
    if (owner == NULL || options == NULL || options->codec == NULL || options->session_limit == 0u || options->session_limit > 1024u ||
        options->streams_per_session == 0u || options->streams_per_session > 1024u || options->idle_timeout_ms == 0u ||
        options->idle_timeout_ms > UINT64_MAX / UINT64_C(1000000) ||
        options->idle_check_interval_ms > UINT64_MAX / UINT64_C(1000000) || options->min_idle_sessions > options->session_limit ||
        (options->min_idle_sessions != 0u && options->idle_check_interval_ms == 0u) ||
        options->codec->frame_limit == 0u || options->codec->frame_limit > 1024u * 1024u ||
        options->codec->create == NULL || options->codec->start == NULL || options->codec->open == NULL ||
        options->codec->write == NULL || options->codec->end == NULL || options->codec->decode == NULL || options->codec->destroy == NULL) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(owner)) return SOLARIS_ETHREAD;
    solaris_session_pool_t *pool = solaris_memory_allocate(solaris_executor_budget(owner), sizeof(*pool));
    if (pool == NULL) return SOLARIS_ENOMEM;
    memset(pool, 0, sizeof(*pool)); pool->options = *options;
    solaris_status_t rc = solaris_dialer_options_normalize(&options->dialer, &pool->options.dialer);
    if (pool->options.session_pending_bytes == 0u) pool->options.session_pending_bytes =
        pool->options.dialer.pending_byte_limit > 1024u * 1024u ? pool->options.dialer.pending_byte_limit : 1024u * 1024u;
    if (pool->options.session_pending_requests == 0u) pool->options.session_pending_requests =
        pool->options.dialer.pending_request_limit > 64u ? pool->options.dialer.pending_request_limit : 64u;
    if (rc == SOLARIS_OK) rc = solaris_scope_init(&pool->scope, owner, pool_cancelled, pool_destroyed, pool);
    if (rc != SOLARIS_OK) { solaris_memory_free(pool); return rc; }
    pool->accepted = 1; *out = pool; return SOLARIS_OK;
}
void solaris_session_pool_retire(solaris_session_pool_t *pool)
{
    if (pool->retired) return;
    pool->retired = 1;
    if (pool->idle_check != NULL) solaris_deadline_cancel(pool->idle_check);
    for (session_t *s = pool->sessions; s != NULL; s = s->next) collect_idle(s);
    if (pool->count == 0u) solaris_scope_cancel(&pool->scope);
}
