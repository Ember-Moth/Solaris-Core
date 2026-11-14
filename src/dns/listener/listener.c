#include "dns/listener/listener.h"

#include <assert.h>
#include <string.h>

/* Per listener generation, in addition to the shared engine and DNS service
 * budgets. A TCP reader pauses at its pipeline limit and resumes after writes. */
enum {
    CONNECTION_LIMIT = 128,
    QUERY_LIMIT = 256,
    PIPELINE_LIMIT = 16,
    INPUT_LIMIT = 2 * (SOLARIS_DNS_MAX_MESSAGE + 2),
    BUFFER_LIMIT = 8 * 1024 * 1024,
    IDLE_MS = 30000,
    REQUEST_MS = 5000,
    SWEEP_MS = 1000
};

typedef struct dns_connection dns_connection_t;
typedef struct dns_query dns_query_t;
struct solaris_dns_listener {
    solaris_scope_t scope;
    solaris_scope_t *parent;
    solaris_budget_t *budget;
    solaris_dns_binding_t *binding;
    solaris_dns_lookup_view_t view;
    void (*on_close)(void *);
    void *context;
    solaris_deadline_t *timer;
    dns_connection_t *connections;
    dns_query_t *queries;
    size_t connection_count, query_count, buffered;
    int retired;
};

struct dns_connection {
    solaris_scope_t scope;
    solaris_dns_listener_t *listener;
    solaris_dns_listener_lease_t lease;
    dns_connection_t *next;
    solaris_stream_t *stream;
    uint8_t *input;
    size_t length, capacity, pending;
    uint64_t last_active, frame_started;
    int eof, writing;
};

struct dns_query {
    solaris_dns_listener_t *listener;
    dns_connection_t *connection;
    dns_query_t *next;
    solaris_dns_request_t *request;
    solaris_dns_wire_t *query;
    solaris_buffer_t *reply;
    size_t charge, udp_limit;
    int writing;
    /* Datagram-specific fields. The slot is pinned through send completion. */
    solaris_dns_listener_sender_t sender;
    solaris_dns_listener_lease_t lease;
    solaris_address_t peer;
};

static void process_input(dns_connection_t *c);
static void flush_tcp(dns_connection_t *c);

static int valid_lease(const solaris_dns_listener_lease_t *lease)
{
    return lease && lease->retain && lease->release;
}

static void finish_retirement(solaris_dns_listener_t *listener)
{
    if (listener->retired && !listener->connection_count && !listener->query_count)
        solaris_scope_cancel(&listener->scope);
}

static void discard_query(dns_query_t *q)
{
    solaris_dns_listener_t *listener = q->listener;
    dns_connection_t *c = q->connection;
    assert(!q->request && !q->writing);
    dns_query_t **link = &listener->queries;
    while (*link != q) link = &(*link)->next;
    *link = q->next;
    --listener->query_count;
    assert(listener->buffered >= q->charge);
    listener->buffered -= q->charge;
    solaris_dns_wire_release(q->query);
    solaris_buffer_release(q->reply);
    if (c) {
        --c->pending;
        solaris_scope_release(&c->scope);
    } else {
        q->lease.release(q->lease.context);
        solaris_scope_release(&listener->scope);
    }
    solaris_memory_free(q);
    finish_retirement(listener);
}

static void cancel_query(dns_query_t *q)
{
    if (q->request)
        (void)solaris_dns_request_cancel(q->request);
    else if (!q->writing)
        discard_query(q);
}

static void connection_cancel(void *context)
{
    dns_connection_t *c = context;
    if (c->stream) (void)solaris_stream_close(c->stream);
    for (dns_query_t *q = c->listener->queries, *next; q; q = next) {
        next = q->next;
        if (q->connection == c) cancel_query(q);
    }
}

static void connection_done(void *context)
{
    dns_connection_t *c = context;
    solaris_dns_listener_t *listener = c->listener;
    assert(!c->stream && !c->pending);
    dns_connection_t **link = &listener->connections;
    while (*link != c) link = &(*link)->next;
    *link = c->next;
    --listener->connection_count;
    listener->buffered -= c->capacity;
    solaris_memory_free(c->input);
    if (c->lease.release) c->lease.release(c->lease.context);
    solaris_memory_free(c);
    finish_retirement(listener);
    solaris_scope_release(&listener->scope);
}

static void listener_cancel(void *context)
{
    solaris_dns_listener_t *listener = context;
    if (listener->timer) solaris_deadline_cancel(listener->timer);
    for (dns_connection_t *c = listener->connections; c; c = c->next)
        solaris_scope_cancel(&c->scope);
    for (dns_query_t *q = listener->queries, *next; q; q = next) {
        next = q->next;
        if (!q->connection) cancel_query(q);
    }
}

static void listener_done(void *context)
{
    solaris_dns_listener_t *listener = context;
    solaris_scope_t *parent = listener->parent;
    assert(!listener->connections && !listener->queries && !listener->timer && !listener->buffered);
    solaris_dns_binding_release(listener->binding);
    listener->on_close(listener->context);
    solaris_memory_free(listener);
    solaris_scope_release(parent);
}

static solaris_status_t start_sweep(solaris_dns_listener_t *listener);

static void sweep(void *context, solaris_status_t status)
{
    solaris_dns_listener_t *listener = context;
    listener->timer = NULL;
    if (status == SOLARIS_OK && !listener->scope.cancelled) {
        uint64_t now = solaris_executor_now_ns(listener->scope.owner);
        for (dns_connection_t *c = listener->connections; c; c = c->next) {
            if (now - c->last_active >= IDLE_MS * UINT64_C(1000000) ||
                (c->length && c->pending < PIPELINE_LIMIT &&
                 now - c->frame_started >= REQUEST_MS * UINT64_C(1000000)))
                solaris_scope_cancel(&c->scope);
        }
        if (listener->connection_count && start_sweep(listener) != SOLARIS_OK) {
            /* Fail these connections closed if their deadline cannot be armed.
             * A subsequent admission can try to establish its own timer. */
            for (dns_connection_t *c = listener->connections; c; c = c->next)
                solaris_scope_cancel(&c->scope);
        }
    }
    solaris_scope_release(&listener->scope);
}

static solaris_status_t start_sweep(solaris_dns_listener_t *listener)
{
    if (listener->timer) return SOLARIS_OK;
    solaris_status_t rc = solaris_deadline_start(listener->scope.owner, SWEEP_MS, sweep, listener, &listener->timer);
    if (rc == SOLARIS_OK) solaris_scope_retain(&listener->scope);
    return rc;
}

solaris_status_t solaris_dns_listener_create(solaris_scope_t *parent, solaris_dns_binding_t *binding,
    const solaris_dns_lookup_view_t *view, void (*on_close)(void *), void *context, solaris_dns_listener_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!parent || !parent->owner || !binding || !view || !on_close) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(parent->owner)) return SOLARIS_ETHREAD;
    if (parent->cancelled || parent->finishing) return SOLARIS_ECLOSED;
    solaris_budget_t *budget = solaris_executor_budget(parent->owner);
    solaris_dns_listener_t *listener = solaris_memory_allocate(budget, sizeof(*listener));
    if (!listener) return SOLARIS_ENOMEM;
    memset(listener, 0, sizeof(*listener));
    solaris_status_t rc = solaris_scope_init(&listener->scope, parent->owner, listener_cancel, listener_done, listener);
    if (rc != SOLARIS_OK) {
        solaris_memory_free(listener);
        return rc;
    }
    listener->parent = parent;
    solaris_scope_retain(parent);
    listener->budget = budget;
    listener->binding = binding;
    solaris_dns_binding_retain(binding);
    listener->view = *view;
    listener->view.role = SOLARIS_DNS_CLIENT_QUERY;
    listener->on_close = on_close;
    listener->context = context;
    *out = listener;
    return SOLARIS_OK;
}

void solaris_dns_listener_retire(solaris_dns_listener_t *listener)
{
    if (!listener) return;
    assert(solaris_executor_is_owner(listener->scope.owner));
    listener->retired = 1;
    finish_retirement(listener);
}

void solaris_dns_listener_close(solaris_dns_listener_t *listener)
{
    if (!listener) return;
    assert(solaris_executor_is_owner(listener->scope.owner));
    solaris_scope_cancel(&listener->scope);
}

static solaris_status_t make_servfail(dns_query_t *q, solaris_buffer_t **out)
{
    solaris_buffer_t *body = NULL;
    solaris_status_t rc = solaris_dns_wire_make_response(q->listener->budget, q->query, SOLARIS_DNS_RA, 2,
                                                        NULL, 0, &body);
    if (rc != SOLARIS_OK) return rc;
    if (!q->connection) {
        *out = body;
        return SOLARIS_OK;
    }
    size_t length = solaris_buffer_length(body);
    rc = solaris_buffer_allocate(q->listener->budget, length + 2, out);
    if (rc == SOLARIS_OK) {
        uint8_t *bytes = solaris_buffer_mutable_data(*out);
        bytes[0] = (uint8_t)(length >> 8);
        bytes[1] = (uint8_t)length;
        memcpy(bytes + 2, solaris_buffer_data(body), length);
        (void)solaris_buffer_set_length(*out, length + 2);
        solaris_buffer_publish(*out);
    }
    solaris_buffer_release(body);
    return rc;
}

static void write_done(void *context, solaris_status_t status)
{
    dns_query_t *q = context;
    dns_connection_t *c = q->connection;
    q->writing = 0;
    if (c) c->writing = 0;
    discard_query(q);
    if (!c || c->scope.cancelled) return;
    if (status != SOLARIS_OK) {
        solaris_scope_cancel(&c->scope);
        return;
    }
    c->last_active = solaris_executor_now_ns(c->scope.owner);
    process_input(c);
    if (!c->scope.cancelled) flush_tcp(c);
}

static void flush_tcp(dns_connection_t *c)
{
    if (c->scope.cancelled || c->writing) return;
    /* Oldest ready query wins. A delayed earlier query never blocks another
     * result, and a busy pipeline cannot starve an already-ready reply. */
    dns_query_t *q = NULL;
    for (dns_query_t *candidate = c->listener->queries; candidate; candidate = candidate->next) {
        if (candidate->connection == c && candidate->reply) q = candidate;
    }
    if (!q) return;
    solaris_slice_t slice = {q->reply, 0, solaris_buffer_length(q->reply)};
    solaris_status_t rc = solaris_stream_write(c->stream, &slice, write_done, q);
    if (rc == SOLARIS_OK) {
        c->writing = q->writing = 1;
        solaris_buffer_release(q->reply);
        q->reply = NULL;
    } else if (rc != SOLARIS_EAGAIN) {
        solaris_scope_cancel(&c->scope);
    }
}

/* EDNS is negotiated independently on the upstream and client hops (RFC
 * 6891 sections 6 and 7). Unknown client options do not acquire resolver
 * semantics. DO and CD remain inputs to the upstream and cache key. */
static solaris_status_t forwarded_query(solaris_budget_t *budget, solaris_dns_wire_t **query)
{
    solaris_dns_edns_t opt = *solaris_dns_wire_edns(*query);
    if (!opt.present || (!opt.option_count && opt.udp_size == SOLARIS_DNS_DEFAULT_UDP_SIZE)) return SOLARIS_OK;
    const solaris_dns_header_t *header = solaris_dns_wire_header(*query);
    opt.udp_size = SOLARIS_DNS_DEFAULT_UDP_SIZE;
    opt.option_count = opt.options_length = 0;
    solaris_buffer_t *body = NULL;
    solaris_status_t rc = solaris_dns_wire_make_query(budget, header->id, header->flags,
        solaris_dns_wire_question(*query), &opt, &body);
    if (rc != SOLARIS_OK) return rc;
    solaris_dns_wire_t *normalized = NULL;
    rc = solaris_dns_wire_parse(budget, solaris_buffer_data(body), solaris_buffer_length(body), NULL, &normalized, NULL);
    solaris_buffer_release(body);
    if (rc == SOLARIS_OK) {
        solaris_dns_wire_release(*query);
        *query = normalized;
    }
    return rc;
}

static void put16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t)(value >> 8);
    bytes[1] = (uint8_t)value;
}

/* Add/swap a trailing OPT without moving retained RR data or invalidating
 * compression pointers hidden in opaque RDATA. Replacing a bare interior
 * OPT with another bare OPT is also length-preserving. */
static solaris_status_t client_answer(dns_query_t *q, const solaris_dns_wire_t *answer, solaris_dns_wire_t **out)
{
    const solaris_dns_edns_t *client = solaris_dns_wire_edns(q->query);
    const solaris_dns_edns_t *upstream = solaris_dns_wire_edns(answer);
    const solaris_dns_header_t *header = solaris_dns_wire_header(answer);
    if (client->present == upstream->present && (!client->present ||
        (!upstream->option_count && upstream->udp_size == SOLARIS_DNS_DEFAULT_UDP_SIZE &&
         upstream->flags == client->flags))) {
        solaris_dns_wire_retain(answer);
        *out = (solaris_dns_wire_t *)answer;
        return SOLARIS_OK;
    }
    if (!client->present && header->rcode > 15) return SOLARIS_ENOTSUP;
    const solaris_buffer_t *original = solaris_dns_wire_buffer(answer);
    size_t length = solaris_buffer_length(original);
    size_t offset = length, removed = 0;
    uint16_t additional = header->additional;
    if (upstream->present) {
        /* The parser accepts only a one-byte root and fixed ten-byte OPT
         * header before options_offset. */
        offset = upstream->options_offset - 11;
        removed = 11 + upstream->options_length;
        if (offset + removed != length && (!client->present || removed != 11)) return SOLARIS_ENOTSUP;
        --additional;
    }
    size_t added = client->present ? 11 : 0;
    size_t total = length - removed + added;
    if (total > SOLARIS_DNS_MAX_MESSAGE) return SOLARIS_EMSGSIZE;
    solaris_buffer_t *copy = NULL;
    solaris_status_t rc = solaris_buffer_allocate(q->listener->budget, total, &copy);
    if (rc != SOLARIS_OK) return rc;
    uint8_t *bytes = solaris_buffer_mutable_data(copy);
    const uint8_t *source = solaris_buffer_data(original);
    memcpy(bytes, source, offset);
    if (client->present) {
        uint8_t *opt = bytes + offset;
        opt[0] = 0;
        put16(opt + 1, SOLARIS_DNS_OPT);
        put16(opt + 3, SOLARIS_DNS_DEFAULT_UDP_SIZE);
        opt[5] = (uint8_t)(header->rcode >> 4);
        opt[6] = 0;
        put16(opt + 7, client->flags);
        put16(opt + 9, 0);
        ++additional;
    }
    memcpy(bytes + offset + added, source + offset + removed, length - offset - removed);
    put16(bytes + 10, additional);
    solaris_dns_wire_limits_t limits;
    solaris_dns_wire_limits_init(&limits);
    limits.records = SOLARIS_DNS_MAX_RECORDS;
    rc = solaris_dns_wire_parse(q->listener->budget, bytes, total, &limits, out, NULL);
    solaris_buffer_release(copy);
    return rc;
}

static void complete_query(dns_query_t *q, const solaris_dns_wire_t *answer)
{
    solaris_dns_listener_t *listener = q->listener;
    dns_connection_t *c = q->connection;
    q->request = NULL;
    if (listener->scope.cancelled || (c && c->scope.cancelled) || !solaris_executor_accepting(listener->scope.owner)) {
        discard_query(q);
        return;
    }
    solaris_dns_wire_t *normalized = NULL;
    solaris_status_t rc = answer ? client_answer(q, answer, &normalized) : SOLARIS_ENOTSUP;
    if (rc == SOLARIS_OK) {
        if (c)
            rc = solaris_dns_wire_frame(normalized, listener->budget, &q->reply);
        else
            rc = solaris_dns_wire_truncate(normalized, listener->budget, q->udp_limit, &q->reply);
        solaris_dns_wire_release(normalized);
    } else if (rc != SOLARIS_ENOMEM) {
        rc = make_servfail(q, &q->reply);
    }
    if (rc == SOLARIS_OK && solaris_buffer_length(q->reply) > BUFFER_LIMIT - listener->buffered)
        rc = SOLARIS_EAGAIN;
    if (rc != SOLARIS_OK) {
        discard_query(q);
        if (c) solaris_scope_cancel(&c->scope);
        return;
    }
    size_t length = solaris_buffer_length(q->reply);
    q->charge += length;
    listener->buffered += length;
    if (c) {
        flush_tcp(c);
    } else {
        solaris_slice_t slice = {q->reply, 0, length};
        rc = q->sender.send(q->sender.context, &q->peer, &slice, write_done, q);
        if (rc == SOLARIS_OK) {
            q->writing = 1;
            solaris_buffer_release(q->reply);
            q->reply = NULL;
        } else {
            discard_query(q);
        }
    }
}

static void resolved(void *context, solaris_dns_request_t *request, const solaris_dns_service_result_t *result)
{
    dns_query_t *q = context;
    assert(q->request == request);
    (void)request;
    complete_query(q, result->status == SOLARIS_OK ? result->response : NULL);
}

static solaris_status_t submit(solaris_dns_listener_t *listener, dns_connection_t *c,
    const solaris_dns_listener_sender_t *sender, const solaris_address_t *peer, const solaris_dns_listener_lease_t *lease,
    const uint8_t *bytes, size_t length)
{
    if (listener->query_count >= QUERY_LIMIT || length > BUFFER_LIMIT - listener->buffered) return SOLARIS_EAGAIN;
    solaris_dns_wire_t *query = NULL;
    solaris_status_t rc = solaris_dns_wire_parse(listener->budget, bytes, length, NULL, &query, NULL);
    if (rc != SOLARIS_OK) return rc;
    const solaris_dns_header_t *header = solaris_dns_wire_header(query);
    if ((header->flags & ~(SOLARIS_DNS_RD | SOLARIS_DNS_CD | SOLARIS_DNS_AD)) ||
        header->additional != solaris_dns_wire_edns(query)->present) {
        solaris_dns_wire_release(query);
        return SOLARIS_EINVAL;
    }
    size_t udp_limit = solaris_dns_wire_udp_limit(query, SOLARIS_DNS_DEFAULT_UDP_SIZE);
    rc = forwarded_query(listener->budget, &query);
    if (rc != SOLARIS_OK) {
        solaris_dns_wire_release(query);
        return rc;
    }
    dns_query_t *q = solaris_memory_allocate(listener->budget, sizeof(*q));
    if (!q) {
        solaris_dns_wire_release(query);
        return SOLARIS_ENOMEM;
    }
    memset(q, 0, sizeof(*q));
    q->listener = listener;
    q->connection = c;
    q->query = query;
    q->udp_limit = udp_limit;
    q->charge = length;
    listener->buffered += length;
    q->next = listener->queries;
    listener->queries = q;
    ++listener->query_count;
    if (c) {
        solaris_scope_retain(&c->scope);
        ++c->pending;
    } else {
        solaris_scope_retain(&listener->scope);
        q->sender = *sender;
        q->peer = *peer;
        q->lease = *lease;
        q->lease.retain(q->lease.context);
    }
    solaris_dns_query_options_t options = {
        .owner = listener->scope.owner,
        .parent_scope = c ? &c->scope : &listener->scope,
        .view = listener->view,
    };
    uint64_t now = solaris_executor_now_ns(options.owner);
    uint64_t duration = REQUEST_MS * UINT64_C(1000000);
    options.deadline_ns = now > UINT64_MAX - duration ? UINT64_MAX : now + duration;
    rc = solaris_dns_service_query(listener->binding, &options, query, resolved, q, &q->request);
    if (rc != SOLARIS_OK) complete_query(q, NULL);
    return SOLARIS_OK;
}

solaris_status_t solaris_dns_listener_packet(solaris_dns_listener_t *listener,
    const solaris_dns_listener_sender_t *sender, const solaris_address_t *peer, const solaris_buffer_t *packet,
    const solaris_dns_listener_lease_t *lease)
{
    if (!listener || !sender || !sender->send || !peer || !packet || !valid_lease(lease)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(listener->scope.owner)) return SOLARIS_ETHREAD;
    if (listener->retired || listener->scope.cancelled) return SOLARIS_ECLOSED;
    return submit(listener, NULL, sender, peer, lease, solaris_buffer_data(packet), solaris_buffer_length(packet));
}

static void process_input(dns_connection_t *c)
{
    if (c->scope.cancelled) return;
    size_t used = 0;
    while (c->pending < PIPELINE_LIMIT && c->length - used >= 2) {
        const uint8_t *frame = c->input + used;
        size_t size = ((size_t)frame[0] << 8) | frame[1];
        if (size < 12) {
            solaris_scope_cancel(&c->scope);
            return;
        }
        if (c->length - used - 2 < size) break;
        solaris_status_t rc = submit(c->listener, c, NULL, NULL, NULL, frame + 2, size);
        if (rc != SOLARIS_OK || c->scope.cancelled) {
            solaris_scope_cancel(&c->scope);
            return;
        }
        used += size + 2;
    }
    if (used) {
        c->length -= used;
        if (c->length) memmove(c->input, c->input + used, c->length);
        c->frame_started = solaris_executor_now_ns(c->scope.owner);
    }
    if (c->eof) {
        if ((c->length && c->pending < PIPELINE_LIMIT) || (!c->length && !c->pending))
            solaris_scope_cancel(&c->scope);
    } else if (solaris_stream_set_reading(c->stream, c->pending < PIPELINE_LIMIT) != SOLARIS_OK) {
        solaris_scope_cancel(&c->scope);
    }
}

static void opened(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    dns_connection_t *c = context;
    assert(c->stream == stream);
    if (status != SOLARIS_OK || solaris_stream_set_reading(stream, 1) != SOLARIS_OK)
        solaris_scope_cancel(&c->scope);
}

static void data(void *context, solaris_stream_t *stream, const solaris_buffer_t *buffer)
{
    dns_connection_t *c = context;
    assert(c->stream == stream);
    (void)stream;
    if (c->scope.cancelled) return;
    size_t size = solaris_buffer_length(buffer);
    if (size > INPUT_LIMIT - c->length) {
        solaris_scope_cancel(&c->scope);
        return;
    }
    size_t needed = c->length + size;
    if (c->capacity < needed) {
        size_t capacity = c->capacity ? c->capacity : 512;
        while (capacity < needed) capacity *= 2;
        if (capacity > INPUT_LIMIT) capacity = INPUT_LIMIT;
        if (capacity - c->capacity > BUFFER_LIMIT - c->listener->buffered) {
            solaris_scope_cancel(&c->scope);
            return;
        }
        uint8_t *input = solaris_memory_allocate(c->listener->budget, capacity);
        if (!input) {
            solaris_scope_cancel(&c->scope);
            return;
        }
        if (c->length) memcpy(input, c->input, c->length);
        solaris_memory_free(c->input);
        c->listener->buffered += capacity - c->capacity;
        c->input = input;
        c->capacity = capacity;
    }
    c->last_active = solaris_executor_now_ns(c->scope.owner);
    if (!c->length) c->frame_started = c->last_active;
    if (size) memcpy(c->input + c->length, solaris_buffer_data(buffer), size);
    c->length = needed;
    process_input(c);
}

static void eof_received(void *context, solaris_stream_t *stream)
{
    dns_connection_t *c = context;
    assert(c->stream == stream);
    (void)stream;
    c->eof = 1;
    process_input(c);
}

static void writable(void *context, solaris_stream_t *stream)
{
    dns_connection_t *c = context;
    assert(c->stream == stream);
    (void)stream;
    flush_tcp(c);
}

static void closed(void *context, solaris_stream_t *stream, solaris_status_t status)
{
    dns_connection_t *c = context;
    assert(c->stream == stream);
    (void)stream;
    (void)status;
    c->stream = NULL;
    solaris_scope_cancel(&c->scope);
    solaris_scope_release(&c->scope); /* Accepted native stream. */
}

static const solaris_stream_callbacks_t callbacks = {
    .on_open = opened, .on_data = data, .on_eof = eof_received, .on_writable = writable, .on_close = closed
};

solaris_status_t solaris_dns_listener_accept(solaris_dns_listener_t *listener, solaris_stream_t *stream,
    solaris_stream_callbacks_t *out_callbacks, void **stream_context, const solaris_dns_listener_lease_t *lease)
{
    if (!listener || !stream || !out_callbacks || !stream_context || !valid_lease(lease)) return SOLARIS_EINVAL;
    if (!solaris_executor_is_owner(listener->scope.owner) || stream->owner != listener->scope.owner) return SOLARIS_ETHREAD;
    if (listener->retired || listener->scope.cancelled) return SOLARIS_ECLOSED;
    if (listener->connection_count >= CONNECTION_LIMIT) return SOLARIS_EAGAIN;
    dns_connection_t *c = solaris_memory_allocate(listener->budget, sizeof(*c));
    if (!c) return SOLARIS_ENOMEM;
    memset(c, 0, sizeof(*c));
    solaris_status_t rc = solaris_scope_init(&c->scope, listener->scope.owner, connection_cancel, connection_done, c);
    if (rc != SOLARIS_OK) {
        solaris_memory_free(c);
        return rc;
    }
    c->listener = listener;
    solaris_scope_retain(&listener->scope);
    c->next = listener->connections;
    listener->connections = c;
    ++listener->connection_count;
    rc = start_sweep(listener);
    if (rc != SOLARIS_OK) {
        solaris_scope_cancel(&c->scope);
        return rc;
    }
    c->last_active = solaris_executor_now_ns(c->scope.owner);
    c->lease = *lease;
    c->lease.retain(c->lease.context);
    c->stream = stream;
    solaris_scope_retain(&c->scope);
    *out_callbacks = callbacks;
    *stream_context = c;
    return SOLARIS_OK;
}
