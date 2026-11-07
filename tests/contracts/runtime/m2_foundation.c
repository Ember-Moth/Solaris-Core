#include "runtime/operation/ledger.h"
#include "runtime/config/publication.h"
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <uv.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #x); abort(); } } while (0)
typedef struct object { atomic_uint refs; uint64_t revision, check; atomic_uint *destroyed; } object_t;
static void retain(void *context) { CHECK(atomic_fetch_add(&((object_t *)context)->refs, 1) != 0); }
static void release(void *context)
{
    object_t *o = context;
    if (atomic_fetch_sub(&o->refs, 1) == 1) { atomic_fetch_add(o->destroyed, 1); solaris_memory_free(o); }
}
static solaris_snapshot_ref_t make(solaris_budget_t *budget, uint64_t revision, atomic_uint *destroyed)
{
    object_t *o = solaris_memory_allocate(budget, sizeof(*o)); CHECK(o);
    atomic_init(&o->refs, 1); o->revision = revision; o->check = revision ^ UINT64_C(0xface12345678); o->destroyed = destroyed;
    return (solaris_snapshot_ref_t){o, retain, release, revision};
}
typedef struct reader { solaris_publication_t *publication; atomic_int *stop; atomic_uint *reads; } reader_t;
static void read_views(void *context)
{
    reader_t *r = context;
    while (!atomic_load(r->stop)) {
        solaris_snapshot_ref_t v; CHECK(solaris_publication_acquire(r->publication, &v) == SOLARIS_OK);
        if (v.context) {
            object_t *o = v.context;
            CHECK(o->revision == v.revision && o->check == (v.revision ^ UINT64_C(0xface12345678)));
            atomic_fetch_add(r->reads, 1);
        }
        solaris_snapshot_ref_release(&v);
    }
}
static void ledger(solaris_budget_t *budget)
{
    solaris_operation_ledger_t l; uint64_t a, b, c, d;
    CHECK(solaris_operation_ledger_init(&l, budget, 3) == SOLARIS_OK);
    CHECK(solaris_operation_ledger_accept(&l, &a) == SOLARIS_OK && a == 1);
    CHECK(solaris_operation_ledger_accept(&l, &b) == SOLARIS_OK && b == 2);
    CHECK(solaris_operation_ledger_accept(&l, &c) == SOLARIS_OK && c == 3);
    CHECK(solaris_operation_ledger_complete(&l, c) == SOLARIS_OK && l.watermark == 0 && l.completed == 1);
    CHECK(solaris_operation_ledger_accept(&l, &d) == SOLARIS_EBUSY && !d);
    CHECK(solaris_operation_ledger_complete(&l, c) == SOLARIS_EINVAL);
    CHECK(solaris_operation_ledger_dispose(&l) == SOLARIS_EBUSY);
    CHECK(solaris_operation_ledger_rollback(&l, c) == SOLARIS_EINVAL);
    CHECK(solaris_operation_ledger_complete(&l, a) == SOLARIS_OK && l.watermark == 1);
    CHECK(solaris_operation_ledger_accept(&l, &d) == SOLARIS_OK && d == 4);
    CHECK(solaris_operation_ledger_rollback(&l, b) == SOLARIS_EINVAL);
    CHECK(solaris_operation_ledger_rollback(&l, d) == SOLARIS_OK && l.accepted == 3);
    CHECK(solaris_operation_ledger_complete(&l, b) == SOLARIS_OK && l.watermark == 3 && l.completed == 3);
    CHECK(solaris_operation_ledger_complete(&l, a) == SOLARIS_EINVAL);
    l.accepted = l.completed = l.watermark = UINT64_MAX - 1;
    CHECK(solaris_operation_ledger_accept(&l, &d) == SOLARIS_OK && d == UINT64_MAX);
    CHECK(solaris_operation_ledger_complete(&l, d) == SOLARIS_OK && l.watermark == UINT64_MAX);
    CHECK(solaris_operation_ledger_accept(&l, &d) == SOLARIS_EOVERFLOW && !d);
    CHECK(solaris_operation_ledger_dispose(&l) == SOLARIS_OK);
}
static void publication(solaris_budget_t *budget)
{
    solaris_publication_t *p; CHECK(solaris_publication_create(budget, &p) == SOLARIS_OK);
    atomic_uint destroyed, reads; atomic_int stop;
    atomic_init(&destroyed, 0); atomic_init(&reads, 0); atomic_init(&stop, 0);
    solaris_snapshot_ref_t v, old; uint64_t actual;
    CHECK(solaris_publication_acquire(p, &v) == SOLARIS_OK && !v.context && !v.revision);
    v = make(budget, 1, &destroyed);
    CHECK(solaris_publication_publish(p, 0, &v, &actual) == SOLARIS_OK && actual == 1);
    solaris_snapshot_ref_release(&v); CHECK(solaris_publication_acquire(p, &old) == SOLARIS_OK);
    v = make(budget, 1, &destroyed);
    CHECK(solaris_publication_publish(p, 0, &v, &actual) == SOLARIS_EAGAIN && actual == 1);
    solaris_snapshot_ref_release(&v);
    reader_t reader = {p, &stop, &reads}; uv_thread_t threads[3];
    for (unsigned i = 0; i < 3; ++i) CHECK(!uv_thread_create(&threads[i], read_views, &reader));
    while (!atomic_load(&reads)) uv_sleep(1);
    for (uint64_t revision = 2; revision <= 10000; ++revision) {
        v = make(budget, revision, &destroyed);
        CHECK(solaris_publication_publish(p, revision - 1, &v, &actual) == SOLARIS_OK && actual == revision);
        solaris_snapshot_ref_release(&v);
    }
    atomic_store(&stop, 1);
    for (unsigned i = 0; i < 3; ++i) CHECK(!uv_thread_join(&threads[i]));
    CHECK(atomic_load(&reads) > 0);
    v = (solaris_snapshot_ref_t){.revision = 10001};
    CHECK(solaris_publication_publish(p, 10000, &v, &actual) == SOLARIS_OK);
    CHECK(solaris_publication_acquire(p, &v) == SOLARIS_OK && !v.context && v.revision == 10001);
    CHECK(((object_t *)old.context)->revision == 1);
    solaris_publication_destroy(p);
    CHECK(atomic_load(&destroyed) == 10000); solaris_snapshot_ref_release(&old);
    CHECK(atomic_load(&destroyed) == 10001);
}
typedef struct reentrant {
    solaris_publication_t *publication;
    unsigned references, released;
    uint64_t observed;
    solaris_status_t status;
} reentrant_t;
static void reentrant_retain(void *context) { ++((reentrant_t *)context)->references; }
static void reentrant_release(void *context)
{
    reentrant_t *value = context;
    CHECK(value->references != 0);
    --value->references;
    ++value->released;
    solaris_snapshot_ref_t current;
    value->status = solaris_publication_acquire(value->publication, &current);
    value->observed = current.revision;
    solaris_snapshot_ref_release(&current);
}
static void publication_release_boundary(solaris_budget_t *budget)
{
    solaris_publication_t *p;
    CHECK(solaris_publication_create(budget, &p) == SOLARIS_OK);
    reentrant_t object = {.publication = p};
    solaris_snapshot_ref_t view = {&object, reentrant_retain, reentrant_release, 1};
    uint64_t revision;
    CHECK(solaris_publication_publish(p, 0, &view, &revision) == SOLARIS_OK);
    solaris_snapshot_ref_t empty = {.revision = 2};
    CHECK(solaris_publication_publish(p, 1, &empty, &revision) == SOLARIS_OK);
    /* Retirement can query the new publication: no release under its lock. */
    CHECK(object.released == 1 && object.references == 0 && object.observed == 2 && object.status == SOLARIS_OK);
    view.revision = 3;
    CHECK(solaris_publication_publish(p, 2, &view, &revision) == SOLARIS_OK);
    solaris_publication_destroy(p);
    CHECK(object.released == 2 && object.references == 0 && object.status == SOLARIS_ECLOSED);
}
static void allocation_failure(void)
{
    solaris_budget_t *budget;
    CHECK(solaris_budget_create(1, NULL, &budget) == SOLARIS_OK);
    solaris_publication_t *p = (void *)1;
    CHECK(solaris_publication_create(budget, &p) == SOLARIS_ENOMEM && p == NULL);
    solaris_operation_ledger_t ledger;
    CHECK(solaris_operation_ledger_init(&ledger, budget, 1) == SOLARIS_ENOMEM);
    CHECK(solaris_operation_ledger_dispose(&ledger) == SOLARIS_OK);
    CHECK(solaris_operation_ledger_init(&ledger, budget, SIZE_MAX) == SOLARIS_EINVAL);
    CHECK(solaris_budget_used(budget) == 0);
    solaris_budget_release(budget);
}
int main(void)
{
    solaris_budget_t *budget; CHECK(solaris_budget_create(4 * 1024 * 1024, NULL, &budget) == SOLARIS_OK);
    ledger(budget); publication(budget); publication_release_boundary(budget); allocation_failure();
    CHECK(solaris_budget_used(budget) == 0); solaris_budget_release(budget);
    puts("M2 shared contracts: bounded out-of-order completion watermark, rollback, revision CAS and concurrent snapshot leases passed");
    return 0;
}
