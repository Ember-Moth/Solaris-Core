#include "runtime/config/publication.h"
#include <string.h>
#include <uv.h>
struct solaris_publication { uv_mutex_t mutex; solaris_snapshot_ref_t active; int closed; };
solaris_status_t solaris_publication_create(solaris_budget_t *budget, solaris_publication_t **out)
{
    if (!out) return SOLARIS_EINVAL;
    *out = NULL;
    if (!budget) return SOLARIS_EINVAL;
    solaris_publication_t *p = solaris_memory_allocate(budget, sizeof(*p));
    if (!p) return SOLARIS_ENOMEM;
    memset(p, 0, sizeof(*p));
    if (uv_mutex_init(&p->mutex)) { solaris_memory_free(p); return SOLARIS_EIO; }
    *out = p; return SOLARIS_OK;
}
solaris_status_t solaris_publication_acquire(solaris_publication_t *p, solaris_snapshot_ref_t *out)
{
    if (!p || !out) return SOLARIS_EINVAL;
    uv_mutex_lock(&p->mutex);
    if (p->closed) { memset(out, 0, sizeof(*out)); uv_mutex_unlock(&p->mutex); return SOLARIS_ECLOSED; }
    *out = p->active;
    if (out->context) out->retain(out->context);
    uv_mutex_unlock(&p->mutex); return SOLARIS_OK;
}
solaris_status_t solaris_publication_publish(solaris_publication_t *p, uint64_t expected,
    const solaris_snapshot_ref_t *next, uint64_t *actual)
{
    if (actual) *actual = 0;
    if (!p || !next || !actual || (next->context ? (!next->retain || !next->release) : (next->retain || next->release)))
        return SOLARIS_EINVAL;
    if (expected == UINT64_MAX) return SOLARIS_EOVERFLOW;
    if (next->revision != expected + 1) return SOLARIS_EINVAL;
    uv_mutex_lock(&p->mutex);
    *actual = p->active.revision;
    if (p->closed) { uv_mutex_unlock(&p->mutex); return SOLARIS_ECLOSED; }
    if (*actual != expected) { uv_mutex_unlock(&p->mutex); return SOLARIS_EAGAIN; }
    if (next->context) next->retain(next->context);
    solaris_snapshot_ref_t old = p->active; p->active = *next; *actual = next->revision;
    uv_mutex_unlock(&p->mutex); solaris_snapshot_ref_release(&old); return SOLARIS_OK;
}
void solaris_snapshot_ref_release(solaris_snapshot_ref_t *r)
{
    if (!r) return;
    solaris_snapshot_ref_t old = *r; memset(r, 0, sizeof(*r));
    if (old.context) old.release(old.context);
}
void solaris_publication_destroy(solaris_publication_t *p)
{
    if (!p) return;
    uv_mutex_lock(&p->mutex); p->closed = 1;
    solaris_snapshot_ref_t old = p->active; memset(&p->active, 0, sizeof(p->active));
    uv_mutex_unlock(&p->mutex);
    solaris_snapshot_ref_release(&old); uv_mutex_destroy(&p->mutex); solaris_memory_free(p);
}
