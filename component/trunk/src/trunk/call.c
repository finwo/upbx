#include <stdlib.h>
#include <string.h>
#include "call.h"

int call_cmp(const void *a, const void *b, void *udata) {
    (void)udata;
    const struct trunk_call *ca = a;
    const struct call_key   *cb = b;
    size_t len = ca->call_id_len < cb->call_id_len ? ca->call_id_len : cb->call_id_len;
    int r = strncmp(ca->call_id, cb->call_id, len);
    if (r != 0) return r;
    return (int)(ca->call_id_len - cb->call_id_len);
}

void call_purge(void *item, void *udata) {
    (void)udata;
    struct trunk_call *c = item;
    free(c->call_id);
    free(c->sip_call_id);
    free(c->trunk_did);
    free(c->trunk_cid);
    free(c->trunk_via);
    free(c->trunk_from);
    free(c->trunk_to);
    free(c->trunk_contact);
    free(c->remote_sdp_host);
    free(c->backbone_tags);
    rtp_free(c->rtp);
    free(c);
}

struct trunk_call *call_create(struct mindex_t *mindex, const char *call_id,
                              const char *sip_call_id) {
    struct trunk_call *c = calloc(1, sizeof(struct trunk_call));
    if (!c) return NULL;

    c->call_id = strdup(call_id);
    c->call_id_len = strlen(call_id);
    c->sip_call_id = sip_call_id ? strdup(sip_call_id) : NULL;
    c->state = CALL_WAITING;
    c->trunk_fd = -1;

    mindex_set(mindex, c);
    return c;
}

struct trunk_call *call_lookup(struct mindex_t *mindex, const char *call_id) {
    struct call_key key = {call_id, strlen(call_id)};
    return (struct trunk_call *)mindex_get(mindex, &key);
}

void call_destroy(struct mindex_t *mindex, struct trunk_call *call) {
    if (!mindex || !call) return;
    struct call_key key = {call->call_id, call->call_id_len};
    mindex_delete(mindex, &key);
}