#include "domain/pbx/call.h"

#include <stdlib.h>
#include <string.h>

#include "finwo/mindex.h"
#include "rxi/log.h"

static struct mindex_t *calls = NULL;

static int call_compare(const void *a, const void *b, void *udata) {
  (void)udata;
  pbx_call_t *ca = (pbx_call_t *)a;
  pbx_call_t *cb = (pbx_call_t *)b;
  return strcmp(ca->call_id, cb->call_id);
}

static void call_purge(void *item, void *udata) {
  (void)udata;
  pbx_call_t *call = (pbx_call_t *)item;
  free(call->call_id);
  free(call->source_extension);
  free(call->destination_extension);
  free(call->from_tag);
  free(call->to_tag);
  free(call->rtp_session_id);
  free(call->source_advertise);
  free(call->dest_advertise);
  free(call);
}

void pbx_call_init(void) {
  calls = mindex_init(call_compare, call_purge, NULL);
  log_debug("pbx: call manager initialized");
}

void pbx_call_shutdown(void) {
  if (calls) {
    mindex_free(calls);
    calls = NULL;
  }
}

pbx_call_t *pbx_call_create(const char *call_id, const char *source_ext, const char *dest_ext, const char *from_tag) {
  if (!calls) return NULL;

  pbx_call_t key = { .call_id = (char *)call_id };
  pbx_call_t *existing = (pbx_call_t *)mindex_get(calls, &key);
  if (existing) {
    mindex_delete(calls, existing);
    call_purge(existing, NULL);
  }

  pbx_call_t *call = calloc(1, sizeof(pbx_call_t));
  call->call_id = strdup(call_id);
  call->source_extension = strdup(source_ext);
  call->destination_extension = strdup(dest_ext);
  call->from_tag = from_tag ? strdup(from_tag) : NULL;

  mindex_set(calls, call);
  log_debug("pbx: created call %s: %s -> %s", call_id, source_ext, dest_ext);

  return call;
}

pbx_call_t *pbx_call_find(const char *call_id) {
  if (!calls) return NULL;
  pbx_call_t key = { .call_id = (char *)call_id };
  return (pbx_call_t *)mindex_get(calls, &key);
}

void pbx_call_delete(const char *call_id) {
  if (!calls) return;
  pbx_call_t key = { .call_id = (char *)call_id };
  pbx_call_t *call = (pbx_call_t *)mindex_get(calls, &key);
  if (call) {
    mindex_delete(calls, call);
    call_purge(call, NULL);
    log_debug("pbx: deleted call %s", call_id);
  }
}

void pbx_call_set_rtp_info(const char *call_id, const char *session_id, int src_port, int dst_port, const char *src_adv, const char *dst_adv) {
  pbx_call_t *call = pbx_call_find(call_id);
  if (!call) return;

  call->rtp_session_id = session_id ? strdup(session_id) : NULL;
  call->source_media_port = src_port;
  call->dest_media_port = dst_port;
  call->source_advertise = src_adv ? strdup(src_adv) : NULL;
  call->dest_advertise = dst_adv ? strdup(dst_adv) : NULL;

  log_debug("pbx: call %s RTP: src=%d->%s:%d dst=%d->%s:%d", 
            call_id, src_port, src_adv ? src_adv : "?", dst_port, dst_adv ? dst_adv : "?");
}
