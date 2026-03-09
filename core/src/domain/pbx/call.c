#include "domain/pbx/call.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

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
  log_debug("pbx: call_purge - item=%p", item);
  pbx_call_t *call = (pbx_call_t *)item;
  log_debug("pbx: call_purge - call_id=%s", call->call_id ? call->call_id : "(null)");
  free(call->call_id);
  free(call->source_extension);
  free(call->destination_extension);
  free(call->from_tag);
  free(call->to_tag);
  free(call->rtp_session_id);
  free(call->source_media_ports);
  free(call->dest_media_ports);
  free(call->source_advertise);
  free(call->dest_advertise);
  free(call->source_via);
  free(call->dest_via);
  log_debug("pbx: call_purge - freeing call struct");
  free(call);
  log_debug("pbx: call_purge - done");
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
  log_debug("pbx: call_delete - call_id=%s calls=%p", call_id ? call_id : "(null)", calls);
  if (!calls) return;
  pbx_call_t key = { .call_id = (char *)call_id };
  pbx_call_t *call = (pbx_call_t *)mindex_get(calls, &key);
  log_debug("pbx: call_delete - call=%p", call);
  if (!call) {
    log_debug("pbx: call_delete - call not found, returning");
    return;
  }
  log_debug("pbx: call_delete - deleting call");
  mindex_delete(calls, call);
  log_debug("pbx: call_delete - call deleted");
}

void pbx_call_set_media_info(const char *call_id, int *src_ports, int src_count, int *dst_ports, int dst_count, const char *src_adv, const char *dst_adv) {
  pbx_call_t *call = pbx_call_find(call_id);
  if (!call) return;

  call->source_media_ports = src_count > 0 && src_ports ? malloc(src_count * sizeof(int)) : NULL;
  if (call->source_media_ports && src_ports) {
    memcpy(call->source_media_ports, src_ports, src_count * sizeof(int));
  }
  call->source_media_port_count = src_count;

  call->dest_media_ports = dst_count > 0 && dst_ports ? malloc(dst_count * sizeof(int)) : NULL;
  if (call->dest_media_ports && dst_ports) {
    memcpy(call->dest_media_ports, dst_ports, dst_count * sizeof(int));
  }
  call->dest_media_port_count = dst_count;

  call->source_advertise = src_adv ? strdup(src_adv) : NULL;
  call->dest_advertise = dst_adv ? strdup(dst_adv) : NULL;

  log_debug("pbx: call %s media: src_ports=%d dst_ports=%d src_adv=%s dst_adv=%s",
            call_id, src_count, dst_count, src_adv ? src_adv : "?", dst_adv ? dst_adv : "?");
}

void pbx_call_set_via(const char *call_id, const char *src_via, const char *dst_via) {
  pbx_call_t *call = pbx_call_find(call_id);
  if (!call) return;

  if (src_via) {
    free(call->source_via);
    call->source_via = strdup(src_via);
  }
  if (dst_via) {
    free(call->dest_via);
    call->dest_via = strdup(dst_via);
  }

  log_debug("pbx: call %s via: src_via=%s dst_via=%s",
            call_id, call->source_via ? call->source_via : "?", call->dest_via ? call->dest_via : "?");
}

void pbx_call_set_answered(const char *call_id) {
  pbx_call_t *call = pbx_call_find(call_id);
  if (!call) return;
  call->answered_at = time(NULL);
  log_debug("pbx: call %s answered at %ld", call_id, (long)call->answered_at);
}
