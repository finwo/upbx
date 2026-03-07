#include "domain/pbx/sip/sip_proto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "domain/pbx/sip/sip_message.h"

char *sip_proto_build_response(
  const sip_message_t *req,
  int status_code,
  const char *reason,
  const char *extra_headers,
  const char *body,
  size_t body_len,
  size_t *out_len
) {
  if (!req || !out_len) return NULL;

  size_t cap = 1024 + (extra_headers ? strlen(extra_headers) : 0) + body_len;
  char  *resp = malloc(cap);
  if (!resp) return NULL;

  size_t used = 0;
  int    n;

  n = snprintf(resp + used, cap - used, "SIP/2.0 %d %s\r\n", status_code, reason ? reason : "OK");
  if (n < 0 || (size_t)n >= cap - used) {
    free(resp);
    return NULL;
  }
  used += (size_t)n;

  const char *vias[10];
  size_t via_lens[10];
  size_t via_count = 0;
  sip_message_header_get_all(req, "Via", vias, via_lens, 10, &via_count);
  for (size_t i = 0; i < via_count; i++) {
    n = snprintf(resp + used, cap - used, "Via: %.*s\r\n", (int)via_lens[i], vias[i]);
    if (n < 0 || (size_t)n >= cap - used) {
      free(resp);
      return NULL;
    }
    used += (size_t)n;
  }

  size_t      from_len;
  const char *from = sip_message_header_get(req, "From", &from_len);
  if (from && from_len > 0) {
    n = snprintf(resp + used, cap - used, "From: %.*s\r\n", (int)from_len, from);
    if (n < 0 || (size_t)n >= cap - used) {
      free(resp);
      return NULL;
    }
    used += (size_t)n;
  }

  size_t      to_len;
  const char *to = sip_message_header_get(req, "To", &to_len);
  if (to && to_len > 0) {
    n = snprintf(resp + used, cap - used, "To: %.*s\r\n", (int)to_len, to);
    if (n < 0 || (size_t)n >= cap - used) {
      free(resp);
      return NULL;
    }
    used += (size_t)n;
  }

  size_t      call_id_len;
  const char *call_id = sip_message_header_get(req, "Call-ID", &call_id_len);
  if (call_id && call_id_len > 0) {
    n = snprintf(resp + used, cap - used, "Call-ID: %.*s\r\n", (int)call_id_len, call_id);
    if (n < 0 || (size_t)n >= cap - used) {
      free(resp);
      return NULL;
    }
    used += (size_t)n;
  }

  size_t      cseq_len;
  const char *cseq = sip_message_header_get(req, "CSeq", &cseq_len);
  if (cseq && cseq_len > 0) {
    n = snprintf(resp + used, cap - used, "CSeq: %.*s\r\n", (int)cseq_len, cseq);
    if (n < 0 || (size_t)n >= cap - used) {
      free(resp);
      return NULL;
    }
    used += (size_t)n;
  }

  if (extra_headers && extra_headers[0]) {
    n = snprintf(resp + used, cap - used, "%s\r\n", extra_headers);
    if (n < 0 || (size_t)n >= cap - used) {
      free(resp);
      return NULL;
    }
    used += (size_t)n;
  }

  if (body && body_len > 0) {
    n = snprintf(resp + used, cap - used, "Content-Type: application/sdp\r\nContent-Length: %d\r\n\r\n", (int)body_len);
    if (n < 0 || (size_t)n >= cap - used) {
      free(resp);
      return NULL;
    }
    used += (size_t)n;

    if (used + body_len >= cap) {
      char *new_resp = realloc(resp, used + body_len + 1);
      if (!new_resp) {
        free(resp);
        return NULL;
      }
      resp = new_resp;
      cap = used + body_len + 1;
    }
    memcpy(resp + used, body, body_len);
    used += body_len;
  } else {
    n = snprintf(resp + used, cap - used, "Content-Length: 0\r\n\r\n");
    if (n < 0 || (size_t)n >= cap - used) {
      free(resp);
      return NULL;
    }
    used += (size_t)n;
  }

  *out_len = used;
  return resp;
}

char *sip_proto_build_request(
  const char *method,
  const char *uri,
  const char *via_host,
  const char *from_header,
  const char *to_header,
  const char *call_id,
  const char *cseq,
  const char *contact,
  const char *content_type,
  const char *body,
  size_t body_len,
  size_t *out_len
) {
  if (!method || !uri || !out_len) return NULL;

  size_t cap = 1024 + (contact ? strlen(contact) : 0) + (content_type ? strlen(content_type) : 0) + body_len;
  char  *req = malloc(cap);
  if (!req) return NULL;

  size_t used = 0;
  int    n;

  n = snprintf(req + used, cap - used, "%s %s SIP/2.0\r\n", method, uri);
  if (n < 0 || (size_t)n >= cap - used) {
    free(req);
    return NULL;
  }
  used += (size_t)n;

  n = snprintf(req + used, cap - used, "Via: SIP/2.0/UDP %s\r\n", via_host ? via_host : "127.0.0.1");
  if (n < 0 || (size_t)n >= cap - used) {
    free(req);
    return NULL;
  }
  used += (size_t)n;

  if (from_header && from_header[0]) {
    n = snprintf(req + used, cap - used, "From: %s\r\n", from_header);
    if (n < 0 || (size_t)n >= cap - used) {
      free(req);
      return NULL;
    }
    used += (size_t)n;
  }

  if (to_header && to_header[0]) {
    n = snprintf(req + used, cap - used, "To: %s\r\n", to_header);
    if (n < 0 || (size_t)n >= cap - used) {
      free(req);
      return NULL;
    }
    used += (size_t)n;
  }

  if (call_id && call_id[0]) {
    n = snprintf(req + used, cap - used, "Call-ID: %s\r\n", call_id);
    if (n < 0 || (size_t)n >= cap - used) {
      free(req);
      return NULL;
    }
    used += (size_t)n;
  }

  if (cseq && cseq[0]) {
    n = snprintf(req + used, cap - used, "CSeq: %s\r\n", cseq);
    if (n < 0 || (size_t)n >= cap - used) {
      free(req);
      return NULL;
    }
    used += (size_t)n;
  }

  if (contact && contact[0]) {
    n = snprintf(req + used, cap - used, "Contact: <%s>\r\n", contact);
    if (n < 0 || (size_t)n >= cap - used) {
      free(req);
      return NULL;
    }
    used += (size_t)n;
  }

  if (body && body_len > 0) {
    if (!content_type) content_type = "application/sdp";
    n = snprintf(req + used, cap - used, "Content-Type: %s\r\nContent-Length: %d\r\n\r\n", content_type, (int)body_len);
    if (n < 0 || (size_t)n >= cap - used) {
      free(req);
      return NULL;
    }
    used += (size_t)n;

    if (used + body_len >= cap) {
      char *new_req = realloc(req, used + body_len + 1);
      if (!new_req) {
        free(req);
        return NULL;
      }
      req = new_req;
      cap = used + body_len + 1;
    }
    memcpy(req + used, body, body_len);
    used += body_len;
  } else {
    n = snprintf(req + used, cap - used, "Content-Length: 0\r\n\r\n");
    if (n < 0 || (size_t)n >= cap - used) {
      free(req);
      return NULL;
    }
    used += (size_t)n;
  }

  *out_len = used;
  return req;
}
