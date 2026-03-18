#include "sip/message.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *get_reason_phrase(int status_code) {
  switch (status_code) {
    case 100: return "Trying";
    case 180: return "Ringing";
    case 181: return "Call Is Being Forwarded";
    case 182: return "Queued";
    case 183: return "Session Progress";
    case 200: return "OK";
    case 202: return "Accepted";
    case 302: return "Moved Temporarily";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 407: return "Proxy Authentication Required";
    case 408: return "Request Timeout";
    case 480: return "Temporarily Unavailable";
    case 486: return "Busy Here";
    case 487: return "Request Terminated";
    case 488: return "Not Acceptable Here";
    case 491: return "Request Pending";
    case 493: return "Undecipherable";
    case 500: return "Server Internal Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Server Time-out";
    case 513: return "Message Too Large";
    case 600: return "Busy Everywhere";
    case 603: return "Decline";
    case 604: return "Does Not Exist Anywhere";
    case 606: return "Not Acceptable";
    default: return "Unknown";
  }
}

char *sip_build_response(const struct sip_response *resp, size_t *out_len) {
  if (!resp || !out_len) return NULL;

  const char *reason = get_reason_phrase(resp->status_code);

  size_t cap = 512 + (resp->body_len > 0 ? resp->body_len : 0);
  char *buf = malloc(cap);
  if (!buf) return NULL;

  int offset = 0;

  offset += snprintf(buf + offset, cap - offset, "%s %d %s\r\n",
                     resp->version ? resp->version : "SIP/2.0",
                     resp->status_code,
                     reason);

  if (resp->via) {
    offset += snprintf(buf + offset, cap - offset, "Via: %s\r\n", resp->via);
  }
  if (resp->from) {
    offset += snprintf(buf + offset, cap - offset, "From: %s\r\n", resp->from);
  }
  if (resp->to) {
    offset += snprintf(buf + offset, cap - offset, "To: %s\r\n", resp->to);
  }
  if (resp->call_id) {
    offset += snprintf(buf + offset, cap - offset, "Call-ID: %s\r\n", resp->call_id);
  }
  if (resp->cseq) {
    offset += snprintf(buf + offset, cap - offset, "CSeq: %s\r\n", resp->cseq);
  }
  if (resp->content_type) {
    offset += snprintf(buf + offset, cap - offset, "Content-Type: %s\r\n", resp->content_type);
  }

  offset += snprintf(buf + offset, cap - offset, "Content-Length: %d\r\n", resp->content_length);

  offset += snprintf(buf + offset, cap - offset, "\r\n");

  if (resp->body && resp->body_len > 0) {
    memcpy(buf + offset, resp->body, resp->body_len);
    offset += resp->body_len;
  }

  *out_len = offset;
  return buf;
}

char *sip_build_request(enum sip_method method, const char *uri, const char *from, const char *to, const char *call_id, const char *cseq, const char *contact, const char *via, const char *branch, const char *body, size_t body_len, size_t *out_len) {
  if (!uri || !out_len) return NULL;

  size_t cap = 512 + (body_len > 0 ? body_len : 0);
  char *buf = malloc(cap);
  if (!buf) return NULL;

  int offset = 0;

  const char *method_str = sip_method_to_string(method);
  offset += snprintf(buf + offset, cap - offset, "%s %s SIP/2.0\r\n", method_str, uri);

  if (via) {
    offset += snprintf(buf + offset, cap - offset, "Via: %s\r\n", via);
  } else if (branch) {
    offset += snprintf(buf + offset, cap - offset, "Via: SIP/2.0/UDP $LOCALIP;branch=%s\r\n", branch);
  }

  if (from) {
    offset += snprintf(buf + offset, cap - offset, "From: %s\r\n", from);
  }
  if (to) {
    offset += snprintf(buf + offset, cap - offset, "To: %s\r\n", to);
  }
  if (call_id) {
    offset += snprintf(buf + offset, cap - offset, "Call-ID: %s\r\n", call_id);
  }
  if (cseq) {
    offset += snprintf(buf + offset, cap - offset, "CSeq: %s\r\n", cseq);
  }
  if (contact) {
    offset += snprintf(buf + offset, cap - offset, "Contact: %s\r\n", contact);
  }

  offset += snprintf(buf + offset, cap - offset, "Content-Length: %zu\r\n", body_len);

  offset += snprintf(buf + offset, cap - offset, "\r\n");

  if (body && body_len > 0) {
    memcpy(buf + offset, body, body_len);
    offset += body_len;
  }

  *out_len = offset;
  return buf;
}
