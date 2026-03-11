#include "domain/pbx/sip_builder.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *status_reason(int code) {
  switch (code) {
    case 100: return "Trying";
    case 180: return "Ringing";
    case 181: return "Call Is Being Forwarded";
    case 182: return "Queued";
    case 200: return "OK";
    case 401: return "Unauthorized";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 408: return "Request Timeout";
    case 486: return "Busy Here";
    case 487: return "Request Terminated";
    case 488: return "Not Acceptable Here";
    case 500: return "Server Internal Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    default:  return "Unknown";
  }
}

char *sip_build_message(int status_code, const char *reason, const sip_message_t *req, const char *extra_headers, const char *body) {
  if (!req) return NULL;

  if (!reason) reason = status_reason(status_code);

  size_t buf_size = 256;
  if (req->uri) buf_size += strlen(req->uri);
  if (req->via) buf_size += strlen(req->via);
  if (req->from) buf_size += strlen(req->from);
  if (req->to) buf_size += strlen(req->to);
  if (req->call_id) buf_size += strlen(req->call_id);
  if (req->cseq_method) buf_size += strlen(req->cseq_method);
  if (extra_headers) buf_size += strlen(extra_headers);
  if (body) buf_size += strlen(body);

  char *buf = malloc(buf_size);
  if (!buf) return NULL;
  buf[0] = '\0';

  char request_line[128];
  if (status_code == 0 && req->method && req->uri) {
    snprintf(request_line, sizeof(request_line), "%s %s SIP/2.0\r\n", req->method, req->uri);
  } else {
    snprintf(request_line, sizeof(request_line), "SIP/2.0 %d %s\r\n", status_code, reason);
  }
  strcat(buf, request_line);

  if (req->via) {
    strcat(buf, "Via: ");
    strcat(buf, req->via);
    strcat(buf, "\r\n");
  }

  if (req->from) {
    strcat(buf, "From: ");
    strcat(buf, req->from);
    strcat(buf, "\r\n");
  }

  if (req->to) {
    strcat(buf, "To: ");
    strcat(buf, req->to);
    strcat(buf, "\r\n");
  }

  if (req->call_id) {
    strcat(buf, "Call-ID: ");
    strcat(buf, req->call_id);
    strcat(buf, "\r\n");
  }

  if (req->cseq > 0 && req->cseq_method) {
    strcat(buf, "CSeq: ");
    char cseq_str[32];
    snprintf(cseq_str, sizeof(cseq_str), "%d %s", req->cseq, req->cseq_method);
    strcat(buf, cseq_str);
    strcat(buf, "\r\n");
  }

  if (status_code == 401 && req->www_authenticate) {
    strcat(buf, "WWW-Authenticate: ");
    strcat(buf, req->www_authenticate);
    strcat(buf, "\r\n");
  }

  if (extra_headers) {
    strcat(buf, extra_headers);
    if (strstr(extra_headers, "\r\n") != extra_headers + strlen(extra_headers) - 2) {
      strcat(buf, "\r\n");
    }
  }

  if (body) {
    strcat(buf, "Content-Length: ");
    char cl_str[32];
    snprintf(cl_str, sizeof(cl_str), "%zu\r\n", strlen(body));
    strcat(buf, cl_str);
    strcat(buf, "\r\n");
    strcat(buf, body);
  } else {
    strcat(buf, "Content-Length: 0\r\n");
  }

  strcat(buf, "\r\n");

  return buf;
}
