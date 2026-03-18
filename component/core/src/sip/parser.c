#include "sip/parser.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *strdup_range(const char *start, const char *end) {
  if (!start || !end || end <= start) return NULL;
  size_t len = end - start;
  char *result = malloc(len + 1);
  if (!result) return NULL;
  memcpy(result, start, len);
  result[len] = '\0';
  return result;
}

static char *trim_whitespace(char *s) {
  if (!s) return s;
  while (isspace((unsigned char)*s)) s++;
  char *end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
  return s;
}

void sip_request_free(struct sip_request *req) {
  if (!req) return;
  free(req->method_str);
  free(req->uri);
  free(req->version);
  free(req->from);
  free(req->to);
  free(req->call_id);
  free(req->cseq);
  free(req->contact);
  free(req->via);
  free(req->branch);
  free(req->user_agent);
  free(req->content_type);
  free(req->authorization);
  free(req->proxy_authorization);
  free(req->body);
  free(req);
}

void sip_response_free(struct sip_response *resp) {
  if (!resp) return;
  free(resp->reason_phrase);
  free(resp->version);
  free(resp->via);
  free(resp->from);
  free(resp->to);
  free(resp->call_id);
  free(resp->cseq);
  free(resp->content_type);
  free(resp->body);
  free(resp);
}

enum sip_method sip_method_from_string(const char *str) {
  if (!str) return SIP_METHOD_UNKNOWN;
  if (strcmp(str, "INVITE") == 0) return SIP_METHOD_INVITE;
  if (strcmp(str, "ACK") == 0) return SIP_METHOD_ACK;
  if (strcmp(str, "BYE") == 0) return SIP_METHOD_BYE;
  if (strcmp(str, "CANCEL") == 0) return SIP_METHOD_CANCEL;
  if (strcmp(str, "OPTIONS") == 0) return SIP_METHOD_OPTIONS;
  if (strcmp(str, "REGISTER") == 0) return SIP_METHOD_REGISTER;
  if (strcmp(str, "PRACK") == 0) return SIP_METHOD_PRACK;
  if (strcmp(str, "NOTIFY") == 0) return SIP_METHOD_NOTIFY;
  if (strcmp(str, "SUBSCRIBE") == 0) return SIP_METHOD_SUBSCRIBE;
  if (strcmp(str, "INFO") == 0) return SIP_METHOD_INFO;
  if (strcmp(str, "REFER") == 0) return SIP_METHOD_REFER;
  if (strcmp(str, "MESSAGE") == 0) return SIP_METHOD_MESSAGE;
  return SIP_METHOD_UNKNOWN;
}

const char *sip_method_to_string(enum sip_method method) {
  switch (method) {
    case SIP_METHOD_INVITE: return "INVITE";
    case SIP_METHOD_ACK: return "ACK";
    case SIP_METHOD_BYE: return "BYE";
    case SIP_METHOD_CANCEL: return "CANCEL";
    case SIP_METHOD_OPTIONS: return "OPTIONS";
    case SIP_METHOD_REGISTER: return "REGISTER";
    case SIP_METHOD_PRACK: return "PRACK";
    case SIP_METHOD_NOTIFY: return "NOTIFY";
    case SIP_METHOD_SUBSCRIBE: return "SUBSCRIBE";
    case SIP_METHOD_INFO: return "INFO";
    case SIP_METHOD_REFER: return "REFER";
    case SIP_METHOD_MESSAGE: return "MESSAGE";
    default: return "UNKNOWN";
  }
}

static char *extract_header_value(const char *headers, const char *name) {
  if (!headers || !name) return NULL;

  size_t name_len = strlen(name);
  const char *pos = headers;

  while (*pos) {
    if (strncasecmp(pos, name, name_len) == 0 && pos[name_len] == ':') {
      const char *value_start = pos + name_len + 1;
      while (*value_start == ' ') value_start++;
      const char *value_end = strstr(value_start, "\r\n");
      if (!value_end) value_end = value_start + strlen(value_start);
      while (value_end > value_start && isspace((unsigned char)*(value_end - 1))) value_end--;
      return strdup_range(value_start, value_end);
    }
    pos = strstr(pos, "\r\n");
    if (!pos) break;
    pos += 2;
  }

  return NULL;
}

static char *extract_branch_from_via(const char *via) {
  if (!via) return NULL;

  const char *branch = strstr(via, "branch=");
  if (!branch) return NULL;

  branch += 7;
  while (*branch == ' ') branch++;

  const char *end = branch;
  while (*end && !isspace((unsigned char)*end) && *end != ';') end++;

  return strdup_range(branch, end);
}

struct sip_request *sip_parse_request(const char *data, size_t len) {
  if (!data || len == 0) return NULL;

  char *buf = malloc(len + 1);
  memcpy(buf, data, len);
  buf[len] = '\0';

  struct sip_request *req = calloc(1, sizeof(*req));

  const char *start = buf;
  const char *end = strstr(start, "\r\n");
  if (!end) {
    end = strstr(start, "\n");
  }
  if (!end) {
    free(buf);
    sip_request_free(req);
    return NULL;
  }

  char *line = strndup(start, end - start);
  
  char *method_end = strchr(line, ' ');
  if (method_end) {
    req->method_str = strndup(line, method_end - line);
    req->method = sip_method_from_string(req->method_str);
    
    char *uri_start = method_end + 1;
    while (*uri_start == ' ') uri_start++;
    char *uri_end = strchr(uri_start, ' ');
    if (uri_end) {
      req->uri = strndup(uri_start, uri_end - uri_start);
      req->version = strdup(uri_end + 1);
    } else {
      req->uri = strdup(uri_start);
    }
  } else {
    req->method_str = strdup(line);
    req->method = sip_method_from_string(req->method_str);
  }
  free(line);

  const char *headers = end + (end[0] == '\r' && end[1] == '\n' ? 2 : 1);
  const char *body = strstr(headers, "\r\n\r\n");
  if (body) {
    req->body_len = len - (body + 4 - buf);
    req->body = req->body_len > 0 ? strdup(body + 4) : NULL;
  }

  req->from = extract_header_value(headers, "From");
  req->to = extract_header_value(headers, "To");
  req->call_id = extract_header_value(headers, "Call-ID");
  req->cseq = extract_header_value(headers, "CSeq");
  req->contact = extract_header_value(headers, "Contact");
  req->via = extract_header_value(headers, "Via");
  req->user_agent = extract_header_value(headers, "User-Agent");
  req->content_type = extract_header_value(headers, "Content-Type");
  req->authorization = extract_header_value(headers, "Authorization");
  req->proxy_authorization = extract_header_value(headers, "Proxy-Authorization");

  char *cl = extract_header_value(headers, "Content-Length");
  if (cl) {
    req->content_length = atoi(cl);
    free(cl);
  }

  char *exp = extract_header_value(headers, "Expires");
  if (exp) {
    req->expires = atoi(exp);
    free(exp);
  }

  if (req->via) {
    req->branch = extract_branch_from_via(req->via);
  }

  free(buf);
  return req;
}

struct sip_response *sip_parse_response(const char *data, size_t len) {
  if (!data || len == 0) return NULL;

  char *buf = malloc(len + 1);
  memcpy(buf, data, len);
  buf[len] = '\0';

  struct sip_response *resp = calloc(1, sizeof(*resp));

  const char *start = buf;
  const char *end = strstr(start, "\r\n");
  if (!end) {
    free(buf);
    sip_response_free(resp);
    return NULL;
  }

  resp->version = strdup_range(start, end);

  const char *status_start = end + 1;
  while (*status_start == ' ') status_start++;
  const char *status_end = status_start;
  while (*status_end && !isspace((unsigned char)*status_end)) status_end++;

  char *status_code_str = strdup_range(status_start, status_end);
  if (status_code_str) {
    resp->status_code = atoi(status_code_str);
    free(status_code_str);
  }

  const char *reason_start = status_end;
  while (*reason_start == ' ') reason_start++;
  const char *reason_end = strstr(reason_start, "\r\n");
  if (!reason_end) reason_end = reason_start + strlen(reason_start);
  resp->reason_phrase = strdup_range(reason_start, reason_end);

  const char *headers = end + 2;
  const char *body = strstr(headers, "\r\n\r\n");
  if (body) {
    resp->body_len = len - (body + 4 - buf);
    resp->body = resp->body_len > 0 ? strdup(body + 4) : NULL;
  }

  resp->via = extract_header_value(headers, "Via");
  resp->from = extract_header_value(headers, "From");
  resp->to = extract_header_value(headers, "To");
  resp->call_id = extract_header_value(headers, "Call-ID");
  resp->cseq = extract_header_value(headers, "CSeq");
  resp->content_type = extract_header_value(headers, "Content-Type");

  char *cl = extract_header_value(headers, "Content-Length");
  if (cl) {
    resp->content_length = atoi(cl);
    free(cl);
  }

  free(buf);
  return resp;
}
