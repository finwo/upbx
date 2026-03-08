#include "domain/pbx/sip_parser.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/digest_auth.h"

static char *strdup_slice(const char *start, const char *end) {
  if (!start || !end || end <= start) return NULL;
  size_t len = (size_t)(end - start);
  char *s = malloc(len + 1);
  if (!s) return NULL;
  memcpy(s, start, len);
  s[len] = '\0';
  return s;
}

static char *trim(char *s) {
  while (s && *s && isspace((unsigned char)*s)) s++;
  if (!s || !*s) return s;
  char *end = s + strlen(s) - 1;
  while (end > s && isspace((unsigned char)*end)) end--;
  end[1] = '\0';
  return s;
}

static char *extract_tag(const char *header_value) {
  if (!header_value) return NULL;
  const char *tag = strstr(header_value, "tag=");
  if (!tag) return NULL;
  tag += 4;
  const char *end = tag;
  while (*end && *end != ';' && *end != ' ') end++;
  return strdup_slice(tag, end);
}

void sip_message_free(sip_message_t *msg) {
  if (!msg) return;
  free(msg->method);
  free(msg->uri);
  free(msg->via);
  free(msg->from);
  free(msg->to);
  free(msg->call_id);
  free(msg->contact);
  free(msg->cseq_method);
  free(msg->from_tag);
  free(msg->to_tag);
  free(msg->authorization);
  free(msg->www_authenticate);
  free(msg->content_type);
  free(msg->body);
  free(msg->raw_request_line);
  free(msg);
}

static char *header_value(sip_message_t *msg, const char *name) {
  if (!msg || !name) return NULL;
  if (strcmp(name, "via") == 0) return msg->via;
  if (strcmp(name, "from") == 0) return msg->from;
  if (strcmp(name, "to") == 0) return msg->to;
  if (strcmp(name, "call-id") == 0) return msg->call_id;
  if (strcmp(name, "contact") == 0) return msg->contact;
  if (strcmp(name, "authorization") == 0) return msg->authorization;
  if (strcmp(name, "www-authenticate") == 0) return msg->www_authenticate;
  if (strcmp(name, "content-type") == 0) return msg->content_type;
  return NULL;
}

sip_message_t *sip_parse(const char *buf, size_t len) {
  if (!buf || len == 0) return NULL;

  char *data = malloc(len + 1);
  if (!data) return NULL;
  memcpy(data, buf, len);
  data[len] = '\0';

  sip_message_t *msg = calloc(1, sizeof(sip_message_t));
  if (!msg) {
    free(data);
    return NULL;
  }

  char *line, *saveptr;
  char *data_copy = data;

  line = strtok_r(data_copy, "\r\n", &saveptr);
  if (line) {
    msg->raw_request_line = strdup(line);

    char *method_end = strchr(line, ' ');
    if (method_end) {
      msg->method = strdup_slice(line, method_end);
      char *uri_start = method_end + 1;
      char *uri_end = strchr(uri_start, ' ');
      if (uri_end) {
        msg->uri = strdup_slice(uri_start, uri_end);
      } else {
        msg->uri = strdup(uri_start);
      }
    }
  }

  while ((line = strtok_r(NULL, "\r\n", &saveptr)) != NULL) {
    if (line[0] == '\0') {
      msg->body = strdup(line + 1);
      if (msg->body && *msg->body == '\0') {
        free(msg->body);
        msg->body = NULL;
      }
      break;
    }

    char *colon = strchr(line, ':');
    if (!colon) continue;
    *colon = '\0';
    char *name = trim(line);
    char *value = trim(colon + 1);

    if (strcasecmp(name, "Via") == 0) {
      msg->via = strdup(value);
    } else if (strcasecmp(name, "From") == 0) {
      msg->from = strdup(value);
      msg->from_tag = extract_tag(value);
    } else if (strcasecmp(name, "To") == 0) {
      msg->to = strdup(value);
      msg->to_tag = extract_tag(value);
    } else if (strcasecmp(name, "Call-ID") == 0 || strcasecmp(name, "Call-Id") == 0) {
      msg->call_id = strdup(value);
    } else if (strcasecmp(name, "Contact") == 0) {
      msg->contact = strdup(value);
    } else if (strcasecmp(name, "CSeq") == 0) {
      char *cseq_end = strchr(value, ' ');
      if (cseq_end) {
        msg->cseq = atoi(value);
        msg->cseq_method = strdup(trim(cseq_end + 1));
      } else {
        msg->cseq = atoi(value);
      }
    } else if (strcasecmp(name, "Content-Length") == 0) {
      msg->content_length = atoi(value);
    } else if (strcasecmp(name, "Authorization") == 0) {
      msg->authorization = strdup(value);
    } else if (strcasecmp(name, "WWW-Authenticate") == 0) {
      msg->www_authenticate = strdup(value);
    } else if (strcasecmp(name, "Content-Type") == 0) {
      msg->content_type = strdup(value);
    }
  }

  free(data);
  return msg;
}

int sip_is_request(const sip_message_t *msg) {
  if (!msg || !msg->method) return 0;
  return strcmp(msg->method, "INVITE") == 0 ||
         strcmp(msg->method, "ACK") == 0 ||
         strcmp(msg->method, "BYE") == 0 ||
         strcmp(msg->method, "CANCEL") == 0 ||
         strcmp(msg->method, "REGISTER") == 0 ||
         strcmp(msg->method, "OPTIONS") == 0 ||
         strcmp(msg->method, "INFO") == 0 ||
         strcmp(msg->method, "NOTIFY") == 0 ||
         strcmp(msg->method, "MESSAGE") == 0 ||
         strcmp(msg->method, "PRACK") == 0 ||
         strcmp(msg->method, "UPDATE") == 0;
}

int sip_response_status_code(const sip_message_t *msg) {
  if (!msg || !msg->uri) return 0;
  if (isdigit((unsigned char)msg->uri[0]) && isdigit((unsigned char)msg->uri[1]) && isdigit((unsigned char)msg->uri[2])) {
    return atoi(msg->uri);
  }
  return 0;
}

const char *sip_header_get(const sip_message_t *msg, const char *name) {
  return header_value(msg, name);
}

char *sip_header_copy(const sip_message_t *msg, const char *name) {
  char *v = header_value(msg, name);
  return v ? strdup(v) : NULL;
}

char *sip_request_uri_user(const sip_message_t *msg) {
  if (!msg || !msg->uri) return NULL;
  if (strncmp(msg->uri, "sip:", 4) == 0) {
    const char *user_start = msg->uri + 4;
    const char *at = strchr(user_start, '@');
    if (at) {
      const char *port = strchr(user_start, ':');
      const char *end = at;
      if (port && port < at) end = port;
      return strdup_slice(user_start, end);
    }
  }
  return NULL;
}

char *sip_request_uri_user_from_to(const sip_message_t *msg) {
  if (!msg || !msg->to) return NULL;
  const char *to = msg->to;
  if (to[0] == '<') {
    to = strchr(to, '<');
    if (to) to++;
    const char *end = strchr(to, '>');
    if (end) {
      size_t len = (size_t)(end - to);
      char *tmp = malloc(len + 1);
      memcpy(tmp, to, len);
      tmp[len] = '\0';
      char *result = sip_request_uri_user(&(sip_message_t){.uri = tmp});
      free(tmp);
      return result;
    }
  }
  if (strncmp(to, "sip:", 4) == 0) {
    const char *user_start = to + 4;
    const char *at = strchr(user_start, '@');
    if (at) {
      const char *port = strchr(user_start, ':');
      const char *end = at;
      if (port && port < at) end = port;
      return strdup_slice(user_start, end);
    }
  }
  return NULL;
}

char *sip_request_uri_host_port(const sip_message_t *msg) {
  if (!msg || !msg->uri) return NULL;
  const char *host_start;
  if (strncmp(msg->uri, "sip:", 4) == 0) {
    host_start = msg->uri + 4;
    const char *at = strchr(host_start, '@');
    if (at) host_start = at + 1;
  } else {
    host_start = msg->uri;
  }

  const char *end = strchr(host_start, ';');
  if (!end) end = host_start + strlen(host_start);

  char *result = malloc((size_t)(end - host_start) + 1);
  if (!result) return NULL;
  memcpy(result, host_start, (size_t)(end - host_start));
  result[end - host_start] = '\0';
  return result;
}

char *sip_format_request_uri(const char *user, const char *host_port) {
  if (!user || !host_port) return NULL;
  char *result = malloc(strlen(user) + strlen(host_port) + 5);
  sprintf(result, "sip:%s@%s", user, host_port);
  return result;
}

void sip_rewrite_request_uri(sip_message_t *msg, const char *new_uri) {
  if (!msg || !new_uri) return;
  free(msg->uri);
  msg->uri = strdup(new_uri);
}

void sip_prepend_via(sip_message_t *msg, const char *via) {
  if (!msg || !via) return;
  if (msg->via) {
    char *old_via = msg->via;
    msg->via = malloc(strlen(via) + strlen(old_via) + 3);
    sprintf(msg->via, "%s\r\n%s", via, old_via);
    free(old_via);
  } else {
    msg->via = strdup(via);
  }
}

void sip_strip_top_via(sip_message_t *msg) {
  if (!msg || !msg->via) return;
  char *first_via_end = strstr(msg->via, "\r\n");
  if (first_via_end) {
    char *rest = first_via_end + 2;
    while (*rest == ' ' || *rest == '\t') rest++;
    if (*rest == '\0') {
      free(msg->via);
      msg->via = NULL;
    } else {
      char *new_via = strdup(rest);
      free(msg->via);
      msg->via = new_via;
    }
  }
}

static char *parse_auth_param(const char *auth_header, const char *param) {
  if (!auth_header || !param) return NULL;
  const char *p = strstr(auth_header, param);
  if (!p) return NULL;
  p += strlen(param);
  while (*p == ' ' || *p == '=' || *p == '"') p++;
  const char *end = p;
  while (*end && *end != '"' && *end != ',') end++;
  return strdup_slice(p, end);
}

int sip_security_check_raw(const char *auth_header, const char *method, const char *uri, const char *password) {
  if (!auth_header || !method || !uri || !password) return -1;

  char *username = parse_auth_param(auth_header, "username=");
  char *realm = parse_auth_param(auth_header, "realm=");
  char *nonce = parse_auth_param(auth_header, "nonce=");
  char *uri_in_auth = parse_auth_param(auth_header, "uri=");
  char *response = parse_auth_param(auth_header, "response=");

  if (!username || !realm || !nonce || !uri_in_auth || !response) {
    free(username);
    free(realm);
    free(nonce);
    free(uri_in_auth);
    free(response);
    return -1;
  }

  HASHHEX ha1, ha2, expected_response;
  digest_calc_ha1(username, realm, password, ha1);
  digest_calc_ha2(method, uri_in_auth, ha2);
  digest_calc_response(ha1, nonce, ha2, expected_response);

  int result = strcasecmp(response, expected_response);

  free(username);
  free(realm);
  free(nonce);
  free(uri_in_auth);
  free(response);

  return result == 0 ? 0 : -1;
}
