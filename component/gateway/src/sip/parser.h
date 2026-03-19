#ifndef GW_SIP_PARSER_H
#define GW_SIP_PARSER_H

#include <stddef.h>
#include <sys/socket.h>

enum sip_method {
    SIP_METHOD_UNKNOWN,
    SIP_METHOD_REGISTER,
    SIP_METHOD_INVITE,
    SIP_METHOD_ACK,
    SIP_METHOD_BYE,
    SIP_METHOD_CANCEL,
    SIP_METHOD_OPTIONS,
};

struct sip_msg {
    enum sip_method method;
    char *method_str;
    char *uri;
    char *via;
    char *from;
    char *to;
    char *call_id;
    char *cseq_method;
    int   cseq_num;
    char *contact;
    char *authorization;
    char *www_authenticate;
    int   expires;
    int   content_length;
    char *content_type;
    char *body;
    int   body_len;
    int   status_code;
    char *reason;
};

struct sip_msg *sip_parse_request(const char *buf, int len);
void sip_msg_free(struct sip_msg *msg);
char *sip_extract_uri_user(const char *uri);
char *sip_extract_uri_host(const char *uri);

struct sip_auth {
    char *username;
    char *realm;
    char *nonce;
    char *uri;
    char *response;
};

struct sip_auth *sip_parse_auth(const char *header);
void sip_auth_free(struct sip_auth *auth);

#endif
