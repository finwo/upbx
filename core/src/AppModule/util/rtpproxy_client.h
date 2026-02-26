#ifndef UPBX_RTPPROXY_CLIENT_H
#define UPBX_RTPPROXY_CLIENT_H

#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>

typedef enum {
  RTPP_TYPE_UNIX,    /* unix:/path */
  RTPP_TYPE_CUNIX,  /* cunix:/path (connection-oriented) */
  RTPP_TYPE_TCP,    /* tcp://host:port */
  RTPP_TYPE_UDP,    /* udp://host:port */
} rtpp_type_t;

typedef struct {
  rtpp_type_t type;
  char *url;           /* Original URL */
  char *path;          /* For unix/cunix: socket path */
  char *host;          /* For tcp/udp: hostname */
  int port;            /* For tcp/udp: port (default 22222) */
  int sockfd;          /* Active socket fd */
  int connected;       /* 1 if connected */
} rtpp_client_t;

int rtpp_client_init(rtpp_client_t *client, const char *url);
void rtpp_client_cleanup(rtpp_client_t *client);

int rtpp_client_connect(rtpp_client_t *client);
void rtpp_client_disconnect(rtpp_client_t *client);

int rtpp_client_send(rtpp_client_t *client, const char *cmd, size_t cmd_len);
int rtpp_client_recv(rtpp_client_t *client, char *reply, size_t reply_len);

int rtpp_version(rtpp_client_t *client, char *version_out, size_t version_len);

int rtpp_update(rtpp_client_t *client,
                const char *call_id,
                const char *remote_ip, int remote_port,
                const char *from_tag, const char *to_tag,
                const char *opts,
                int *out_port, char *out_ip, size_t out_ip_len);

int rtpp_lookup(rtpp_client_t *client,
               const char *call_id,
               const char *remote_ip, int remote_port,
               const char *from_tag, const char *to_tag,
               const char *opts,
               int *out_port);

int rtpp_delete(rtpp_client_t *client,
                const char *call_id,
                const char *from_tag, const char *to_tag,
                int weak);

int rtpp_query(rtpp_client_t *client,
               const char *call_id,
               const char *from_tag, const char *to_tag,
               int verbose,
               char *stats_out, size_t stats_len);

/* Global singleton instance */
extern rtpp_client_t *rtpproxy_client;

/* Initialize global client from config - returns 0 on success */
int rtpproxy_client_global_init(void);

/* Get global client (may return NULL if not initialized) */
rtpp_client_t *rtpproxy_get_client(void);

/* Get fallback IP for SDP when rtpproxy doesn't return one:
 * - For TCP/UDP: return the configured rtpproxy host
 * - For Unix: return NULL (caller should use PBX's own IP)
 */
const char *rtpproxy_get_fallback_ip(void);

#endif
