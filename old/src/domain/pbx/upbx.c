#include "upbx.h"
#include "domain/config.h"
#include "../../common/resp.h"
#include "../../common/digest_auth.h"
#include "../../common/socket_util.h"
#include "../../common/scheduler.h"
#include "domain/pbx/media_proxy.h"
#include "finwo/url-parser.h"
#include "rxi/log.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>

/* Forward declarations */
static struct registration *find_registration(const char *id);
static struct registration *find_registration_by_addr(const struct sockaddr_storage *addr);
static void handle_register(struct main_data *md, int fd, struct sip_msg *msg, const struct sockaddr_storage *src);
static void handle_invite(struct main_data *md, int fd, struct sip_msg *msg, const struct sockaddr_storage *src);
static void handle_ack(struct main_data *md, int fd, struct sip_msg *msg, const struct sockaddr_storage *src);
static void handle_cancel(struct main_data *md, int fd, struct sip_msg *msg, const struct sockaddr_storage *src);
static void handle_bye(struct main_data *md, int fd, struct sip_msg *msg, const struct sockaddr_storage *src);
static void send_options_reply(struct main_data *md, int fd, struct sip_msg *msg, const struct sockaddr_storage *src);
static void forward_in_dialog(struct main_data *md, int fd, struct sip_msg *msg, const struct sockaddr_storage *src);

/* Simple list implementation for our needs */
struct list {
    struct list_node *head;
    struct list_node *tail;
    size_t count;
};

struct list_node {
    void *data;
    struct list_node *next;
    struct list_node *prev;
};

static struct list *list_create(void) {
    struct list *list = calloc(1, sizeof(struct list));
    return list;
}

static void list_add(struct list *list, struct list_node *node) {
    if (!list || !node) return;
    
    node->next = NULL;
    node->prev = list->tail;
    
    if (list->tail) {
        list->tail->next = node;
    } else {
        list->head = node;
    }
    
    list->tail = node;
    list->count++;
}

static void list_remove(struct list *list, struct list_node *node) {
    if (!list || !node) return;
    
    if (node->prev) {
        node->prev->next = node->next;
    } else {
        list->head = node->next;
    }
    
    if (node->next) {
        node->next->prev = node->prev;
    } else {
        list->tail = node->prev;
    }
    
    list->count--;
}

#define LIST_FOR_EACH(list, node) \
    for (struct list_node *node = (list)->head; node != NULL; node = node->next)

#define LIST_FOR_EACH_SAFE(list, node, next) \
    for (struct list_node *node = (list)->head; node != NULL; node = next) { \
        struct list_node *next = node->next;