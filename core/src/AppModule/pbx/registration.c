#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>

#include "rxi/log.h"
#include "RespModule/resp.h"
#include "config.h"
#include "AppModule/pbx/registration.h"

#define MAX_REGISTRATIONS 1024
#define CLEANUP_INTERVAL_SEC 60

static registration_t *registrations[MAX_REGISTRATIONS];
static size_t registration_count = 0;
static char *registrations_dir = NULL;

void registration_set_dir(const char *path) {
    if (registrations_dir) free(registrations_dir);
    registrations_dir = path ? strdup(path) : NULL;
}

const char *registration_get_dir(void) {
    return registrations_dir;
}

static void sockaddr_to_string(const struct sockaddr *addr, char *buf, size_t buf_size) {
    if (!addr || !buf || buf_size == 0) return;
    
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &sin->sin_addr, buf, buf_size);
        size_t len = strlen(buf);
        if (buf_size - len > 6) {
            snprintf(buf + len, buf_size - len, ":%d", ntohs(sin->sin_port));
        }
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        buf[0] = '[';
        inet_ntop(AF_INET6, &sin6->sin6_addr, buf + 1, (socklen_t)(buf_size - 1));
        size_t len = strlen(buf);
        if (buf_size - len > 6) {
            snprintf(buf + len, buf_size - len, "]:%d", ntohs(sin6->sin6_port));
        }
    } else {
        buf[0] = '\0';
    }
}

static int string_to_sockaddr(const char *str, struct sockaddr_storage *addr) {
    if (!str || !addr) return -1;
    memset(addr, 0, sizeof(*addr));
    
    const char *port_str = strrchr(str, ':');
    if (!port_str) return -1;
    
    char host[256];
    size_t host_len = (size_t)(port_str - str);
    if (host_len >= sizeof(host)) return -1;
    memcpy(host, str, host_len);
    host[host_len] = '\0';
    
    int port = atoi(port_str + 1);
    if (port <= 0 || port > 65535) return -1;
    
    if (host[0] == '[' && host[host_len - 1] == ']') {
        host[host_len - 1] = '\0';
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, host + 1, &sin6->sin6_addr) != 1) return -1;
    } else {
        struct sockaddr_in *sin = (struct sockaddr_in *)addr;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, host, &sin->sin_addr) != 1) return -1;
    }
    
    return 0;
}

static int save_registration_to_file(const registration_t *reg) {
    if (!reg || !reg->number || !registrations_dir) return -1;
    
    if (mkdir(registrations_dir, 0755) != 0 && errno != EEXIST) {
        log_error("registration: failed to create directory %s: %s", registrations_dir, strerror(errno));
        return -1;
    }
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.reg", registrations_dir, reg->number);
    
    char addr_str[INET6_ADDRSTRLEN + 8] = "";
    sockaddr_to_string((const struct sockaddr *)&reg->remote_addr, addr_str, sizeof(addr_str));
    
    resp_object *obj = resp_array_init();
    if (!obj) return -1;
    
    resp_array_append_bulk(obj, "number");
    resp_array_append_bulk(obj, reg->number);
    resp_array_append_bulk(obj, "contact");
    resp_array_append_bulk(obj, reg->contact ? reg->contact : "");
    resp_array_append_bulk(obj, "remote_addr");
    resp_array_append_bulk(obj, addr_str);
    resp_array_append_bulk(obj, "expires_at");
    resp_array_append_int(obj, (long long)reg->expires_at);
    resp_array_append_bulk(obj, "registered_at");
    resp_array_append_int(obj, (long long)reg->registered_at);
    
    char *buf = NULL;
    size_t buf_len = 0;
    const resp_object *const argv[] = { obj };
    if (resp_encode_array(1, argv, &buf, &buf_len) != 0) {
        resp_free(obj);
        return -1;
    }
    
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        log_error("registration: failed to open %s: %s", path, strerror(errno));
        free(buf);
        resp_free(obj);
        return -1;
    }
    
    ssize_t written = write(fd, buf, buf_len);
    close(fd);
    free(buf);
    resp_free(obj);
    
    if (written != (ssize_t)buf_len) {
        log_error("registration: failed to write %s", path);
        return -1;
    }
    
    return 0;
}

static int delete_registration_file(const char *number) {
    if (!number || !registrations_dir) return -1;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.reg", registrations_dir, number);
    
    if (unlink(path) != 0 && errno != ENOENT) {
        log_error("registration: failed to delete %s: %s", path, strerror(errno));
        return -1;
    }
    
    return 0;
}

static registration_t *load_registration_from_file(const char *number) {
    if (!number || !registrations_dir) return NULL;
    
    char path[512];
    snprintf(path, sizeof(path), "%s/%s.reg", registrations_dir, number);
    
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    
    resp_object *obj = resp_read(fd);
    close(fd);
    
    if (!obj || obj->type != RESPT_ARRAY) {
        if (obj) resp_free(obj);
        return NULL;
    }
    
    const char *num = resp_map_get_string(obj, "number");
    if (!num || strcmp(num, number) != 0) {
        resp_free(obj);
        return NULL;
    }
    
    registration_t *reg = calloc(1, sizeof(registration_t));
    if (!reg) {
        resp_free(obj);
        return NULL;
    }
    
    reg->number = strdup(num);
    reg->contact = strdup(resp_map_get_string(obj, "contact") ? resp_map_get_string(obj, "contact") : "");
    
    const char *addr_str = resp_map_get_string(obj, "remote_addr");
    if (addr_str && addr_str[0]) {
        string_to_sockaddr(addr_str, &reg->remote_addr);
    }
    
    resp_object *val;
    val = resp_map_get(obj, "expires_at");
    reg->expires_at = val && val->type == RESPT_INT ? (time_t)val->u.i : 0;
    
    val = resp_map_get(obj, "registered_at");
    reg->registered_at = val && val->type == RESPT_INT ? (time_t)val->u.i : 0;
    
    resp_free(obj);
    return reg;
}

void registration_init(void) {
    if (!registrations_dir) {
        registrations_dir = strdup("/var/lib/upbx/registrations");
    }
    
    if (mkdir(registrations_dir, 0755) != 0 && errno != EEXIST) {
        log_warn("registration: could not create directory %s: %s", registrations_dir, strerror(errno));
        return;
    }
    
    log_info("registration: loading from %s", registrations_dir);
}

registration_t *registration_find(const char *number) {
    if (!number) return NULL;
    
    for (size_t i = 0; i < registration_count; i++) {
        if (registrations[i] && registrations[i]->number && 
            strcmp(registrations[i]->number, number) == 0) {
            if (registrations[i]->expires_at > 0 && registrations[i]->expires_at < time(NULL)) {
                continue;
            }
            return registrations[i];
        }
    }
    
    registration_t *reg = load_registration_from_file(number);
    if (reg) {
        if (reg->expires_at > 0 && reg->expires_at < time(NULL)) {
            registration_free(reg);
            delete_registration_file(number);
            return NULL;
        }
        if (registration_count < MAX_REGISTRATIONS) {
            registrations[registration_count++] = reg;
            return reg;
        }
        registration_free(reg);
    }
    
    return NULL;
}

int registration_add(const char *number, const char *contact,
                     const struct sockaddr *remote_addr, int expires_seconds) {
    if (!number) return -1;
    
    registration_t *reg = registration_find(number);
    if (!reg) {
        if (registration_count >= MAX_REGISTRATIONS) {
            log_error("registration: max registrations reached");
            return -1;
        }
        reg = calloc(1, sizeof(registration_t));
        if (!reg) return -1;
        reg->number = strdup(number);
        registrations[registration_count++] = reg;
    }
    
    if (reg->contact) free(reg->contact);
    reg->contact = contact ? strdup(contact) : strdup("");
    
    if (remote_addr) {
        memcpy(&reg->remote_addr, remote_addr, sizeof(reg->remote_addr));
    }
    
    time_t now = time(NULL);
    reg->registered_at = now;
    reg->expires_at = expires_seconds > 0 ? now + expires_seconds : 0;
    
    if (save_registration_to_file(reg) != 0) {
        log_error("registration: failed to save %s to file", number);
        if (reg->contact) { free(reg->contact); reg->contact = NULL; }
        reg->expires_at = 0;
        reg->registered_at = 0;
        return -1;
    }
    
    char addr_str[INET6_ADDRSTRLEN + 8] = "";
    if (remote_addr) {
        sockaddr_to_string(remote_addr, addr_str, sizeof(addr_str));
    }
    log_info("registration: %s registered from %s, expires in %d seconds", 
             number, addr_str[0] ? addr_str : "unknown", expires_seconds);
    
    return 0;
}

void registration_remove(const char *number) {
    if (!number) return;
    
    for (size_t i = 0; i < registration_count; i++) {
        if (registrations[i] && registrations[i]->number && 
            strcmp(registrations[i]->number, number) == 0) {
            
            log_info("registration: %s unregistered", number);
            
            registration_free(registrations[i]);
            
            for (size_t j = i; j < registration_count - 1; j++) {
                registrations[j] = registrations[j + 1];
            }
            registration_count--;
            registrations[registration_count] = NULL;
            
            delete_registration_file(number);
            return;
        }
    }
}

void registration_free(registration_t *reg) {
    if (!reg) return;
    free(reg->number);
    free(reg->contact);
    free(reg);
}

PT_THREAD(registration_cleanup_pt(struct pt *pt, int64_t timestamp, struct pt_task *task)) {
    (void)task;
    
    static int64_t last_cleanup = 0;
    
    log_trace("registration_cleanup: protothread entry");
    PT_BEGIN(pt);
    
    last_cleanup = timestamp;
    
    for (;;) {
        PT_WAIT_UNTIL(pt, timestamp - last_cleanup >= CLEANUP_INTERVAL_SEC * 1000);
        
        last_cleanup = timestamp;
        time_t now = time(NULL);
        
        for (size_t i = registration_count; i > 0; i--) {
            size_t idx = i - 1;
            registration_t *reg = registrations[idx];
            if (reg && reg->expires_at > 0 && reg->expires_at < now) {
                log_info("registration: %s expired", reg->number);
                char *number = strdup(reg->number);
                registration_remove(number);
                free(number);
            }
        }
    }
    
    PT_END(pt);
}
