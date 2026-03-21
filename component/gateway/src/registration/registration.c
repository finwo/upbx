#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "rxi/log.h"
#include "finwo/socket-util.h"
#include "md5/md5.h"
#include "registration/registration.h"

/* ── helpers ────────────────────────────────────────────────────────── */

static void mkdirs(const char *path) {
    char tmp[512];
    strncpy(tmp, path, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void ensure_dirs(const char *data_dir) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registration/by-ext", data_dir);
    mkdirs(path);
    snprintf(path, sizeof(path), "%s/registration/by-adr", data_dir);
    mkdirs(path);
}

static char *addr_to_md5(struct sockaddr_storage *addr) {
    char addr_str[128];
    sockaddr_to_string((struct sockaddr *)addr, addr_str, sizeof(addr_str));
    uint8_t digest[16];
    gw_md5((const uint8_t *)addr_str, strlen(addr_str), digest);
    char *hex = malloc(33);
    if (!hex) return NULL;
    gw_md5_hex(digest, hex);
    return hex;
}

static int parse_line_value(const char *buf, const char *key, char *out, size_t out_size) {
    const char *p = buf;
    size_t klen = strlen(key);
    while (p && *p) {
        const char *nl = strchr(p, '\n');
        size_t line_len = nl ? (size_t)(nl - p) : strlen(p);
        if (line_len > klen + 1 && memcmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *val = p + klen + 1;
            size_t vlen = line_len - klen - 1;
            if (vlen >= out_size) vlen = out_size - 1;
            memcpy(out, val, vlen);
            out[vlen] = '\0';
            return 1;
        }
        p = nl ? nl + 1 : NULL;
    }
    return 0;
}

static char *build_buffer(const char *extension, struct sockaddr_storage *remote_addr,
                          const char *contact, const char *pbx_addr,
                          time_t expires) {
    char addr_str[128];
    sockaddr_to_string((struct sockaddr *)remote_addr, addr_str, sizeof(addr_str));
    char *buf = malloc(1024);
    if (!buf) return NULL;
    snprintf(buf, 1024,
        "ext=%s\n"
        "remote_addr=%s\n"
        "contact=%s\n"
        "pbx_addr=%s\n"
        "expires=%ld\n",
        extension, addr_str,
        contact ? contact : "",
        pbx_addr ? pbx_addr : "",
        (long)expires);
    return buf;
}

/* ── public API ─────────────────────────────────────────────────────── */

void registration_save(const char *data_dir, const char *extension,
                       struct sockaddr_storage *remote_addr,
                       const char *contact, const char *pbx_addr, time_t expires) {
    ensure_dirs(data_dir);
    char *buf = build_buffer(extension, remote_addr, contact, pbx_addr, expires);
    if (!buf) return;

    char *md5 = addr_to_md5(remote_addr);
    if (!md5) { free(buf); return; }

    char path[512];

    /* Write to by-ext */
    snprintf(path, sizeof(path), "%s/registration/by-ext/%s", data_dir, extension);
    FILE *f = fopen(path, "w");
    if (f) { fwrite(buf, 1, strlen(buf), f); fclose(f); }

    /* Write same buffer to by-adr */
    snprintf(path, sizeof(path), "%s/registration/by-adr/%s", data_dir, md5);
    f = fopen(path, "w");
    if (f) { fwrite(buf, 1, strlen(buf), f); fclose(f); }

    log_info("registration: saved %s (addr %s)", extension, md5);
    free(buf);
    free(md5);
}

void registration_delete(const char *data_dir, const char *extension) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registration/by-ext/%s", data_dir, extension);

    /* Read old file to get remote_addr for md5 */
    FILE *f = fopen(path, "r");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);

    char addr_str[128];
    if (parse_line_value(buf, "remote_addr", addr_str, sizeof(addr_str))) {
        struct sockaddr_storage addr;
        memset(&addr, 0, sizeof(addr));
        if (string_to_sockaddr(addr_str, &addr)) {
            char *md5 = addr_to_md5(&addr);
            if (md5) {
                char adr_path[512];
                snprintf(adr_path, sizeof(adr_path), "%s/registration/by-adr/%s", data_dir, md5);
                remove(adr_path);
                free(md5);
            }
        }
    }

    remove(path);
    free(buf);
    log_info("registration: deleted %s", extension);
}

int registration_load(const char *data_dir, const char *extension,
                      struct sockaddr_storage *remote_addr_out,
                      char **contact_out, char **pbx_addr_out, time_t *expires_out) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registration/by-ext/%s", data_dir, extension);

    FILE *f = fopen(path, "r");
    if (!f) return 0;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return 0; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);

    time_t expires = 0;
    char val[256];

    if (parse_line_value(buf, "expires", val, sizeof(val))) {
        expires = (time_t)atol(val);
    }
    if (expires > 0 && expires < time(NULL)) {
        free(buf);
        return 0; /* expired */
    }

    if (expires_out) *expires_out = expires;

    if (remote_addr_out) {
        memset(remote_addr_out, 0, sizeof(*remote_addr_out));
        if (parse_line_value(buf, "remote_addr", val, sizeof(val)))
            string_to_sockaddr(val, remote_addr_out);
    }

    if (contact_out) {
        *contact_out = NULL;
        if (parse_line_value(buf, "contact", val, sizeof(val)) && val[0])
            *contact_out = strdup(val);
    }

    if (pbx_addr_out) {
        *pbx_addr_out = NULL;
        if (parse_line_value(buf, "pbx_addr", val, sizeof(val)) && val[0])
            *pbx_addr_out = strdup(val);
    }

    free(buf);
    return 1;
}

char *registration_find_by_addr(const char *data_dir, struct sockaddr_storage *src) {
    char *md5 = addr_to_md5(src);
    if (!md5) return NULL;

    char path[512];
    snprintf(path, sizeof(path), "%s/registration/by-adr/%s", data_dir, md5);
    free(md5);

    FILE *f = fopen(path, "r");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    fread(buf, 1, (size_t)sz, f);
    buf[sz] = '\0';
    fclose(f);

    /* Check expiry */
    char val[256];
    time_t expires = 0;
    if (parse_line_value(buf, "expires", val, sizeof(val)))
        expires = (time_t)atol(val);

    if (expires > 0 && expires < time(NULL)) {
        free(buf);
        return NULL; /* expired */
    }

    /* Extract extension */
    char *ext = NULL;
    if (parse_line_value(buf, "ext", val, sizeof(val)))
        ext = strdup(val);

    free(buf);
    return ext;
}

void registration_cleanup_once(const char *data_dir) {
    char dirpath[512];
    snprintf(dirpath, sizeof(dirpath), "%s/registration/by-ext", data_dir);

    DIR *d = opendir(dirpath);
    if (!d) return;

    time_t now = time(NULL);
    struct dirent *ent;
    int cleaned = 0;

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        char path[512];
        snprintf(path, sizeof(path), "%s/registration/by-ext/%s", data_dir, ent->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;

        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        char *buf = malloc((size_t)sz + 1);
        if (!buf) { fclose(f); continue; }
        fread(buf, 1, (size_t)sz, f);
        buf[sz] = '\0';
        fclose(f);

        char val[256];
        time_t expires = 0;
        if (parse_line_value(buf, "expires", val, sizeof(val)))
            expires = (time_t)atol(val);

        if (expires > 0 && expires < now) {
            /* Expired — delete both files */
            if (parse_line_value(buf, "remote_addr", val, sizeof(val))) {
                struct sockaddr_storage addr;
                memset(&addr, 0, sizeof(addr));
                if (string_to_sockaddr(val, &addr)) {
                    char *md5 = addr_to_md5(&addr);
                    if (md5) {
                        char adr_path[512];
                        snprintf(adr_path, sizeof(adr_path), "%s/registration/by-adr/%s", data_dir, md5);
                        remove(adr_path);
                        free(md5);
                    }
                }
            }
            remove(path);
            log_info("registration: cleanup removed expired %s", ent->d_name);
            cleaned++;
        }

        free(buf);
    }

    closedir(d);
}
