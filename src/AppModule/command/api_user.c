/*
 * CLI commands for managing API users in the config file.
 * Usage:
 *   upbx [-f config] api-user list
 *   upbx [-f config] api-user add [--permit PATTERN]... <username> <secret>
 *   upbx [-f config] api-user remove|rm <username>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "CliModule/common.h"

static void usage(void) {
  fprintf(stderr, "Usage: upbx [-f config] api-user <list|add|remove|rm>\n");
  fprintf(stderr, "  list                                         List API users\n");
  fprintf(stderr, "  add [--permit PATTERN]... <username> <secret> Add an API user\n");
  fprintf(stderr, "  remove|rm <username>                         Remove an API user\n");
}

static int cmd_list(const char *config_path) {
  upbx_config c;
  config_init(&c);
  int rc = config_load(&c, config_path);
  if (rc != 0) {
    fprintf(stderr, "Error loading config: %s (rc=%d)\n", config_path, rc);
    config_free(&c);
    return 1;
  }
  if (c.api.user_count == 0) {
    printf("No API users configured.\n");
  } else {
    printf("%-15s %-40s\n", "USERNAME", "PERMITS");
    printf("%-15s %-40s\n", "--------", "-------");
    for (size_t i = 0; i < c.api.user_count; i++) {
      config_api_user *u = &c.api.users[i];
      char permits_buf[256] = "";
      for (size_t j = 0; j < u->permit_count; j++) {
        if (j) strncat(permits_buf, ", ", sizeof(permits_buf) - strlen(permits_buf) - 1);
        if (u->permits[j]) strncat(permits_buf, u->permits[j], sizeof(permits_buf) - strlen(permits_buf) - 1);
      }
      printf("%-15s %-40s\n",
        u->username ? u->username : "",
        permits_buf);
    }
  }
  config_free(&c);
  return 0;
}

/* Collect all --permit values from argv. Returns count. */
static size_t collect_permits(int argc, const char **argv, const char **out, size_t max_out) {
  size_t n = 0;
  for (int i = 0; i < argc - 1 && n < max_out; i++) {
    if (strcmp(argv[i], "--permit") == 0) {
      out[n++] = argv[i + 1];
      i++; /* skip value */
    }
  }
  return n;
}

static int cmd_add(const char *config_path, const char *username, const char *secret,
                   int argc, const char **argv) {
  if (!username || !secret) {
    fprintf(stderr, "Error: <username> and <secret> are required for add\n");
    usage();
    return 1;
  }

  /* Verify the user doesn't already exist. */
  upbx_config c;
  config_init(&c);
  int rc = config_load(&c, config_path);
  if (rc != 0) {
    fprintf(stderr, "Error loading config: %s (rc=%d)\n", config_path, rc);
    config_free(&c);
    return 1;
  }
  for (size_t i = 0; i < c.api.user_count; i++) {
    if (c.api.users[i].username && strcmp(c.api.users[i].username, username) == 0) {
      fprintf(stderr, "Error: API user '%s' already exists\n", username);
      config_free(&c);
      return 1;
    }
  }
  config_free(&c);

  /* Collect --permit flags */
  const char *permits[32];
  size_t permit_count = collect_permits(argc, argv, permits, 32);

  /* Append the new section to the config file. */
  FILE *f = fopen(config_path, "a");
  if (!f) {
    perror("fopen");
    return 1;
  }
  fprintf(f, "\n[api:%s]\n", username);
  fprintf(f, "secret = %s\n", secret);
  for (size_t i = 0; i < permit_count; i++)
    fprintf(f, "permit = %s\n", permits[i]);
  fclose(f);
  printf("Added API user '%s'\n", username);
  return 0;
}

static int cmd_remove(const char *config_path, const char *username) {
  if (!username) {
    fprintf(stderr, "Error: <username> is required for remove\n");
    usage();
    return 1;
  }

  /* Read entire file, skip the [api:username] section, write back. */
  FILE *f = fopen(config_path, "r");
  if (!f) { perror("fopen"); return 1; }
  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);
  char *content = malloc((size_t)fsize + 1);
  if (!content) { fclose(f); return 1; }
  size_t nread = fread(content, 1, (size_t)fsize, f);
  content[nread] = '\0';
  fclose(f);

  char section_header[128];
  snprintf(section_header, sizeof(section_header), "[api:%s]", username);

  char *sec_start = strstr(content, section_header);
  if (!sec_start) {
    fprintf(stderr, "Error: API user '%s' not found in config\n", username);
    free(content);
    return 1;
  }

  /* Find end of section: next '[' at start of line, or end of file. */
  char *sec_end = sec_start + strlen(section_header);
  while (*sec_end) {
    if (*sec_end == '[' && (sec_end == content || sec_end[-1] == '\n'))
      break;
    sec_end++;
  }

  /* Remove trailing blank lines before next section. */
  while (sec_start > content && sec_start[-1] == '\n') sec_start--;
  if (sec_start > content) sec_start++; /* keep one newline */

  f = fopen(config_path, "w");
  if (!f) { perror("fopen"); free(content); return 1; }
  fwrite(content, 1, (size_t)(sec_start - content), f);
  if (*sec_end)
    fwrite(sec_end, 1, strlen(sec_end), f);
  fclose(f);
  free(content);
  printf("Removed API user '%s'\n", username);
  return 0;
}

int appmodule_cmd_api_user(int argc, const char **argv) {
  if (argc < 2) { usage(); return 1; }
  const char *subcmd = argv[1];
  const char *config_path = cli_config_path();
  if (!config_path) {
    fprintf(stderr, "Error: no config file found (use -f or place config in a default location)\n");
    return 1;
  }

  if (strcmp(subcmd, "list") == 0)
    return cmd_list(config_path);

  if (strcmp(subcmd, "add") == 0) {
    const char *pos[2] = {NULL, NULL};
    cli_collect_positional(argc, argv, 2, pos, 2);
    return cmd_add(config_path, pos[0], pos[1], argc, argv);
  }

  if (strcmp(subcmd, "remove") == 0 || strcmp(subcmd, "rm") == 0) {
    const char *pos[1] = {NULL};
    cli_collect_positional(argc, argv, 2, pos, 1);
    return cmd_remove(config_path, pos[0]);
  }

  fprintf(stderr, "Unknown subcommand: %s\n", subcmd);
  usage();
  return 1;
}
