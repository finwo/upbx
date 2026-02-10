/*
 * CLI commands for managing trunks in the config file.
 * Usage:
 *   upbx [-f config] trunk list
 *   upbx [-f config] trunk add [--host H --username U --password P --did D --cid C] <trunkname>
 *   upbx [-f config] trunk remove|rm <trunkname>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "CliModule/common.h"

static void usage(void) {
  fprintf(stderr, "Usage: upbx [-f config] trunk <list|add|remove|rm>\n");
  fprintf(stderr, "  list                                             List trunks\n");
  fprintf(stderr, "  add [--host H --username U --password P] <name>  Add a trunk\n");
  fprintf(stderr, "  remove|rm <name>                                 Remove a trunk\n");
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
  if (c.trunk_count == 0) {
    printf("No trunks configured.\n");
  } else {
    printf("%-15s %-25s %-15s %-20s\n", "NAME", "HOST", "USERNAME", "DIDs");
    printf("%-15s %-25s %-15s %-20s\n", "----", "----", "--------", "----");
    for (size_t i = 0; i < c.trunk_count; i++) {
      config_trunk *t = &c.trunks[i];
      /* Build comma-separated DID string. */
      char dids_buf[256] = "";
      for (size_t j = 0; j < t->did_count; j++) {
        if (j) strncat(dids_buf, ",", sizeof(dids_buf) - strlen(dids_buf) - 1);
        if (t->dids[j]) strncat(dids_buf, t->dids[j], sizeof(dids_buf) - strlen(dids_buf) - 1);
      }
      char host_port[280] = "";
      if (t->host) {
        strncpy(host_port, t->host, sizeof(host_port) - 1);
        if (t->port && strcmp(t->port, "5060") != 0) {
          strncat(host_port, ":", sizeof(host_port) - strlen(host_port) - 1);
          strncat(host_port, t->port, sizeof(host_port) - strlen(host_port) - 1);
        }
      }
      printf("%-15s %-25s %-15s %-20s\n",
        t->name ? t->name : "",
        host_port,
        t->username ? t->username : "",
        dids_buf);
    }
  }
  config_free(&c);
  return 0;
}

static int cmd_add(const char *config_path, const char *name, int argc, const char **argv) {
  const char *host     = cli_find_arg(argc, argv, "--host");
  const char *username = cli_find_arg(argc, argv, "--username");
  const char *password = cli_find_arg(argc, argv, "--password");
  const char *did      = cli_find_arg(argc, argv, "--did");
  const char *cid      = cli_find_arg(argc, argv, "--cid");

  if (!name || !host || !username || !password) {
    fprintf(stderr, "Error: <name>, --host, --username, and --password are required for add\n");
    usage();
    return 1;
  }

  /* Verify the trunk doesn't already exist. */
  upbx_config c;
  config_init(&c);
  int rc = config_load(&c, config_path);
  if (rc != 0) {
    fprintf(stderr, "Error loading config: %s (rc=%d)\n", config_path, rc);
    config_free(&c);
    return 1;
  }
  for (size_t i = 0; i < c.trunk_count; i++) {
    if (c.trunks[i].name && strcmp(c.trunks[i].name, name) == 0) {
      fprintf(stderr, "Error: trunk %s already exists\n", name);
      config_free(&c);
      return 1;
    }
  }
  config_free(&c);

  FILE *f = fopen(config_path, "a");
  if (!f) { perror("fopen"); return 1; }
  fprintf(f, "\n[trunk:%s]\n", name);
  fprintf(f, "host = %s\n", host);
  fprintf(f, "username = %s\n", username);
  fprintf(f, "password = %s\n", password);
  if (did && did[0])
    fprintf(f, "did = %s\n", did);
  if (cid && cid[0])
    fprintf(f, "cid = %s\n", cid);
  fclose(f);
  printf("Added trunk %s\n", name);
  return 0;
}

static int cmd_remove(const char *config_path, const char *name) {
  if (!name) {
    fprintf(stderr, "Error: <name> is required for remove\n");
    usage();
    return 1;
  }

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
  snprintf(section_header, sizeof(section_header), "[trunk:%s]", name);

  char *sec_start = strstr(content, section_header);
  if (!sec_start) {
    fprintf(stderr, "Error: trunk %s not found in config\n", name);
    free(content);
    return 1;
  }

  char *sec_end = sec_start + strlen(section_header);
  while (*sec_end) {
    if (*sec_end == '[' && (sec_end == content || sec_end[-1] == '\n'))
      break;
    sec_end++;
  }

  while (sec_start > content && sec_start[-1] == '\n') sec_start--;
  if (sec_start > content) sec_start++;

  f = fopen(config_path, "w");
  if (!f) { perror("fopen"); free(content); return 1; }
  fwrite(content, 1, (size_t)(sec_start - content), f);
  if (*sec_end)
    fwrite(sec_end, 1, strlen(sec_end), f);
  fclose(f);
  free(content);
  printf("Removed trunk %s\n", name);
  return 0;
}

int appmodule_cmd_trunk(int argc, const char **argv) {
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
    const char *pos[1] = {NULL};
    cli_collect_positional(argc, argv, 2, pos, 1);
    return cmd_add(config_path, pos[0], argc, argv);
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
