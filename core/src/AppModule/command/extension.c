/// <!-- path: src/AppModule/command/extension.c -->
/// # EXTENSION
/// **extension** is the command that manages SIP extensions in the config file. It has subcommands: **list**, **add**, and **remove** (or **rm**).
///
/// **Synopsis**
///
/// **upbx** [global options] **extension** **list**  
/// **upbx** [global options] **extension** **add** [`--name` NAME] &lt;number&gt; &lt;secret&gt;  
/// **upbx** [global options] **extension** **remove**|**rm** &lt;number&gt;
///
/// **Description**
///
/// Each extension is a **[ext:number]** section with **secret** and optional **name**. Extensions register via SIP REGISTER; routing (locality, DIDs, short-dial) is determined by **[upbx]** and **[trunk:...]** settings. Use global `-f` to choose the config file; if omitted, default locations are searched.
///
/// **Subcommands**
///
/// - **list**  
///   List all configured extensions. Output: NUMBER and NAME columns. No arguments.
///
/// - **add** [`--name` NAME] &lt;number&gt; &lt;secret&gt;  
///   Add a new extension. Appends a new **[ext:number]** section to the config. **number** and **secret** are required positional arguments. `--name` NAME sets the optional display name (e.g. "Reception"). Fails if the extension number already exists.
///
/// - **remove**, **rm** &lt;number&gt;  
///   Remove the extension with the given number. Deletes the **[ext:number]** section from the config file. **number** is required.
///
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "CliModule/common.h"

static void usage(void) {
  fprintf(stderr, "Usage: upbx [-f config] extension <list|add|remove|rm>\n");
  fprintf(stderr, "  list                                  List extensions\n");
  fprintf(stderr, "  add [--name NAME] <number> <secret>   Add an extension\n");
  fprintf(stderr, "  remove|rm <number>                    Remove an extension\n");
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
  if (c.extension_count == 0) {
    printf("No extensions configured.\n");
  } else {
    printf("%-10s %-20s\n", "NUMBER", "NAME");
    printf("%-10s %-20s\n", "------", "----");
    for (size_t i = 0; i < c.extension_count; i++) {
      printf("%-10s %-20s\n",
        c.extensions[i].number ? c.extensions[i].number : "",
        c.extensions[i].name ? c.extensions[i].name : "");
    }
  }
  config_free(&c);
  return 0;
}

static int cmd_add(const char *config_path, const char *number, const char *secret, const char *name) {
  if (!number || !secret) {
    fprintf(stderr, "Error: <number> and <secret> are required for add\n");
    usage();
    return 1;
  }
  /* Verify the extension doesn't already exist. */
  upbx_config c;
  config_init(&c);
  int rc = config_load(&c, config_path);
  if (rc != 0) {
    fprintf(stderr, "Error loading config: %s (rc=%d)\n", config_path, rc);
    config_free(&c);
    return 1;
  }
  for (size_t i = 0; i < c.extension_count; i++) {
    if (c.extensions[i].number && strcmp(c.extensions[i].number, number) == 0) {
      fprintf(stderr, "Error: extension %s already exists\n", number);
      config_free(&c);
      return 1;
    }
  }
  config_free(&c);

  /* Append the new section to the config file. */
  FILE *f = fopen(config_path, "a");
  if (!f) {
    perror("fopen");
    return 1;
  }
  fprintf(f, "\n[ext:%s]\n", number);
  fprintf(f, "secret = %s\n", secret);
  if (name && name[0])
    fprintf(f, "name = %s\n", name);
  fclose(f);
  printf("Added extension %s\n", number);
  return 0;
}

static int cmd_remove(const char *config_path, const char *number) {
  if (!number) {
    fprintf(stderr, "Error: <number> is required for remove\n");
    usage();
    return 1;
  }

  /* Read entire file, skip the [ext:N] section, write back. */
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

  char section_header[64];
  snprintf(section_header, sizeof(section_header), "[ext:%s]", number);

  char *sec_start = strstr(content, section_header);
  if (!sec_start) {
    fprintf(stderr, "Error: extension %s not found in config\n", number);
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
  printf("Removed extension %s\n", number);
  return 0;
}

int appmodule_cmd_extension(int argc, const char **argv) {
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
    const char *name = cli_find_arg(argc, argv, "--name");
    const char *pos[2] = {NULL, NULL};
    cli_collect_positional(argc, argv, 2, pos, 2);
    return cmd_add(config_path, pos[0], pos[1], name);
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
