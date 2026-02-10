/*
 * Shell completion helper.
 * Usage:
 *   upbx completion bash          -- output bash completion script
 *   upbx completion zsh           -- output zsh completion script
 *   upbx completion _extensions   -- list extension numbers (for completion)
 *   upbx completion _trunks       -- list trunk names (for completion)
 *
 * Install:
 *   eval "$(upbx completion bash)"
 *   eval "$(upbx completion zsh)"
 */
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "CliModule/common.h"

static int output_extensions(void) {
  const char *config_path = cli_config_path();
  if (!config_path) return 0;
  upbx_config c;
  config_init(&c);
  if (config_load(&c, config_path) != 0) { config_free(&c); return 0; }
  for (size_t i = 0; i < c.extension_count; i++) {
    if (c.extensions[i].number)
      printf("%s\n", c.extensions[i].number);
  }
  config_free(&c);
  return 0;
}

static int output_trunks(void) {
  const char *config_path = cli_config_path();
  if (!config_path) return 0;
  upbx_config c;
  config_init(&c);
  if (config_load(&c, config_path) != 0) { config_free(&c); return 0; }
  for (size_t i = 0; i < c.trunk_count; i++) {
    if (c.trunks[i].name)
      printf("%s\n", c.trunks[i].name);
  }
  config_free(&c);
  return 0;
}

static void output_bash(void) {
  printf(
    "_upbx_completions() {\n"
    "  local cur prev\n"
    "  COMPREPLY=()\n"
    "  cur=\"${COMP_WORDS[COMP_CWORD]}\"\n"
    "  prev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n"
    "\n"
    "  # Complete file path after -f\n"
    "  if [ \"$prev\" = \"-f\" ]; then\n"
    "    COMPREPLY=( $(compgen -f -- \"$cur\") )\n"
    "    return 0\n"
    "  fi\n"
    "\n"
    "  # Build -f flag from command line\n"
    "  local f_flag=\"\"\n"
    "  for ((i=1; i<${#COMP_WORDS[@]}; i++)); do\n"
    "    if [ \"${COMP_WORDS[i]}\" = \"-f\" ] && [ $((i+1)) -lt ${#COMP_WORDS[@]} ]; then\n"
    "      f_flag=\"-f ${COMP_WORDS[$((i+1))]}\"\n"
    "      break\n"
    "    fi\n"
    "  done\n"
    "\n"
    "  # Find command and subcommand (skip global flags and their values)\n"
    "  local cmd=\"\" subcmd=\"\"\n"
    "  local skip_next=0\n"
    "  for ((i=1; i<COMP_CWORD; i++)); do\n"
    "    if [ $skip_next -eq 1 ]; then skip_next=0; continue; fi\n"
    "    local w=\"${COMP_WORDS[i]}\"\n"
    "    case \"$w\" in -f|-v|--verbosity|--log) skip_next=1; continue;; esac\n"
    "    if [ -z \"$cmd\" ]; then cmd=\"$w\"\n"
    "    elif [ -z \"$subcmd\" ]; then subcmd=\"$w\"; fi\n"
    "  done\n"
    "\n"
    "  # Top-level: commands and global flags\n"
    "  if [ -z \"$cmd\" ]; then\n"
    "    COMPREPLY=( $(compgen -W \"daemon extension trunk completion list-commands -f\" -- \"$cur\") )\n"
    "    return 0\n"
    "  fi\n"
    "\n"
    "  # Subcommand level\n"
    "  if [ -z \"$subcmd\" ]; then\n"
    "    case \"$cmd\" in\n"
    "      extension) COMPREPLY=( $(compgen -W \"list add remove rm\" -- \"$cur\") );;\n"
    "      trunk)     COMPREPLY=( $(compgen -W \"list add remove rm\" -- \"$cur\") );;\n"
    "      daemon)    COMPREPLY=( $(compgen -W \"-d -D --daemonize --no-daemonize\" -- \"$cur\") );;\n"
    "      completion) COMPREPLY=( $(compgen -W \"bash zsh\" -- \"$cur\") );;\n"
    "    esac\n"
    "    return 0\n"
    "  fi\n"
    "\n"
    "  # Argument completion\n"
    "  case \"$cmd\" in\n"
    "    extension)\n"
    "      case \"$subcmd\" in\n"
    "        add)\n"
    "          if [ \"$prev\" = \"--name\" ]; then return 0; fi\n"
    "          COMPREPLY=( $(compgen -W \"--name\" -- \"$cur\") );;\n"
    "        remove|rm)\n"
    "          local exts=$(upbx $f_flag completion _extensions 2>/dev/null)\n"
    "          COMPREPLY=( $(compgen -W \"$exts\" -- \"$cur\") );;\n"
    "      esac;;\n"
    "    trunk)\n"
    "      case \"$subcmd\" in\n"
    "        add)\n"
    "          case \"$prev\" in --host|--username|--password|--did|--cid) return 0;; esac\n"
    "          COMPREPLY=( $(compgen -W \"--host --username --password --did --cid\" -- \"$cur\") );;\n"
    "        remove|rm)\n"
    "          local trunks=$(upbx $f_flag completion _trunks 2>/dev/null)\n"
    "          COMPREPLY=( $(compgen -W \"$trunks\" -- \"$cur\") );;\n"
    "      esac;;\n"
    "  esac\n"
    "  return 0\n"
    "}\n"
    "complete -F _upbx_completions upbx\n"
  );
}

static void output_zsh(void) {
  printf(
    "#compdef upbx\n"
    "\n"
    "# Helper: get -f value from current command line\n"
    "_upbx_f_flag() {\n"
    "  local i\n"
    "  for ((i=1; i<${#words[@]}; i++)); do\n"
    "    if [[ \"${words[i]}\" == \"-f\" ]] && (( i+1 < ${#words[@]} )); then\n"
    "      echo \"-f ${words[$((i+1))]}\"\n"
    "      return\n"
    "    fi\n"
    "  done\n"
    "}\n"
    "\n"
    "_upbx() {\n"
    "  local -a commands\n"
    "  commands=(\n"
    "    'daemon:Run the UPBX daemon'\n"
    "    'extension:Manage extensions'\n"
    "    'trunk:Manage trunks'\n"
    "    'completion:Output shell completion script'\n"
    "    'list-commands:List available commands'\n"
    "  )\n"
    "\n"
    "  _arguments -C \\\n"
    "    '-f[Config file]:file:_files' \\\n"
    "    '-v[Log verbosity]:level:(fatal error warn info debug trace)' \\\n"
    "    '--log[Log to file]:file:_files' \\\n"
    "    '1:command:->command' \\\n"
    "    '*::arg:->args'\n"
    "\n"
    "  case $state in\n"
    "    command)\n"
    "      _describe -t commands 'upbx command' commands\n"
    "      ;;\n"
    "    args)\n"
    "      local f_flag=$(_upbx_f_flag)\n"
    "      case $line[1] in\n"
    "        extension)\n"
    "          local -a ext_subcmds\n"
    "          ext_subcmds=(list add remove rm)\n"
    "          if (( CURRENT == 2 )); then\n"
    "            _describe -t subcmds 'extension subcommand' ext_subcmds\n"
    "          else\n"
    "            case $line[2] in\n"
    "              add)\n"
    "                _arguments \\\n"
    "                  '--name[Display name]:name:' \\\n"
    "                  '1:number:' \\\n"
    "                  '2:secret:'\n"
    "                ;;\n"
    "              remove|rm)\n"
    "                local -a exts\n"
    "                exts=(${(f)\"$(upbx $f_flag completion _extensions 2>/dev/null)\"})\n"
    "                _describe -t extensions 'extension number' exts\n"
    "                ;;\n"
    "            esac\n"
    "          fi\n"
    "          ;;\n"
    "        trunk)\n"
    "          local -a trunk_subcmds\n"
    "          trunk_subcmds=(list add remove rm)\n"
    "          if (( CURRENT == 2 )); then\n"
    "            _describe -t subcmds 'trunk subcommand' trunk_subcmds\n"
    "          else\n"
    "            case $line[2] in\n"
    "              add)\n"
    "                _arguments \\\n"
    "                  '--host[SIP host]:host:' \\\n"
    "                  '--username[Auth username]:username:' \\\n"
    "                  '--password[Auth password]:password:' \\\n"
    "                  '--did[DID number]:did:' \\\n"
    "                  '--cid[Caller ID]:cid:' \\\n"
    "                  '1:name:'\n"
    "                ;;\n"
    "              remove|rm)\n"
    "                local -a trunks\n"
    "                trunks=(${(f)\"$(upbx $f_flag completion _trunks 2>/dev/null)\"})\n"
    "                _describe -t trunks 'trunk name' trunks\n"
    "                ;;\n"
    "            esac\n"
    "          fi\n"
    "          ;;\n"
    "        daemon)\n"
    "          _arguments \\\n"
    "            '-d[Run in background]' \\\n"
    "            '-D[Force foreground]' \\\n"
    "            '--daemonize[Run in background]' \\\n"
    "            '--no-daemonize[Force foreground]'\n"
    "          ;;\n"
    "        completion)\n"
    "          _arguments '1:shell:(bash zsh)'\n"
    "          ;;\n"
    "      esac\n"
    "      ;;\n"
    "  esac\n"
    "}\n"
    "\n"
    "_upbx\n"
  );
}

int appmodule_cmd_completion(int argc, const char **argv) {
  if (argc < 2) {
    fprintf(stderr, "Usage: upbx completion <bash|zsh>\n");
    return 1;
  }
  if (strcmp(argv[1], "bash") == 0) {
    output_bash();
    return 0;
  }
  if (strcmp(argv[1], "zsh") == 0) {
    output_zsh();
    return 0;
  }
  if (strcmp(argv[1], "_extensions") == 0)
    return output_extensions();
  if (strcmp(argv[1], "_trunks") == 0)
    return output_trunks();

  fprintf(stderr, "Unknown shell: %s (supported: bash, zsh)\n", argv[1]);
  return 1;
}
