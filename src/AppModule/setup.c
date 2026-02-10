#include "AppModule/setup.h"
#include "AppModule/command/daemon.h"
#include "AppModule/command/extension.h"
#include "AppModule/command/trunk.h"
#include "AppModule/command/completion.h"
#include "CliModule/register_command.h"

void appmodule_setup(void) {
  climodule_register_command(
    "daemon",
    "Run the UPBX daemon",
    appmodule_cmd_daemon
  );
  climodule_register_command(
    "extension",
    "Manage extensions (list/add/remove)",
    appmodule_cmd_extension
  );
  climodule_register_command(
    "trunk",
    "Manage trunks (list/add/remove)",
    appmodule_cmd_trunk
  );
  climodule_register_command(
    "completion",
    "Output shell completion script (bash/zsh)",
    appmodule_cmd_completion
  );
}
