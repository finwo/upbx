#include "AppModule/setup.h"
#include "AppModule/command/daemon.h"
#include "AppModule/command/completion.h"
#include "CliModule/register_command.h"

void appmodule_setup(void) {
  climodule_register_command(
    "daemon",
    "Run the UPBX daemon",
    appmodule_cmd_daemon
  );
  climodule_register_command(
    "completion",
    "Output shell completion script (bash/zsh)",
    appmodule_cmd_completion
  );
}
