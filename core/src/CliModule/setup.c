#include "setup.h"
#include "command/list_commands.h"
#include "register_command.h"

void climodule_setup() {
  climodule_register_command(
    "list-commands",
    "Displays known commands and their descriptions",
    climodule_cmd_list_commands
  );
}
