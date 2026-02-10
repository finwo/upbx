#ifndef __CLIMODULE_REGISTER_COMMAND_H__
#define __CLIMODULE_REGISTER_COMMAND_H__

void climodule_register_command(const char *name, const char *description, int (*fn)(int, const char **));

#endif // __CLIMODULE_REGISTER_COMMAND_H__
