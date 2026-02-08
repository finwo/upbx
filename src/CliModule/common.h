#ifndef __CLIMODULE_COMMON_H__
#define __CLIMODULE_COMMON_H__

struct climodule_command {
  void *next;
  const char *cmd;
  const char *desc;
  int (*fn)(int, const char **);
};

extern struct climodule_command *climodule_commands;

#endif // __CLIMODULE_COMMON_H__
