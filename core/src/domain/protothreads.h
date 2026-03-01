#ifndef UDPHOLE_PROTOTHREADS_H
#define UDPHOLE_PROTOTHREADS_H

#include <stddef.h>

#define PT_CONCAT2(s1, s2)   s1##s2
#define PT_CONCAT(s1, s2)    PT_CONCAT2(s1, s2)

#define PT_RESUME(pt) \
  do { \
    if ((pt)->lc != NULL) \
      goto *(pt)->lc; \
  } while (0)

#define PT_SET(pt) \
  do { \
    PT_CONCAT(PT_LABEL, __LINE__): \
    (pt)->lc = &&PT_CONCAT(PT_LABEL, __LINE__); \
  } while (0)

struct pt {
  void *lc;
};

#define PT_WAITING  0
#define PT_YIELDED  1
#define PT_EXITED   2
#define PT_ENDED    3

#define PT_INIT(pt)  ((pt)->lc = NULL)

#define PT_THREAD(name_args)  char name_args

#define PT_BEGIN(pt)  { char PT_YIELD_FLAG = 1; (void)PT_YIELD_FLAG; PT_RESUME((pt))

#define PT_END(pt)  PT_INIT(pt); PT_YIELD_FLAG = 0; return PT_ENDED; }

#define PT_WAIT_UNTIL(pt, condition) \
  do { \
    PT_SET(pt); \
    if (!(condition)) \
      return PT_WAITING; \
  } while (0)

#define PT_WAIT_WHILE(pt, cond)  PT_WAIT_UNTIL((pt), !(cond))

#define PT_WAIT_THREAD(pt, thread)  PT_WAIT_WHILE((pt), PT_SCHEDULE(thread))

#define PT_SPAWN(pt, child, thread) \
  do { \
    PT_INIT((child)); \
    PT_WAIT_THREAD((pt), (thread)); \
  } while (0)

#define PT_RESTART(pt) \
  do { \
    PT_INIT(pt); \
    return PT_WAITING; \
  } while (0)

#define PT_EXIT(pt) \
  do { \
    PT_INIT(pt); \
    return PT_EXITED; \
  } while (0)

#define PT_SCHEDULE(f)  ((f) < PT_EXITED)

#define PT_YIELD(pt) \
  do { \
    PT_YIELD_FLAG = 0; \
    PT_SET(pt); \
    if (PT_YIELD_FLAG == 0) \
      return PT_YIELDED; \
  } while (0)

#define PT_YIELD_UNTIL(pt, cond) \
  do { \
    PT_YIELD_FLAG = 0; \
    PT_SET(pt); \
    if ((PT_YIELD_FLAG == 0) || !(cond)) \
      return PT_YIELDED; \
  } while (0)

struct pt_sem {
  unsigned int count;
};

#define PT_SEM_INIT(s, c)  ((s)->count = (c))

#define PT_SEM_WAIT(pt, s) \
  do { \
    PT_WAIT_UNTIL(pt, (s)->count > 0); \
    (s)->count--; \
  } while (0)

#define PT_SEM_SIGNAL(pt, s)  ((s)->count++)

#endif