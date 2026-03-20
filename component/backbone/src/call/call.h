#ifndef UPBX_CALL_H
#define UPBX_CALL_H

#include <stddef.h>
#include <stdint.h>

enum upbx_call_state {
    UPBX_CALL_PENDING,
    UPBX_CALL_RINGING,
    UPBX_CALL_ACTIVE,
    UPBX_CALL_ENDED
};

struct upbx_tag {
    char *name;
    char *value;
};

struct upbx_call {
    char *call_id;
    size_t call_id_len;
    char *did;
    char *cid;
    int caller_fd;
    int callee_fd;
    struct upbx_tag *tags;
    int tag_count;
    enum upbx_call_state state;
};

#endif
