/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __DEMO_H
#define __DEMO_H
#include "common.h"

#define TASK_COMM_LEN 16

struct event {
	int pid;
	int ppid;
	int uid;
	u8 comm[TASK_COMM_LEN];
};

#endif
