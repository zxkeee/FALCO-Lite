// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <time.h>
#include "falco.h"

__u64 fl_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (__u64)ts.tv_sec * 1000000000ULL + (__u64)ts.tv_nsec;
}

const char *fl_event_label(__u32 type)
{
	static const char *const names[EV__MAX] = {
		[EV_EXEC] = "EXEC",
		[EV_CONNECT] = "CONNECT",
		[EV_OPEN] = "OPENAT",
		[EV_SETUID] = "SETUID",
		[EV_PTRACE] = "PTRACE",
		[EV_FORK] = "FORK",
		[EV_EXIT] = "EXIT",
	};

	if (type >= EV__MAX || !names[type])
		return "?";
	return names[type];
}
