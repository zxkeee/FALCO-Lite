/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Реакція на збіг правил. Власник: Назар. */
#ifndef FALCO_ACTION_H
#define FALCO_ACTION_H

#include "falco.h"
#include "engine.h"

struct fl_action_result {
	enum fl_action requested;	/* найсильніша серед правил, що збіглися */
	enum fl_action done;		/* що зроблено: у --dry-run і для захищених kill -> alert */
	int killed;			/* SIGKILL доставлено */
	int err;			/* errno, якщо kill не вдався */
	__u64 latency_ns;		/* від події в ядрі до реакції (0 у --replay) */
};

/* Процеси, які не можна вбивати за жодним правилом. */
int action_is_protected(__u32 pid, __u32 ppid);

void action_execute(struct fl_ctx *c, const struct fl_event *e,
		    const struct fl_match *m, int n, struct fl_action_result *res);

#endif /* FALCO_ACTION_H */
