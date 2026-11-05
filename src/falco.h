/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Спільний стан демона. */
#ifndef FALCO_H
#define FALCO_H

#include <stdio.h>
#include "events.h"
#include "rules.h"
#include "proctree.h"

struct fl_config {
	const char *rules_path;		/* -c, --config */
	const char *json_path;		/* --json FILE */
	const char *record_path;	/* --record FILE */
	const char *replay_path;	/* --replay FILE */
	int use_syslog;			/* --syslog */
	int use_tui;			/* --tui */
	int dry_run;			/* --dry-run: kill перетворюється на alert */
	int verbose;			/* -v */
};

struct fl_stats {
	unsigned long long events[EV__MAX];
	unsigned long long alerts;
	unsigned long long kills;
	unsigned long long drops;
};

struct fl_ctx {
	struct fl_config cfg;
	struct fl_ruleset rules;
	struct fl_proctree *tree;
	struct fl_stats stats;
	__u64 t0_ns;	/* від нього рахуються мітки часу у виводі */
	FILE *record;	/* --record */
	FILE *json;	/* --json, відкриває out_json.c */
	void *tui;	/* стан tui.c */
};

/* pipeline.c: подія -> дерево -> вивід -> правила -> реакція. Підходить як fl_event_cb. */
void pipeline_handle(const struct fl_event *e, void *ctx);

/* util.c */
__u64 fl_now_ns(void);			/* CLOCK_MONOTONIC, те саме джерело, що bpf_ktime_get_ns() */
const char *fl_event_label(__u32 type);	/* EV_EXEC -> "EXEC" */

#endif /* FALCO_H */
