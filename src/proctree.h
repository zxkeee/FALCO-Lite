/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Дерево процесів: хто кого запустив. Власник модуля: Томас.
 */
#ifndef FALCO_PROCTREE_H
#define FALCO_PROCTREE_H

#include "events.h"

struct fl_proc {
	__u32 pid;
	__u32 ppid;
	__u32 uid;
	__u64 start_ns;			/* як fl_event.start_ns */
	char comm[FL_COMM_LEN];
	char exe[FL_PATH_LEN];		/* абсолютний шлях: readlink /proc/<pid>/exe */
};

struct fl_proctree;

struct fl_proctree *proctree_new(void);
void proctree_free(struct fl_proctree *t);

/* Заповнити дерево процесами, запущеними до старту агента. Кількість процесів або -1. */
int proctree_scan_proc(struct fl_proctree *t);

/* Врахувати подію: EV_FORK додає процес, EV_EXEC змінює comm/exe. */
void proctree_update(struct fl_proctree *t, const struct fl_event *e);

/* Прибрати процес, що завершився (pipeline викликає після обробки EV_EXIT). */
void proctree_remove(struct fl_proctree *t, __u32 pid);

/* NULL, якщо процес невідомий. */
const struct fl_proc *proctree_lookup(struct fl_proctree *t, __u32 pid);

/*
 * Перший предок pid (сам pid не враховується), чий comm збігається з одним
 * із glob-шаблонів. Підйом не глибше за max_depth. NULL — такого предка немає.
 */
const struct fl_proc *proctree_find_ancestor(struct fl_proctree *t, __u32 pid,
					     char *const *globs, int nglobs, int max_depth);

#endif /* FALCO_PROCTREE_H */
