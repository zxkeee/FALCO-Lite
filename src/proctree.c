// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Дерево процесів. Власник: Томас.
 *
 * Зараз тут заглушка: процеси не запам'ятовуються, lookup завжди NULL.
 *
 * TODO(Томас):
 *  - хеш-таблиця pid -> struct fl_proc (uthash.h або власна open addressing);
 *  - proctree_scan_proc: обійти /proc/[0-9]*, з /proc/<pid>/stat взяти ppid,
 *    comm і starttime, exe — через readlink("/proc/<pid>/exe");
 *  - proctree_update:
 *      EV_FORK  — додати дитину, comm/exe/uid успадкувати від батька;
 *      EV_EXEC  — оновити comm і exe (exe читати з /proc/<pid>/exe:
 *                 e->exec.filename буває відносним, "./x");
 *      інші     — якщо pid невідомий, дочитати його з /proc;
 *  - якщо запис із цим pid уже є, але start_ns інший — це новий процес
 *    із повторно використаним pid, запис замінити;
 *  - proctree_find_ancestor: підніматися по ppid до max_depth,
 *    fnmatch(glob, comm, 0) == 0 — збіг; захиститися від циклів і pid 0.
 * Тести: tests/unit/test_proctree.c (зараз SKIP).
 */
#include <stdlib.h>
#include "proctree.h"

struct fl_proctree {
	int nprocs;
};

struct fl_proctree *proctree_new(void)
{
	return calloc(1, sizeof(struct fl_proctree));
}

void proctree_free(struct fl_proctree *t)
{
	free(t);
}

int proctree_scan_proc(struct fl_proctree *t)
{
	(void)t;
	return 0;
}

void proctree_update(struct fl_proctree *t, const struct fl_event *e)
{
	(void)t;
	(void)e;
}

void proctree_remove(struct fl_proctree *t, __u32 pid)
{
	(void)t;
	(void)pid;
}

const struct fl_proc *proctree_lookup(struct fl_proctree *t, __u32 pid)
{
	(void)t;
	(void)pid;
	return NULL;
}

const struct fl_proc *proctree_find_ancestor(struct fl_proctree *t, __u32 pid,
					     char *const *globs, int nglobs, int max_depth)
{
	(void)t;
	(void)pid;
	(void)globs;
	(void)nglobs;
	(void)max_depth;
	return NULL;
}
