// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Рушій правил. Власник: Томас.
 *
 * Зараз engine_match — заглушка й нічого не знаходить.
 *
 * TODO(Томас):
 *   для кожного правила:
 *     пропустити, якщо !(rule->syscall_mask & (1u << e->type));
 *     усі conds мають збігтися (AND), усередині cond — будь-яке значення (OR):
 *       F_PROC_COMM            fnmatch(value, e->comm, 0) == 0
 *       F_PROC_COMM_NOT        жодне значення не збіглося
 *       F_PROC_ANCESTOR(_NOT)  proctree_find_ancestor(tree, e->pid, cond->str,
 *                                                     cond->nvalues, 16)
 *       F_PROC_EXE_PREFIX      exe з дерева (запасний варіант: e->exec.filename)
 *       F_PROC_UID(_NOT)       e->uid
 *       F_FILE_PATH(_PREFIX)   e->open.path
 *       F_NET_DPORT            e->connect.dport
 *       F_SETUID_UID           e->setuid.target_uid
 *       F_PTRACE_REQUEST       e->ptrace.request
 *     збіглося — out[n++] = rule, поки n < max.
 *   Згодом: індекс правил за типом події, щоб не перебирати всі.
 * Тести: tests/unit/test_engine.c (зараз SKIP).
 */
#include "engine.h"

int engine_match(const struct fl_ruleset *rs, struct fl_proctree *tree,
		 const struct fl_event *e, struct fl_match *out, int max)
{
	(void)rs;
	(void)tree;
	(void)e;
	(void)out;
	(void)max;
	return 0;
}

enum fl_action engine_strongest(const struct fl_match *m, int n)
{
	enum fl_action best = ACT_LOG;
	int i;

	for (i = 0; i < n; i++)
		if (m[i].rule->action > best)
			best = m[i].rule->action;
	return best;
}
