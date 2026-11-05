#include <string.h>
#include "test.h"
#include "fixtures.h"
#include "proctree.h"

TEST(test_proctree_fork_exec_lookup)
{
	struct fl_proctree *t;
	const struct fl_proc *p;
	struct fl_event e;

	SKIP("TODO(Томас): прибрати, коли proctree почне запам'ятовувати процеси");

	t = proctree_new();
	e = ev_fork(4213, 1337, "php-fpm8.3");
	proctree_update(t, &e);
	e = ev_exec(4213, 1337, "bash", "/usr/bin/bash");
	proctree_update(t, &e);

	p = proctree_lookup(t, 4213);
	CHECK(p != NULL);
	CHECK(p->ppid == 1337);
	CHECK(!strcmp(p->comm, "bash"));
	proctree_free(t);
}

TEST(test_proctree_exit_removes)
{
	struct fl_proctree *t;
	struct fl_event e;

	SKIP("TODO(Томас): прибрати, коли proctree почне запам'ятовувати процеси");

	t = proctree_new();
	e = ev_fork(4213, 1337, "bash");
	proctree_update(t, &e);
	CHECK(proctree_lookup(t, 4213) != NULL);
	proctree_remove(t, 4213);
	CHECK(proctree_lookup(t, 4213) == NULL);
	proctree_free(t);
}

TEST(test_proctree_ancestor_glob_and_depth)
{
	char *globs[] = { "php-fpm*" };
	struct fl_proctree *t;
	const struct fl_proc *p;
	struct fl_event e;

	SKIP("TODO(Томас): прибрати, коли запрацює proctree_find_ancestor");

	/* php-fpm8.3(1337) -> sh(2000) -> bash(2001) */
	t = proctree_new();
	e = ev_exec(1337, 1, "php-fpm8.3", "/usr/sbin/php-fpm8.3");
	proctree_update(t, &e);
	e = ev_fork(2000, 1337, "php-fpm8.3");
	proctree_update(t, &e);
	e = ev_exec(2000, 1337, "sh", "/bin/sh");
	proctree_update(t, &e);
	e = ev_fork(2001, 2000, "sh");
	proctree_update(t, &e);
	e = ev_exec(2001, 2000, "bash", "/usr/bin/bash");
	proctree_update(t, &e);

	p = proctree_find_ancestor(t, 2001, globs, 1, 16);
	CHECK(p != NULL && p->pid == 1337);
	/* Глибина 1 — лише батько (sh), до php-fpm не дотягнутися. */
	CHECK(proctree_find_ancestor(t, 2001, globs, 1, 1) == NULL);
	/* Сам процес предком не вважається. */
	CHECK(proctree_find_ancestor(t, 1337, globs, 1, 16) == NULL);
	proctree_free(t);
}

TEST(test_proctree_unknown_pid)
{
	struct fl_proctree *t = proctree_new();

	CHECK(t != NULL);
	CHECK(proctree_lookup(t, 999999) == NULL);
	proctree_free(t);
}
