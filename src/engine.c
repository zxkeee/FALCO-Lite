#include <stdlib.h>
#include <string.h>
#include "engine.h"

static void track(struct proctree *t, const struct event *e)
{
	struct proc *p = proctree_get(t, e->pid);
	int known = p && !p->dead;

	if (e->type == EV_EXEC) {
		proctree_set(t, e->pid, known ? p->ppid : e->ppid, e->comm, e->path);
	} else if (e->type == EV_FORK) {
		struct proc *parent = proctree_get(t, e->ppid);
		proctree_set(t, e->pid, e->ppid, e->comm, parent ? parent->exe : "");
	} else if (!known) {
		proctree_set(t, e->pid, e->ppid, e->comm, NULL);
	}
}

static int value_matches(const struct condition *c, const struct event *e, const char *path,
			 struct proctree *t, const char *v)
{
	switch (c->field) {
	case F_COMM:
		return !strncmp(e->comm, v, COMM_LEN - 1);
	case F_ANCESTOR:
		return proctree_has_ancestor(t, e->pid, v);
	case F_PATH:
		return !strcmp(path, v);
	case F_PREFIX:
		return !strncmp(path, v, strlen(v));
	case F_PORT:
		return e->port == atoi(v);
	}
	return 0;
}

static int condition_matches(const struct condition *c, const struct event *e, const char *path,
			     struct proctree *t)
{
	int any = 0;
	for (int i = 0; i < c->count && !any; i++)
		any = value_matches(c, e, path, t, c->values[i]);
	return c->negate ? !any : any;
}

static int rule_matches(const struct rule *r, const struct event *e, const char *path, struct proctree *t)
{
	if (r->event != e->type)
		return 0;
	for (int i = 0; i < r->ncond; i++)
		if (!condition_matches(&r->cond[i], e, path, t))
			return 0;
	return 1;
}

int engine_process(const struct ruleset *rs, struct proctree *t, const struct event *e,
		   const struct rule **matches, int max)
{
	if (e->type == EV_EXIT) {
		proctree_exit(t, e->pid);
		return 0;
	}

	track(t, e);

	const char *path = e->path;
	if (!path[0]) {
		struct proc *p = proctree_get(t, e->pid);
		path = p ? p->exe : "";
	}

	int n = 0;
	for (int i = 0; i < rs->count && n < max; i++)
		if (rule_matches(&rs->rules[i], e, path, t))
			matches[n++] = &rs->rules[i];
	return n;
}
