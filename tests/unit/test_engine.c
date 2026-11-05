/*
 * Рушій тестується окремо від парсера: правила збираються прямо в C,
 * дерево процесів заповнюється синтетичними fork/exec.
 */
#include <string.h>
#include "test.h"
#include "fixtures.h"
#include "engine.h"

static void cond_str(struct fl_cond *c, enum fl_field f, const char *a, const char *b)
{
	memset(c, 0, sizeof(*c));
	c->field = f;
	c->str[c->nvalues++] = (char *)a;
	if (b)
		c->str[c->nvalues++] = (char *)b;
}

/* reverse_shell із rules.yaml, спрощений. */
static void make_reverse_shell(struct fl_rule *r)
{
	memset(r, 0, sizeof(*r));
	snprintf(r->name, sizeof(r->name), "reverse_shell");
	r->syscall_mask = 1u << EV_CONNECT;
	r->severity = SEV_CRITICAL;
	r->action = ACT_KILL;
	cond_str(&r->conds[0], F_PROC_COMM, "bash", "sh");
	cond_str(&r->conds[1], F_PROC_ANCESTOR, "php-fpm*", NULL);
	r->nconds = 2;
}

/* systemd(1) -> php-fpm8.3(1337) -> bash(4213) */
static void feed_webshell_tree(struct fl_proctree *t)
{
	struct fl_event e;

	e = ev_exec(1337, 1, "php-fpm8.3", "/usr/sbin/php-fpm8.3");
	proctree_update(t, &e);
	e = ev_fork(4213, 1337, "php-fpm8.3");
	proctree_update(t, &e);
	e = ev_exec(4213, 1337, "bash", "/usr/bin/bash");
	proctree_update(t, &e);
}

TEST(test_strongest_action)
{
	struct fl_rule a, b, k;
	struct fl_match m[3] = { { &a }, { &k }, { &b } };

	memset(&a, 0, sizeof(a));
	memset(&b, 0, sizeof(b));
	memset(&k, 0, sizeof(k));
	a.action = ACT_ALERT;
	b.action = ACT_LOG;
	k.action = ACT_KILL;

	CHECK(engine_strongest(m, 3) == ACT_KILL);
	CHECK(engine_strongest(m, 1) == ACT_ALERT);
	CHECK(engine_strongest(m, 0) == ACT_LOG);
}

TEST(test_reverse_shell_matches)
{
	struct fl_rule r;
	struct fl_ruleset rs = { 1, &r };
	struct fl_match m[FL_MAX_MATCHES];
	struct fl_proctree *t;
	struct fl_event e;

	SKIP("TODO(Томас): прибрати, коли запрацюють engine_match і proctree");

	make_reverse_shell(&r);
	t = proctree_new();
	feed_webshell_tree(t);

	e = ev_connect(4213, 1337, "bash", "10.0.0.66", 4444);
	CHECK(engine_match(&rs, t, &e, m, FL_MAX_MATCHES) == 1);
	CHECK(m[0].rule == &r);
	proctree_free(t);
}

TEST(test_shell_without_webserver_no_match)
{
	struct fl_rule r;
	struct fl_ruleset rs = { 1, &r };
	struct fl_match m[FL_MAX_MATCHES];
	struct fl_proctree *t;
	struct fl_event e;

	SKIP("TODO(Томас): прибрати, коли запрацюють engine_match і proctree");

	make_reverse_shell(&r);
	t = proctree_new();
	/* sshd(900) -> bash(5000): адмін сам робить curl — не reverse shell */
	e = ev_exec(900, 1, "sshd", "/usr/sbin/sshd");
	proctree_update(t, &e);
	e = ev_fork(5000, 900, "sshd");
	proctree_update(t, &e);
	e = ev_exec(5000, 900, "bash", "/usr/bin/bash");
	proctree_update(t, &e);

	e = ev_connect(5000, 900, "bash", "93.184.216.34", 443);
	CHECK(engine_match(&rs, t, &e, m, FL_MAX_MATCHES) == 0);
	proctree_free(t);
}

TEST(test_wrong_syscall_no_match)
{
	struct fl_rule r;
	struct fl_ruleset rs = { 1, &r };
	struct fl_match m[FL_MAX_MATCHES];
	struct fl_proctree *t;
	struct fl_event e;

	make_reverse_shell(&r);
	t = proctree_new();
	feed_webshell_tree(t);

	/* Той самий bash під php-fpm, але openat, а правило — лише на connect. */
	e = ev_open(4213, 1337, "bash", "/etc/passwd");
	CHECK(engine_match(&rs, t, &e, m, FL_MAX_MATCHES) == 0);
	proctree_free(t);
}
