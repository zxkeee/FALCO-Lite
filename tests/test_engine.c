#include <stdio.h>
#include <string.h>
#include "check.h"
#include "engine.h"

static struct ruleset rs;
static struct proctree *tree;

static struct event ev(int type, int pid, int ppid, const char *comm, const char *path)
{
	struct event e;
	memset(&e, 0, sizeof(e));
	e.type = type;
	e.pid = pid;
	e.ppid = ppid;
	e.uid = 1000;
	snprintf(e.comm, sizeof(e.comm), "%s", comm);
	snprintf(e.path, sizeof(e.path), "%s", path ? path : "");
	return e;
}

static const char *first_match(struct event e)
{
	const struct rule *m[8];
	int n = engine_process(&rs, tree, &e, m, 8);
	return n ? m[0]->name : "";
}

static struct event connect_ev(int pid, int ppid, const char *comm, int port)
{
	struct event e = ev(EV_CONNECT, pid, ppid, comm, NULL);
	e.family = 2;
	e.port = port;
	return e;
}

static void test_reverse_shell_chain(void)
{
	first_match(ev(EV_EXEC, 100, 1, "php-fpm", "/usr/sbin/php-fpm"));
	first_match(ev(EV_FORK, 101, 100, "php-fpm", NULL));
	first_match(ev(EV_EXEC, 101, 100, "sh", "/usr/bin/dash"));
	first_match(ev(EV_FORK, 102, 101, "sh", NULL));
	first_match(ev(EV_EXEC, 102, 101, "bash", "/usr/bin/bash"));

	CHECK(!strcmp(proctree_get(tree, 101)->exe, "/usr/bin/dash"));
	CHECK(!strcmp(first_match(connect_ev(102, 101, "bash", 9001)), "reverse_shell"));
	CHECK(!strcmp(first_match(connect_ev(200, 1, "bash", 9001)), ""));
	CHECK(!strcmp(first_match(connect_ev(103, 100, "php-fpm", 443)), ""));
}

static void test_parent_exited(void)
{
	int baseline = tree->count;

	first_match(ev(EV_EXEC, 800, 1, "php-fpm", "/usr/sbin/php-fpm"));
	first_match(ev(EV_FORK, 801, 800, "php-fpm", NULL));
	first_match(ev(EV_EXIT, 800, 1, "php-fpm", NULL));
	first_match(ev(EV_EXEC, 801, 1, "bash", "/usr/bin/bash"));
	CHECK(!strcmp(first_match(connect_ev(801, 1, "bash", 9001)), "reverse_shell"));
	first_match(ev(EV_EXIT, 801, 1, "bash", NULL));
	CHECK(tree->count == baseline);

	first_match(ev(EV_EXEC, 900, 1, "nginx", "/usr/sbin/nginx"));
	first_match(ev(EV_FORK, 901, 900, "nginx", NULL));
	first_match(ev(EV_EXEC, 901, 900, "setsid", "/usr/bin/setsid"));
	first_match(ev(EV_FORK, 902, 901, "setsid", NULL));
	first_match(ev(EV_EXIT, 901, 900, "setsid", NULL));
	first_match(ev(EV_EXIT, 900, 1, "nginx", NULL));
	first_match(ev(EV_EXEC, 902, 1, "sh", "/usr/bin/dash"));
	CHECK(!strcmp(first_match(connect_ev(902, 1, "sh", 9001)), "reverse_shell"));
	first_match(ev(EV_EXIT, 902, 1, "sh", NULL));
	CHECK(tree->count == baseline);
}

static void test_exec_rules(void)
{
	CHECK(!strcmp(first_match(ev(EV_EXEC, 300, 1, ".x", "/tmp/.x")), "exec_from_tmp"));
	CHECK(!strcmp(first_match(ev(EV_EXEC, 301, 1, "x", "/dev/shm/x")), "exec_from_tmp"));
	CHECK(!strcmp(first_match(ev(EV_EXEC, 302, 1, "ls", "/usr/bin/ls")), ""));
	CHECK(!strcmp(first_match(ev(EV_EXEC, 303, 1, "x", "/tmpfoo/x")), ""));
	CHECK(!strcmp(first_match(ev(EV_EXEC, 304, 1, "xmrig", "/opt/xmrig")), "miner_exec"));
	CHECK(!strcmp(first_match(connect_ev(305, 1, "curl", 3333)), "miner_pool"));
	CHECK(!strcmp(first_match(connect_ev(306, 1, "curl", 443)), ""));
}

static void test_open_setuid_ptrace(void)
{
	struct event open = ev(EV_OPEN, 400, 1, "cat", "/etc/shadow");
	open.ret = -13;
	CHECK(!strcmp(first_match(open), "shadow_read"));
	CHECK(!strcmp(first_match(ev(EV_OPEN, 401, 1, "sshd", "/etc/shadow")), ""));
	CHECK(!strcmp(first_match(ev(EV_OPEN, 402, 1, "unix_chkpwd", "/etc/shadow")), ""));

	CHECK(!strcmp(first_match(ev(EV_SETUID, 500, 1, "rootid", "/opt/rootid")), "setuid_root"));
	CHECK(!strcmp(first_match(ev(EV_SETUID, 501, 1, "sudo", "/usr/lib/cargo/bin/sudo")), ""));
	first_match(ev(EV_EXEC, 502, 1, "passwd", "/usr/bin/passwd"));
	CHECK(!strcmp(first_match(ev(EV_SETUID, 502, 1, "passwd", NULL)), ""));
	CHECK(!strcmp(first_match(ev(EV_SETUID, 503, 1, "exploit", NULL)), "setuid_root"));

	CHECK(!strcmp(first_match(ev(EV_PTRACE, 600, 1, "gdb", NULL)), ""));
	CHECK(!strcmp(first_match(ev(EV_PTRACE, 601, 1, "inject", NULL)), "ptrace_attach"));
}

static void test_exit_and_negation(void)
{
	CHECK(proctree_get(tree, 102) != NULL);
	first_match(ev(EV_EXIT, 102, 101, "bash", NULL));
	CHECK(proctree_get(tree, 102) == NULL);

	const struct rule *m[8];
	struct event e = ev(EV_OPEN, 700, 1, "cat", "/etc/shadow");
	CHECK(engine_process(&rs, tree, &e, m, 0) == 0);
}

int main(void)
{
	char err[256];
	if (rules_load("rules.yaml", &rs, err, sizeof(err))) {
		fprintf(stderr, "%s\n", err);
		return 1;
	}
	tree = proctree_new();
	proctree_set(tree, 1, 0, "systemd", "/sbin/init");

	test_reverse_shell_chain();
	test_parent_exited();
	test_exec_rules();
	test_open_setuid_ptrace();
	test_exit_and_negation();

	proctree_free(tree);
	CHECK_DONE("engine");
}
