#include <string.h>
#include <unistd.h>
#include "check.h"
#include "proctree.h"

static void test_basic(void)
{
	struct proctree *t = proctree_new();
	proctree_set(t, 1, 0, "systemd", "/sbin/init");
	proctree_set(t, 10, 1, "php-fpm", "/usr/sbin/php-fpm");
	proctree_set(t, 20, 10, "sh", "/bin/sh");
	proctree_set(t, 30, 20, "bash", "/bin/bash");
	proctree_set(t, 10 + TREE_BUCKETS, 1, "other", NULL);

	CHECK(t->count == 5);
	CHECK(proctree_get(t, 10 + TREE_BUCKETS) != NULL);
	CHECK(proctree_has_ancestor(t, 30, "php-fpm"));
	CHECK(proctree_has_ancestor(t, 30, "systemd"));
	CHECK(!proctree_has_ancestor(t, 30, "bash"));
	CHECK(!proctree_has_ancestor(t, 30, "nginx"));
	CHECK(proctree_is_ancestor(t, 10, 30));
	CHECK(!proctree_is_ancestor(t, 30, 10));

	proctree_exit(t, 20);
	CHECK(proctree_get(t, 20) != NULL);
	CHECK(proctree_has_ancestor(t, 30, "php-fpm"));
	CHECK(t->count == 5);

	proctree_exit(t, 30);
	CHECK(proctree_get(t, 30) == NULL);
	CHECK(proctree_get(t, 20) == NULL);
	CHECK(proctree_get(t, 10) != NULL);
	CHECK(t->count == 3);

	proctree_exit(t, 999);
	CHECK(t->count == 3);
	proctree_free(t);
}

static void test_reparent(void)
{
	struct proctree *t = proctree_new();
	proctree_set(t, 1, 0, "init", NULL);
	proctree_set(t, 10, 1, "a", NULL);
	proctree_set(t, 11, 10, "b", NULL);
	CHECK(proctree_get(t, 10)->children == 1);

	proctree_set(t, 11, 1, "b", NULL);
	CHECK(proctree_get(t, 10)->children == 0);
	CHECK(proctree_get(t, 1)->children == 2);

	proctree_exit(t, 10);
	CHECK(proctree_get(t, 10) == NULL);
	proctree_free(t);
}

static void test_relay_and_depth(void)
{
	struct proctree *t = proctree_new();
	proctree_set(t, 1, 0, "init", NULL);
	proctree_set(t, 2, 1, "php-fpm", NULL);
	proctree_set(t, 3, 2, "relay", NULL);
	for (int pid = 4; pid < 10000; pid++) {
		proctree_set(t, pid, pid - 1, "relay", NULL);
		proctree_exit(t, pid - 1);
	}
	CHECK(t->count < 10);
	CHECK(proctree_has_ancestor(t, 9999, "php-fpm"));
	proctree_free(t);

	t = proctree_new();
	proctree_set(t, 1, 0, "php-fpm", NULL);
	for (int pid = 2; pid < 100; pid++)
		proctree_set(t, pid, pid - 1, "bash", NULL);
	CHECK(proctree_has_ancestor(t, 99, "php-fpm"));
	proctree_free(t);
}

static void test_chain(void)
{
	struct proctree *t = proctree_new();
	char buf[160];
	proctree_set(t, 1, 0, "systemd", NULL);
	proctree_set(t, 10, 1, "php-fpm", NULL);
	proctree_set(t, 20, 10, "sh", NULL);
	proctree_set(t, 30, 20, "bash", NULL);
	proctree_chain(t, 30, NULL, buf, sizeof(buf));
	CHECK(!strcmp(buf, "bash ← sh ← php-fpm ← systemd"));

	for (int pid = 31; pid < 40; pid++)
		proctree_set(t, pid, pid - 1, "x", NULL);
	proctree_chain(t, 39, NULL, buf, sizeof(buf));
	CHECK(!strcmp(buf, "x ← x ← x ← x ← …"));

	proctree_chain(t, 999, NULL, buf, sizeof(buf));
	CHECK(buf[0] == '\0');

	char tiny[8];
	proctree_chain(t, 30, NULL, tiny, sizeof(tiny));
	CHECK(strlen(tiny) < sizeof(tiny));
	proctree_chain(t, 30, "newname", buf, sizeof(buf));
	CHECK(!strncmp(buf, "newname ← sh", strlen("newname ← sh")));
	proctree_free(t);
}

static void test_loop_guard(void)
{
	struct proctree *t = proctree_new();
	proctree_set(t, 5, 6, "a", NULL);
	proctree_set(t, 6, 5, "b", NULL);
	CHECK(!proctree_has_ancestor(t, 5, "zzz"));
	CHECK(!proctree_is_ancestor(t, 99, 5));
	proctree_free(t);
}

static void test_seed(void)
{
	struct proctree *t = proctree_new();
	CHECK(proctree_seed(t, "/proc") == 0);
	struct proc *self = proctree_get(t, getpid());
	CHECK(self != NULL);
	CHECK(self && self->ppid == getppid());
	CHECK(self && self->exe[0] == '/');
	CHECK(proctree_seed(t, "/nonexistent") != 0);
	proctree_free(t);
}

int main(void)
{
	test_basic();
	test_reparent();
	test_relay_and_depth();
	test_chain();
	test_loop_guard();
	test_seed();
	CHECK_DONE("proctree");
}
