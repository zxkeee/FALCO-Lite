#include <string.h>
#include <unistd.h>
#include "check.h"
#include "output.h"
#include "response.h"

static void test_json(void)
{
	struct rule r;
	memset(&r, 0, sizeof(r));
	strcpy(r.name, "shadow_read");
	r.action = ACT_ALERT;

	struct event e;
	memset(&e, 0, sizeof(e));
	e.type = EV_OPEN;
	e.pid = 42;
	e.ppid = 1;
	e.uid = 1000;
	strcpy(e.comm, "c\"a\\t");
	strcpy(e.path, "/etc/sha\001dow");
	e.ret = -13;

	struct alert a = { &r, &e, "alerted", "cat ← php-fpm", -1, { 0, 5000000 } };
	char buf[LINE_LEN * 3];
	format_alert_json(buf, sizeof(buf), &a);

	CHECK(strstr(buf, "\"time\":\"1970-01-01T00:00:00.005Z\"") != NULL);
	CHECK(strstr(buf, "\"rule\":\"shadow_read\"") != NULL);
	CHECK(strstr(buf, "\"event\":\"openat\"") != NULL);
	CHECK(strstr(buf, "\"comm\":\"c\\\"a\\\\t\"") != NULL);
	CHECK(strstr(buf, "\"path\":\"/etc/sha\\u0001dow\"") != NULL);
	CHECK(strstr(buf, "\"ret\":-13,") != NULL);
	CHECK(strstr(buf, "\"chain\":\"cat ← php-fpm\",\"reaction_us\":-1}") != NULL);
	CHECK(strchr(buf, '\n') == NULL);

	char small[16];
	format_alert_json(small, sizeof(small), &a);
	CHECK(strlen(small) == sizeof(small) - 1);

	char extra[LINE_LEN];
	a.reaction_us = 1234;
	format_alert_extra(extra, sizeof(extra), &a);
	CHECK(strstr(extra, "process tree: cat ← php-fpm") != NULL);
	CHECK(strstr(extra, "SIGKILL 1.23 ms after the kernel event") != NULL);
}

static void test_addr(void)
{
	struct event e;
	char buf[64];
	memset(&e, 0, sizeof(e));
	e.type = EV_CONNECT;
	e.family = 2;
	e.port = 9001;
	e.addr[0] = 10;
	e.addr[3] = 7;
	format_detail(&e, buf, sizeof(buf));
	CHECK(!strcmp(buf, "connect 10.0.0.7:9001"));

	e.family = 10;
	memset(e.addr, 0, sizeof(e.addr));
	e.addr[15] = 1;
	format_detail(&e, buf, sizeof(buf));
	CHECK(!strcmp(buf, "connect [::1]:9001"));
}

static void test_sanitize(void)
{
	char ok[] = "привіт /tmp/x";
	sanitize_text(ok);
	CHECK(!strcmp(ok, "привіт /tmp/x"));

	char cut[] = "\xd0\xbf\xd1";
	sanitize_text(cut);
	CHECK(!strcmp(cut, "\xd0\xbf?"));

	char bad[] = "a\xff\xfe\nb\xed\xa0\x80";
	sanitize_text(bad);
	CHECK(!strcmp(bad, "a???b???"));
}

static void test_kill_guards(void)
{
	struct proctree *t = proctree_new();
	proctree_set(t, 50, 1, "bash", NULL);
	proctree_set(t, 60, 50, "falco-lite", NULL);

	CHECK(response_kill(t, 1, 60, 0) == KILL_REFUSED);
	CHECK(response_kill(t, 0, 60, 0) == KILL_REFUSED);
	CHECK(response_kill(t, 60, 60, 0) == KILL_REFUSED);
	CHECK(response_kill(t, 50, 60, 0) == KILL_REFUSED);
	CHECK(response_kill(t, 70, 60, 1) == KILL_DRY_RUN);
	CHECK(!strcmp(kill_result_name(KILL_DONE), "killed"));
	proctree_free(t);
}

int main(void)
{
	test_json();
	test_addr();
	test_sanitize();
	test_kill_guards();
	CHECK_DONE("output");
}
