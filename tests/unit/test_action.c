#include <string.h>
#include <unistd.h>
#include "test.h"
#include "fixtures.h"
#include "action.h"

TEST(test_protected_pids)
{
	CHECK(action_is_protected(1, 0));		/* init */
	CHECK(action_is_protected(2, 0));		/* kthreadd */
	CHECK(action_is_protected(150, 2));		/* потік ядра */
	CHECK(action_is_protected((__u32)getpid(), 1));	/* сам агент */
	CHECK(!action_is_protected(4213, 1337));
}

TEST(test_dry_run_never_kills)
{
	struct fl_ctx c;
	struct fl_rule r;
	struct fl_match m = { &r };
	struct fl_action_result res;
	/* Власний pid: навіть якщо dry-run зламається, захист не дасть убити тест. */
	struct fl_event e = ev_exec((__u32)getpid(), 1, "bash", "/usr/bin/bash");

	memset(&c, 0, sizeof(c));
	memset(&r, 0, sizeof(r));
	c.cfg.dry_run = 1;
	r.action = ACT_KILL;

	action_execute(&c, &e, &m, 1, &res);
	CHECK(res.requested == ACT_KILL);
	CHECK(res.done == ACT_ALERT);
	CHECK(res.killed == 0);
}
