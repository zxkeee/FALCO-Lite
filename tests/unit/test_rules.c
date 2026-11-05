#include <string.h>
#include "test.h"
#include "rules.h"

TEST(test_names)
{
	CHECK(fl_syscall_from_name("execve") == EV_EXEC);
	CHECK(fl_syscall_from_name("connect") == EV_CONNECT);
	CHECK(fl_syscall_from_name("openat") == EV_OPEN);
	CHECK(fl_syscall_from_name("fork") == -1);
	CHECK(fl_syscall_from_name("bogus") == -1);
	CHECK(fl_field_from_name("proc.comm") == F_PROC_COMM);
	CHECK(fl_field_from_name("proc.ancestor.not") == F_PROC_ANCESTOR_NOT);
	CHECK(fl_field_from_name("proc.cmd") == -1);
	CHECK(!strcmp(fl_action_name(ACT_KILL), "kill"));
	CHECK(!strcmp(fl_severity_name(SEV_CRITICAL), "critical"));
}

TEST(test_rules_missing_file)
{
	struct fl_ruleset rs;
	char err[256] = "";

	CHECK(rules_load("no-such-rules.yaml", &rs, err, sizeof(err)) == -1);
	CHECK(strstr(err, "no-such-rules.yaml") != NULL);
	CHECK(rs.nrules == 0);
}

TEST(test_rules_load_default)
{
	struct fl_ruleset rs;
	char err[256] = "";
	const struct fl_rule *r;

	SKIP("TODO(Томас): прибрати, коли rules_load почне розбирати YAML");

	CHECK(rules_load("rules/rules.yaml", &rs, err, sizeof(err)) == 0);
	CHECK(rs.nrules == 7);

	r = &rs.rules[0];
	CHECK(!strcmp(r->name, "reverse_shell"));
	CHECK(r->severity == SEV_CRITICAL);
	CHECK(r->action == ACT_KILL);
	CHECK(r->syscall_mask == (1u << EV_CONNECT));
	CHECK(r->nconds == 2);
	CHECK(r->conds[0].field == F_PROC_COMM);
	CHECK(r->conds[0].nvalues == 4);
	CHECK(!strcmp(r->conds[0].str[0], "bash"));
	CHECK(r->conds[1].field == F_PROC_ANCESTOR);

	r = &rs.rules[6];
	CHECK(!strcmp(r->name, "miner_pool_connect"));
	CHECK(r->conds[0].field == F_NET_DPORT);
	CHECK(r->conds[0].num[0] == 3333);

	rules_free(&rs);
}

TEST(test_rules_bad_field_reports_line)
{
	struct fl_ruleset rs;
	char err[256] = "";

	SKIP("TODO(Томас): прибрати, коли rules_load почне розбирати YAML");

	/* У tests/fixtures/bad_field.yaml друкарська помилка proc.cmd у рядку 5. */
	CHECK(rules_load("tests/fixtures/bad_field.yaml", &rs, err, sizeof(err)) == -1);
	CHECK(strstr(err, ":5:") != NULL);
	CHECK(strstr(err, "proc.cmd") != NULL);
}
