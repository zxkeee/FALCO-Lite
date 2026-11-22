#include <stdlib.h>
#include <string.h>
#include "check.h"
#include "rules.h"

static struct ruleset rs;
static char err[256];

static int load_text(const char *text)
{
	char path[] = "/tmp/falco-test-XXXXXX";
	int fd = mkstemp(path);
	FILE *f = fdopen(fd, "w");
	fputs(text, f);
	fclose(f);
	int rc = rules_load(path, &rs, err, sizeof(err));
	remove(path);
	return rc;
}

static void test_project_rules(void)
{
	CHECK(rules_load("rules.yaml", &rs, err, sizeof(err)) == 0);
	CHECK(rs.count == 7);
	CHECK(!strcmp(rs.rules[0].name, "reverse_shell"));
	CHECK(rs.rules[0].event == EV_CONNECT);
	CHECK(rs.rules[0].action == ACT_KILL);
	CHECK(rs.rules[0].ncond == 2);
	CHECK(rs.rules[0].cond[1].field == F_ANCESTOR);
	CHECK(rs.rules[2].cond[1].negate == 1);
	CHECK(rs.rules[6].cond[0].field == F_PORT);
	CHECK(rs.rules[6].cond[0].count == 3);
}

static void test_scalar_value(void)
{
	CHECK(load_text("- name: a\n  when:\n    syscall: openat\n    file.path: /etc/shadow\n  action: alert\n") == 0);
	CHECK(rs.rules[0].cond[0].count == 1);
	CHECK(!strcmp(rs.rules[0].cond[0].values[0], "/etc/shadow"));
}

static void test_rejects(void)
{
	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n    proc.comn: [x]\n  action: kill\n") != 0);
	CHECK(strstr(err, "unknown condition") != NULL);

	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n    proc.comm.nott: [x]\n  action: kill\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n  action: kill\n") != 0);
	CHECK(strstr(err, "at least one condition") != NULL);
	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n    proc.comm: x\n  action: block\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: mmap\n    proc.comm: x\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n    net.port: [80]\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: connect\n    net.port: [http]\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: connect\n    net.port: [70000]\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: connect\n    net.port: []\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  extra: 1\n  when:\n    syscall: execve\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  action: alert\n") != 0);
	CHECK(load_text("name: a\n") != 0);
	CHECK(load_text("") != 0);
	CHECK(load_text("- name: [a\n") != 0);
	CHECK(rules_load("/nonexistent/rules.yaml", &rs, err, sizeof(err)) != 0);
}

static void test_rejects_ambiguous(void)
{
	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n    proc.comm: x\n  action: kill\n  action: alert\n") != 0);
	CHECK(strstr(err, "duplicate key") != NULL);
	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n    syscall: connect\n    proc.comm: x\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n    proc.comm: x\n    proc.comm: y\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: execve\n    proc.comm: x\n  action: alert\n---\n- name: b\n") != 0);
	CHECK(strstr(err, "one YAML document") != NULL);
	CHECK(load_text("- name: a\n  when:\n    syscall: connect\n    proc.ancestor: [systemd-journald-x]\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: openat\n    file.prefix: [/etc/]\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: openat\n    proc.comm: [cat]\n  action: alert\n") != 0);
	CHECK(strstr(err, "file.path") != NULL);
	CHECK(load_text("- name: a\n  when:\n    syscall: openat\n    file.path.not: [/etc/hostname]\n  action: alert\n") != 0);
	CHECK(load_text("- name: a\n  when:\n    syscall: connect\n    proc.ancestor: [systemd-journal]\n  action: alert\n") == 0);

	char text[4096];
	int off = 0;
	for (int r = 0; r < 3; r++) {
		off += snprintf(text + off, sizeof(text) - off, "- name: r%d\n  when:\n    syscall: openat\n    file.path: [", r);
		for (int i = 0; i < 22; i++)
			off += snprintf(text + off, sizeof(text) - off, "%s/f%d", i ? ", " : "", r * 22 + i);
		off += snprintf(text + off, sizeof(text) - off, "]\n  action: alert\n");
	}
	CHECK(load_text(text) != 0);
	CHECK(strstr(err, "more than 64") != NULL);
}

int main(void)
{
	test_project_rules();
	test_scalar_value();
	test_rejects();
	test_rejects_ambiguous();
	CHECK_DONE("rules");
}
