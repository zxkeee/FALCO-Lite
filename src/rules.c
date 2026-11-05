// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Завантаження rules.yaml. Власник: Томас.
 *
 * Готово: таблиці імен (частина контракту) і rules_free.
 * Зараз rules_load лише перевіряє, що файл відкривається, і повертає 0 правил.
 *
 * TODO(Томас):
 *  - libyaml, document API: yaml_parser_initialize -> yaml_parser_set_input_file
 *    -> yaml_parser_load -> обхід вузлів (простіше за подієвий API);
 *  - корінь — послідовність правил; у правила: name, severity, when, action;
 *  - when.syscall: рядок або список -> syscall_mask (fl_syscall_from_name);
 *  - інші ключі when -> fl_field_from_name; значення — скаляр або список;
 *    числові поля (uid, dport, setuid.uid) — strtol, рядкові — strdup;
 *    ptrace.request: attach=16, seize=0x4206, poketext=4, pokedata=5;
 *    у числових полів str[] лишати NULL (rules_free робить free по str[]);
 *  - помилки з номером рядка: node->start_mark.line + 1, формат
 *    "rules.yaml:12: невідоме поле 'proc.cmd'";
 *  - ліміти FL_MAX_VALUES / FL_MAX_CONDS — помилка, а не тихе обрізання.
 * Тести: tests/unit/test_rules.c (частина зараз SKIP).
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rules.h"

static const char *const syscall_names[EV__MAX] = {
	[EV_EXEC] = "execve",
	[EV_CONNECT] = "connect",
	[EV_OPEN] = "openat",
	[EV_SETUID] = "setuid",
	[EV_PTRACE] = "ptrace",
};

static const char *const field_names[F__MAX] = {
	[F_PROC_COMM] = "proc.comm",
	[F_PROC_COMM_NOT] = "proc.comm.not",
	[F_PROC_ANCESTOR] = "proc.ancestor",
	[F_PROC_ANCESTOR_NOT] = "proc.ancestor.not",
	[F_PROC_EXE_PREFIX] = "proc.exe.prefix",
	[F_PROC_UID] = "proc.uid",
	[F_PROC_UID_NOT] = "proc.uid.not",
	[F_FILE_PATH] = "file.path",
	[F_FILE_PATH_PREFIX] = "file.path.prefix",
	[F_NET_DPORT] = "net.dport",
	[F_SETUID_UID] = "setuid.uid",
	[F_PTRACE_REQUEST] = "ptrace.request",
};

int fl_syscall_from_name(const char *name)
{
	int i;

	for (i = 0; i < EV__MAX; i++)
		if (syscall_names[i] && !strcmp(syscall_names[i], name))
			return i;
	return -1;
}

int fl_field_from_name(const char *name)
{
	int i;

	for (i = 0; i < F__MAX; i++)
		if (field_names[i] && !strcmp(field_names[i], name))
			return i;
	return -1;
}

const char *fl_action_name(enum fl_action a)
{
	switch (a) {
	case ACT_LOG:
		return "log";
	case ACT_ALERT:
		return "alert";
	case ACT_KILL:
		return "kill";
	}
	return "?";
}

const char *fl_severity_name(enum fl_severity s)
{
	switch (s) {
	case SEV_LOW:
		return "low";
	case SEV_MEDIUM:
		return "medium";
	case SEV_HIGH:
		return "high";
	case SEV_CRITICAL:
		return "critical";
	}
	return "?";
}

int rules_load(const char *path, struct fl_ruleset *out, char *errbuf, size_t errlen)
{
	FILE *f;

	memset(out, 0, sizeof(*out));
	f = fopen(path, "r");
	if (!f) {
		snprintf(errbuf, errlen, "%s: %s", path, strerror(errno));
		return -1;
	}
	fclose(f);

	fprintf(stderr, "[!] парсер правил ще не реалізовано (TODO: Томас): "
			"%s не розібрано, правил 0\n", path);
	return 0;
}

void rules_free(struct fl_ruleset *rs)
{
	int i, j, k;

	for (i = 0; i < rs->nrules; i++)
		for (j = 0; j < rs->rules[i].nconds; j++)
			for (k = 0; k < rs->rules[i].conds[j].nvalues; k++)
				free(rs->rules[i].conds[j].str[k]);
	free(rs->rules);
	rs->rules = NULL;
	rs->nrules = 0;
}
