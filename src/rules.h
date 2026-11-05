/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Правила: внутрішнє представлення rules.yaml.
 * Власник модуля: Томас (парсер + матчинг).
 *
 * Семантика: усередині одного поля значення об'єднуються через OR,
 * різні поля одного правила — через AND. Рядки — glob (fnmatch(3)).
 */
#ifndef FALCO_RULES_H
#define FALCO_RULES_H

#include <stddef.h>
#include "events.h"

/* Порядок важливий: якщо збіглося кілька правил, виконується найсильніша дія. */
enum fl_action {
	ACT_LOG = 0,
	ACT_ALERT,
	ACT_KILL,
};

enum fl_severity {
	SEV_LOW = 0,
	SEV_MEDIUM,
	SEV_HIGH,
	SEV_CRITICAL,
};

/* Поля в when: (ім'я в YAML -> значення enum). */
enum fl_field {
	F_PROC_COMM,		/* proc.comm            str[] */
	F_PROC_COMM_NOT,	/* proc.comm.not        str[] */
	F_PROC_ANCESTOR,	/* proc.ancestor        str[]  будь-який предок (не сам процес) */
	F_PROC_ANCESTOR_NOT,	/* proc.ancestor.not    str[] */
	F_PROC_EXE_PREFIX,	/* proc.exe.prefix      str[] */
	F_PROC_UID,		/* proc.uid             num[] */
	F_PROC_UID_NOT,		/* proc.uid.not         num[] */
	F_FILE_PATH,		/* file.path            str[] */
	F_FILE_PATH_PREFIX,	/* file.path.prefix     str[] */
	F_NET_DPORT,		/* net.dport            num[] */
	F_SETUID_UID,		/* setuid.uid           num[] */
	F_PTRACE_REQUEST,	/* ptrace.request       str[] у YAML (attach, seize, ...) -> num[] */
	F__MAX,
};

#define FL_MAX_VALUES 16
#define FL_MAX_CONDS 8
#define FL_RULE_NAME_LEN 64

struct fl_cond {
	enum fl_field field;
	int nvalues;
	char *str[FL_MAX_VALUES];	/* рядкові поля, після strdup */
	long num[FL_MAX_VALUES];	/* числові поля */
};

struct fl_rule {
	char name[FL_RULE_NAME_LEN];
	unsigned int syscall_mask;	/* бітова маска 1u << EV_* */
	enum fl_severity severity;
	enum fl_action action;
	int nconds;
	struct fl_cond conds[FL_MAX_CONDS];
	int line;			/* рядок у YAML, для повідомлень про помилки */
};

struct fl_ruleset {
	int nrules;
	struct fl_rule *rules;
};

/*
 * Завантажити правила з YAML.
 * 0 — успіх. Інакше -1, а в errbuf — "rules.yaml:12: невідоме поле 'proc.cmd'".
 */
int rules_load(const char *path, struct fl_ruleset *out, char *errbuf, size_t errlen);
void rules_free(struct fl_ruleset *rs);

/* Імена для конфігів і виводу. Повертають -1 / "?" для невідомих. */
int fl_syscall_from_name(const char *name);	/* "execve" -> EV_EXEC */
int fl_field_from_name(const char *name);	/* "proc.comm" -> F_PROC_COMM */
const char *fl_action_name(enum fl_action a);
const char *fl_severity_name(enum fl_severity s);

#endif /* FALCO_RULES_H */
