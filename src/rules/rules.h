#ifndef FALCO_RULES_H
#define FALCO_RULES_H

#include <stddef.h>
#include "event.h"

#define MAX_RULES 64
#define MAX_CONDS 8
#define MAX_VALUES 24
#define VALUE_LEN 128
#define NAME_LEN 64
#define MAX_WATCHED 64

enum cond_field {
	F_COMM,
	F_ANCESTOR,
	F_PATH,
	F_PREFIX,
	F_PORT,
};

enum action {
	ACT_ALERT,
	ACT_KILL,
};

struct condition {
	int field;
	int negate;
	int count;
	char values[MAX_VALUES][VALUE_LEN];
};

struct rule {
	char name[NAME_LEN];
	int event;
	int action;
	int ncond;
	struct condition cond[MAX_CONDS];
};

struct ruleset {
	int count;
	struct rule rules[MAX_RULES];
};

int rules_load(const char *path, struct ruleset *rs, char *err, size_t errlen);
const char *event_name(int type);
const char *action_name(int action);

#endif
