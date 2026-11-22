#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>
#include "rules.h"

#define BIT(x) (1u << (x))
#define ALL_EVENTS (BIT(EV_EXEC) | BIT(EV_CONNECT) | BIT(EV_OPEN) | BIT(EV_SETUID) | BIT(EV_PTRACE))
#define PATH_EVENTS (BIT(EV_EXEC) | BIT(EV_OPEN) | BIT(EV_SETUID))
#define PREFIX_EVENTS (BIT(EV_EXEC) | BIT(EV_SETUID))

static const char *event_names[EV_TYPE_COUNT] = {
	[EV_EXEC] = "execve",
	[EV_FORK] = "fork",
	[EV_EXIT] = "exit",
	[EV_CONNECT] = "connect",
	[EV_OPEN] = "openat",
	[EV_SETUID] = "setuid",
	[EV_PTRACE] = "ptrace",
};

struct field_def {
	const char *key;
	int field;
	unsigned int events;
};

static const struct field_def fields[] = {
	{ "proc.comm", F_COMM, ALL_EVENTS },
	{ "proc.ancestor", F_ANCESTOR, ALL_EVENTS },
	{ "file.path", F_PATH, PATH_EVENTS },
	{ "file.prefix", F_PREFIX, PREFIX_EVENTS },
	{ "net.port", F_PORT, BIT(EV_CONNECT) },
};

const char *event_name(int type)
{
	if (type <= 0 || type >= EV_TYPE_COUNT)
		return "unknown";
	return event_names[type];
}

const char *action_name(int action)
{
	return action == ACT_KILL ? "kill" : "alert";
}

static int parse_event(const char *s)
{
	if (!strcmp(s, "fork") || !strcmp(s, "exit"))
		return 0;
	for (int t = 1; t < EV_TYPE_COUNT; t++)
		if (!strcmp(s, event_names[t]))
			return t;
	return 0;
}

static const char *scalar(yaml_node_t *n)
{
	if (!n || n->type != YAML_SCALAR_NODE)
		return NULL;
	return (const char *)n->data.scalar.value;
}

static int copy_str(char *dst, size_t len, const char *src)
{
	size_t n = strlen(src);
	if (n >= len)
		return -1;
	memcpy(dst, src, n + 1);
	return 0;
}

static int valid_port(const char *s)
{
	char *end;
	long v = strtol(s, &end, 10);
	return *s && !*end && v > 0 && v < 65536;
}

static int add_value(struct condition *c, const char *v, const char *rule, char *err, size_t errlen)
{
	if (c->count >= MAX_VALUES) {
		snprintf(err, errlen, "rule %s: too many values (max %d)", rule, MAX_VALUES);
		return -1;
	}
	if (c->field == F_PORT && !valid_port(v)) {
		snprintf(err, errlen, "rule %s: bad port '%s'", rule, v);
		return -1;
	}
	if ((c->field == F_COMM || c->field == F_ANCESTOR) && strlen(v) > COMM_LEN - 1) {
		snprintf(err, errlen, "rule %s: process name '%s' is longer than %d bytes", rule, v, COMM_LEN - 1);
		return -1;
	}
	if (!*v || copy_str(c->values[c->count], VALUE_LEN, v)) {
		snprintf(err, errlen, "rule %s: empty or too long value", rule);
		return -1;
	}
	c->count++;
	return 0;
}

static int parse_values(yaml_document_t *doc, yaml_node_t *n, struct condition *c,
			const char *rule, char *err, size_t errlen)
{
	if (n->type == YAML_SCALAR_NODE)
		return add_value(c, scalar(n), rule, err, errlen);

	if (n->type != YAML_SEQUENCE_NODE) {
		snprintf(err, errlen, "rule %s: condition value must be a string or a list", rule);
		return -1;
	}

	for (yaml_node_item_t *it = n->data.sequence.items.start; it < n->data.sequence.items.top; it++) {
		const char *v = scalar(yaml_document_get_node(doc, *it));
		if (!v) {
			snprintf(err, errlen, "rule %s: list items must be strings", rule);
			return -1;
		}
		if (add_value(c, v, rule, err, errlen))
			return -1;
	}

	if (c->count == 0) {
		snprintf(err, errlen, "rule %s: empty list", rule);
		return -1;
	}
	return 0;
}

static int parse_condition(yaml_document_t *doc, const char *key, yaml_node_t *value,
			   struct rule *r, char *err, size_t errlen)
{
	char base[NAME_LEN];
	if (copy_str(base, sizeof(base), key)) {
		snprintf(err, errlen, "rule %s: key too long", r->name);
		return -1;
	}

	int negate = 0;
	size_t len = strlen(base);
	if (len > 4 && !strcmp(base + len - 4, ".not")) {
		base[len - 4] = '\0';
		negate = 1;
	}

	const struct field_def *def = NULL;
	for (size_t i = 0; i < sizeof(fields) / sizeof(fields[0]); i++)
		if (!strcmp(base, fields[i].key))
			def = &fields[i];

	if (!def) {
		snprintf(err, errlen, "rule %s: unknown condition '%s'", r->name, key);
		return -1;
	}
	if (!(def->events & BIT(r->event))) {
		snprintf(err, errlen, "rule %s: '%s' does not apply to %s", r->name, key, event_name(r->event));
		return -1;
	}
	if (r->ncond >= MAX_CONDS) {
		snprintf(err, errlen, "rule %s: too many conditions", r->name);
		return -1;
	}

	struct condition *c = &r->cond[r->ncond++];
	c->field = def->field;
	c->negate = negate;
	return parse_values(doc, value, c, r->name, err, errlen);
}

static int has_duplicate_key(yaml_document_t *doc, yaml_node_t *map, const char *where, char *err, size_t errlen)
{
	yaml_node_pair_t *start = map->data.mapping.pairs.start;
	yaml_node_pair_t *top = map->data.mapping.pairs.top;

	for (yaml_node_pair_t *p = start; p < top; p++) {
		const char *a = scalar(yaml_document_get_node(doc, p->key));
		for (yaml_node_pair_t *q = p + 1; a && q < top; q++) {
			const char *b = scalar(yaml_document_get_node(doc, q->key));
			if (b && !strcmp(a, b)) {
				snprintf(err, errlen, "%s: duplicate key '%s'", where, a);
				return 1;
			}
		}
	}
	return 0;
}

static int parse_when(yaml_document_t *doc, yaml_node_t *when, struct rule *r, char *err, size_t errlen)
{
	char where[NAME_LEN + 8];
	snprintf(where, sizeof(where), "rule %s", r->name);

	if (when->type != YAML_MAPPING_NODE) {
		snprintf(err, errlen, "rule %s: 'when' must be a mapping", r->name);
		return -1;
	}
	if (has_duplicate_key(doc, when, where, err, errlen))
		return -1;

	yaml_node_pair_t *start = when->data.mapping.pairs.start;
	yaml_node_pair_t *top = when->data.mapping.pairs.top;

	for (yaml_node_pair_t *p = start; p < top; p++) {
		const char *key = scalar(yaml_document_get_node(doc, p->key));
		if (key && !strcmp(key, "syscall")) {
			const char *v = scalar(yaml_document_get_node(doc, p->value));
			r->event = v ? parse_event(v) : 0;
		}
	}
	if (!r->event) {
		snprintf(err, errlen, "rule %s: missing or unknown syscall", r->name);
		return -1;
	}

	for (yaml_node_pair_t *p = start; p < top; p++) {
		const char *key = scalar(yaml_document_get_node(doc, p->key));
		if (!key) {
			snprintf(err, errlen, "rule %s: bad key", r->name);
			return -1;
		}
		if (!strcmp(key, "syscall"))
			continue;
		if (parse_condition(doc, key, yaml_document_get_node(doc, p->value), r, err, errlen))
			return -1;
	}
	return 0;
}

static int has_watched_path(const struct rule *r)
{
	for (int i = 0; i < r->ncond; i++)
		if (r->cond[i].field == F_PATH && !r->cond[i].negate)
			return 1;
	return 0;
}

static int parse_rule(yaml_document_t *doc, yaml_node_t *n, int idx, struct rule *r, char *err, size_t errlen)
{
	char where[24];
	snprintf(where, sizeof(where), "rule #%d", idx);

	if (n->type != YAML_MAPPING_NODE) {
		snprintf(err, errlen, "%s: expected a mapping", where);
		return -1;
	}
	if (has_duplicate_key(doc, n, where, err, errlen))
		return -1;

	const char *name = NULL;
	const char *action = NULL;
	yaml_node_t *when = NULL;

	for (yaml_node_pair_t *p = n->data.mapping.pairs.start; p < n->data.mapping.pairs.top; p++) {
		const char *key = scalar(yaml_document_get_node(doc, p->key));
		yaml_node_t *value = yaml_document_get_node(doc, p->value);
		if (key && !strcmp(key, "name"))
			name = scalar(value);
		else if (key && !strcmp(key, "action"))
			action = scalar(value);
		else if (key && !strcmp(key, "when"))
			when = value;
		else {
			snprintf(err, errlen, "rule #%d: unknown key '%s'", idx, key ? key : "?");
			return -1;
		}
	}

	if (!name || !*name || copy_str(r->name, sizeof(r->name), name)) {
		snprintf(err, errlen, "rule #%d: missing or too long name", idx);
		return -1;
	}
	if (!action || (strcmp(action, "alert") && strcmp(action, "kill"))) {
		snprintf(err, errlen, "rule %s: action must be alert or kill", r->name);
		return -1;
	}
	r->action = strcmp(action, "kill") ? ACT_ALERT : ACT_KILL;

	if (!when) {
		snprintf(err, errlen, "rule %s: missing 'when'", r->name);
		return -1;
	}
	if (parse_when(doc, when, r, err, errlen))
		return -1;

	if (r->action == ACT_KILL && r->ncond == 0) {
		snprintf(err, errlen, "rule %s: kill rule needs at least one condition", r->name);
		return -1;
	}
	if (r->event == EV_OPEN && !has_watched_path(r)) {
		snprintf(err, errlen, "rule %s: openat rules need a file.path list", r->name);
		return -1;
	}
	return 0;
}

static int count_watched(const struct ruleset *rs)
{
	int n = 0;
	for (int i = 0; i < rs->count; i++) {
		const struct rule *r = &rs->rules[i];
		for (int c = 0; r->event == EV_OPEN && c < r->ncond; c++)
			if (r->cond[c].field == F_PATH && !r->cond[c].negate)
				n += r->cond[c].count;
	}
	return n;
}

static int parse_document(yaml_document_t *doc, struct ruleset *rs, char *err, size_t errlen)
{
	yaml_node_t *root = yaml_document_get_root_node(doc);
	if (!root || root->type != YAML_SEQUENCE_NODE) {
		snprintf(err, errlen, "expected a list of rules");
		return -1;
	}

	int idx = 0;
	for (yaml_node_item_t *it = root->data.sequence.items.start; it < root->data.sequence.items.top; it++) {
		if (rs->count >= MAX_RULES) {
			snprintf(err, errlen, "too many rules (max %d)", MAX_RULES);
			return -1;
		}
		if (parse_rule(doc, yaml_document_get_node(doc, *it), ++idx, &rs->rules[rs->count], err, errlen))
			return -1;
		rs->count++;
	}

	if (rs->count == 0) {
		snprintf(err, errlen, "no rules");
		return -1;
	}
	if (count_watched(rs) > MAX_WATCHED) {
		snprintf(err, errlen, "openat rules watch more than %d files", MAX_WATCHED);
		return -1;
	}
	return 0;
}

static int extra_document(yaml_parser_t *parser)
{
	yaml_document_t doc;
	if (!yaml_parser_load(parser, &doc))
		return 1;
	int extra = yaml_document_get_root_node(&doc) != NULL;
	yaml_document_delete(&doc);
	return extra;
}

int rules_load(const char *path, struct ruleset *rs, char *err, size_t errlen)
{
	memset(rs, 0, sizeof(*rs));

	FILE *f = fopen(path, "r");
	if (!f) {
		snprintf(err, errlen, "cannot open %s", path);
		return -1;
	}

	yaml_parser_t parser;
	yaml_document_t doc;
	int rc = -1;

	yaml_parser_initialize(&parser);
	yaml_parser_set_input_file(&parser, f);

	if (!yaml_parser_load(&parser, &doc)) {
		snprintf(err, errlen, "%s:%zu: %s", path, parser.problem_mark.line + 1,
			 parser.problem ? parser.problem : "parse error");
	} else {
		rc = parse_document(&doc, rs, err, errlen);
		yaml_document_delete(&doc);
		if (rc == 0 && extra_document(&parser)) {
			snprintf(err, errlen, "%s: only one YAML document is allowed", path);
			rc = -1;
		}
	}

	yaml_parser_delete(&parser);
	fclose(f);
	return rc;
}
