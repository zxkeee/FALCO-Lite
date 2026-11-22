#ifndef FALCO_OUTPUT_H
#define FALCO_OUTPUT_H

#include <stdio.h>
#include <time.h>
#include "event.h"
#include "rules.h"

#define LINE_LEN 1024

struct output {
	FILE *json;
	int use_syslog;
};

int output_open(struct output *o, const char *json_path, int use_syslog);
void output_close(struct output *o);
void output_alert(struct output *o, const char *json);

void sanitize_text(char *s);
void format_addr(const struct event *e, char *buf, size_t len);
void format_detail(const struct event *e, char *buf, size_t len);
#define CHAIN_LEN 160

struct alert {
	const struct rule *rule;
	const struct event *event;
	const char *result;
	const char *chain;
	long reaction_us;
	struct timespec ts;
};

void format_alert_json(char *buf, size_t len, const struct alert *a);
void format_alert_text(char *buf, size_t len, const struct alert *a);
void format_alert_extra(char *buf, size_t len, const struct alert *a);

#endif
