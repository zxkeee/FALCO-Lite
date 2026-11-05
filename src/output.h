/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Вивід: текст у stdout (output.c), JSON-лог, syslog, TUI. Власник: Назар.
 */
#ifndef FALCO_OUTPUT_H
#define FALCO_OUTPUT_H

#include "falco.h"
#include "engine.h"
#include "action.h"

/* Диспетчер (output.c). */
int output_open(struct fl_ctx *c);
void output_event(struct fl_ctx *c, const struct fl_event *e);
void output_alert(struct fl_ctx *c, const struct fl_event *e,
		  const struct fl_match *m, int n, const struct fl_action_result *r);
void output_tick(struct fl_ctx *c);	/* ~10 разів на секунду з головного циклу */
void output_close(struct fl_ctx *c);
void output_summary(struct fl_ctx *c);	/* підсумок у stdout, після output_close */

/* Приймачі. *_open: 0 — працює або вимкнений, -1 — фатальна помилка. */
int out_json_open(struct fl_ctx *c);
void out_json_alert(struct fl_ctx *c, const struct fl_event *e,
		    const struct fl_match *m, int n, const struct fl_action_result *r);
void out_json_close(struct fl_ctx *c);

int out_syslog_open(struct fl_ctx *c);
void out_syslog_alert(struct fl_ctx *c, const struct fl_event *e,
		      const struct fl_match *m, int n, const struct fl_action_result *r);
void out_syslog_close(struct fl_ctx *c);

/* TUI: tui_open повертає -1, якщо не вийшло — тоді вивід іде текстом. */
int tui_open(struct fl_ctx *c);
void tui_event(struct fl_ctx *c, const struct fl_event *e);
void tui_alert(struct fl_ctx *c, const struct fl_event *e,
	       const struct fl_match *m, int n, const struct fl_action_result *r);
void tui_tick(struct fl_ctx *c);
void tui_close(struct fl_ctx *c);

#endif /* FALCO_OUTPUT_H */
