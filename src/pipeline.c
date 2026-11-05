// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Шлях однієї події: дерево процесів -> вивід -> правила -> реакція.
 * Один потік: колбек ring buffer викликає pipeline_handle, kill виконується
 * прямо тут — так затримка мінімальна і не потрібні блокування.
 */
#include "falco.h"
#include "engine.h"
#include "action.h"
#include "output.h"
#include "record.h"

void pipeline_handle(const struct fl_event *e, void *ctx)
{
	struct fl_ctx *c = ctx;
	struct fl_match m[FL_MAX_MATCHES];
	struct fl_action_result res;
	int n;

	if (e->type == 0 || e->type >= EV__MAX)
		return;
	if (!c->t0_ns)
		c->t0_ns = e->ts_ns;
	c->stats.events[e->type]++;

	if (c->record)
		record_write(c->record, e);

	/* Спершу дерево: після exec правила мають бачити новий comm/exe. */
	proctree_update(c->tree, e);
	output_event(c, e);

	n = engine_match(&c->rules, c->tree, e, m, FL_MAX_MATCHES);
	if (n > 0) {
		c->stats.alerts++;
		action_execute(c, e, m, n, &res);
		if (res.killed)
			c->stats.kills++;
		output_alert(c, e, m, n, &res);
	}

	/* Процес, що завершився, прибираємо останнім, щоб вивід ще бачив його. */
	if (e->type == EV_EXIT)
		proctree_remove(c->tree, e->pid);
}
