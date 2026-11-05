// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * JSON-лог: один рядок JSON на кожне правило, що спрацювало (JSONL). Власник: Назар.
 *
 * TODO(Назар):
 *  - out_json_open: c->json = fopen(c->cfg.json_path, "a"); не відкрився — повернути -1;
 *  - out_json_alert: по рядку на кожне m[i], fflush після запису. Поля:
 *      {"ts":"2026-11-05T12:00:00.123Z","host":"web-01","rule":"reverse_shell",
 *       "severity":"critical","action":"kill","killed":true,"latency_us":4012,
 *       "proc":{"pid":4213,"ppid":1337,"uid":33,"comm":"bash","exe":"/usr/bin/bash"},
 *       "ancestors":["php-fpm8.3","systemd"],
 *       "event":{"type":"connect","daddr":"10.0.0.66","dport":4444}}
 *    Без пробілів після ':' — tests/e2e/run.sh шукає "rule":"<ім'я>";
 *  - ts: CLOCK_REALTIME зараз - (fl_now_ns() - e->ts_ns);
 *  - екранування рядків (", \, керівні символи < 0x20) — окрема функція
 *    і юніт-тест для неї: comm і шляхи контролює атакувальник.
 *  - Wazuh читає цей файл сам: <localfile><log_format>json</log_format> (див. README).
 */
#include <stdio.h>
#include "output.h"

int out_json_open(struct fl_ctx *c)
{
	fprintf(stderr, "[!] JSON-лог ще не реалізовано (TODO: Назар), --json %s ігнорується\n",
		c->cfg.json_path);
	return 0;
}

void out_json_alert(struct fl_ctx *c, const struct fl_event *e,
		    const struct fl_match *m, int n, const struct fl_action_result *r)
{
	(void)e;
	(void)m;
	(void)n;
	(void)r;
	if (!c->json)
		return;
}

void out_json_close(struct fl_ctx *c)
{
	if (c->json)
		fclose(c->json);
	c->json = NULL;
}
