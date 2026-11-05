// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * syslog. Власник: Назар.
 *
 * TODO(Назар):
 *  - out_syslog_open: openlog("falco-lite", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
 *  - out_syslog_alert: syslog(пріоритет за severity: critical -> LOG_CRIT,
 *    high -> LOG_ERR, medium -> LOG_WARNING, low -> LOG_NOTICE,
 *    "rule=%s severity=%s action=%s pid=%u ppid=%u comm=%s ...");
 *  - out_syslog_close: closelog().
 *  Надсилання у віддалений syslog / Wazuh manager налаштовується в rsyslog,
 *  а не тут (див. README).
 */
#include <stdio.h>
#include "output.h"

int out_syslog_open(struct fl_ctx *c)
{
	(void)c;
	fprintf(stderr, "[!] syslog ще не реалізовано (TODO: Назар), --syslog ігнорується\n");
	return 0;
}

void out_syslog_alert(struct fl_ctx *c, const struct fl_event *e,
		      const struct fl_match *m, int n, const struct fl_action_result *r)
{
	(void)c;
	(void)e;
	(void)m;
	(void)n;
	(void)r;
}

void out_syslog_close(struct fl_ctx *c)
{
	(void)c;
}
