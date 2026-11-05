// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Диспетчер виводу і текстовий вивід у stdout у форматі демо зі слайда:
 *
 *   17.102 EXEC     pid=4213 /usr/bin/bash ← php-fpm(1337)
 *   17.104 CONNECT  pid=4213 bash → 10.0.0.66:4444/tcp
 *   17.105 ALERT    reverse_shell      critical
 *   17.106 ACTION   kill(4213, SIGKILL)  4.0 ms
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "output.h"

static int g_text = 1; /* 0, коли працює TUI */

static double rel_s(const struct fl_ctx *c, __u64 ts)
{
	return (double)(long long)(ts - c->t0_ns) / 1e9;
}

static const char *parent_name(struct fl_ctx *c, __u32 ppid)
{
	const struct fl_proc *p = proctree_lookup(c->tree, ppid);

	return p ? p->comm : "?";
}

int output_open(struct fl_ctx *c)
{
	if (c->cfg.json_path && out_json_open(c))
		return -1;
	if (c->cfg.use_syslog && out_syslog_open(c))
		return -1;
	if (c->cfg.use_tui) {
		if (tui_open(c) == 0)
			g_text = 0;
		else
			fprintf(stderr, "[!] TUI недоступний, вивід буде текстом\n");
	}
	return 0;
}

void output_event(struct fl_ctx *c, const struct fl_event *e)
{
	const char *label = fl_event_label(e->type);
	double t = rel_s(c, e->ts_ns);
	char addr[INET_ADDRSTRLEN];

	if (!g_text) {
		tui_event(c, e);
		return;
	}

	switch (e->type) {
	case EV_EXEC:
		printf("%8.3f %-8s pid=%u %.256s ← %.16s(%u)\n", t, label, e->pid,
		       e->exec.filename, parent_name(c, e->ppid), e->ppid);
		break;
	case EV_CONNECT:
		if (!inet_ntop(AF_INET, &e->connect.daddr, addr, sizeof(addr)))
			strcpy(addr, "?");
		printf("%8.3f %-8s pid=%u %.16s → %s:%u/tcp\n", t, label, e->pid,
		       e->comm, addr, (unsigned)e->connect.dport);
		break;
	case EV_OPEN:
		printf("%8.3f %-8s pid=%u %.16s %.256s\n", t, label, e->pid, e->comm, e->open.path);
		break;
	case EV_SETUID:
		printf("%8.3f %-8s pid=%u %.16s uid %u → %u\n", t, label, e->pid, e->comm,
		       e->uid, e->setuid.target_uid);
		break;
	case EV_PTRACE:
		printf("%8.3f %-8s pid=%u %.16s request=%lld target=%u\n", t, label, e->pid,
		       e->comm, (long long)e->ptrace.request, e->ptrace.target_pid);
		break;
	case EV_FORK:
		if (c->cfg.verbose)
			printf("%8.3f %-8s pid=%u %.16s ← %.16s(%u)\n", t, label, e->pid, e->comm,
			       parent_name(c, e->ppid), e->ppid);
		break;
	case EV_EXIT:
		if (c->cfg.verbose)
			printf("%8.3f %-8s pid=%u %.16s code=%d\n", t, label, e->pid, e->comm,
			       e->exit.exit_code);
		break;
	}
}

void output_alert(struct fl_ctx *c, const struct fl_event *e,
		  const struct fl_match *m, int n, const struct fl_action_result *r)
{
	double t = rel_s(c, e->ts_ns + r->latency_ns);
	int i;

	out_json_alert(c, e, m, n, r);
	out_syslog_alert(c, e, m, n, r);

	if (!g_text) {
		tui_alert(c, e, m, n, r);
		return;
	}

	for (i = 0; i < n; i++)
		printf("%8.3f %-8s %-18s %s\n", t, "ALERT", m[i].rule->name,
		       fl_severity_name(m[i].rule->severity));

	switch (r->done) {
	case ACT_KILL:
		if (r->killed)
			printf("%8.3f %-8s kill(%u, SIGKILL)  %.1f ms\n", t, "ACTION", e->pid,
			       (double)r->latency_ns / 1e6);
		else
			printf("%8.3f %-8s kill(%u) не вдався: %s\n", t, "ACTION", e->pid,
			       strerror(r->err));
		break;
	case ACT_ALERT:
		if (r->requested == ACT_KILL)
			printf("%8.3f %-8s kill(%u) пропущено: %s\n", t, "ACTION", e->pid,
			       c->cfg.dry_run ? "--dry-run" : "захищений процес");
		else
			printf("%8.3f %-8s alert\n", t, "ACTION");
		break;
	case ACT_LOG:
		break;
	}
}

void output_tick(struct fl_ctx *c)
{
	if (!g_text)
		tui_tick(c);
}

void output_close(struct fl_ctx *c)
{
	if (!g_text) {
		tui_close(c);
		g_text = 1;
	}
	out_syslog_close(c);
	out_json_close(c);
}

void output_summary(struct fl_ctx *c)
{
	unsigned long long total = 0;
	int i;

	for (i = 1; i < EV__MAX; i++)
		total += c->stats.events[i];

	printf("підсумок: подій %llu, алертів %llu, процесів зупинено %llu, "
	       "втрачено в ring buffer %llu\n",
	       total, c->stats.alerts, c->stats.kills, c->stats.drops);

	if (c->cfg.verbose)
		for (i = 1; i < EV__MAX; i++)
			printf("  %-8s %llu\n", fl_event_label(i), c->stats.events[i]);
}
