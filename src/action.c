// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Реакція: kill / alert. Власник: Назар.
 *
 * Готово: базовий захист (pid 1, kthreads, сам агент), --dry-run, звичайний kill().
 *
 * TODO(Назар):
 *  - замість kill(): pidfd_open(pid) -> звірити e->start_ns зі starttime з
 *    /proc/<pid>/stat (поле 22, у тіках: * 1e9 / sysconf(_SC_CLK_TCK)) ->
 *    pidfd_send_signal(SIGKILL). Інакше між подією та kill pid може
 *    дістатися іншому процесу;
 *  - список «ніколи не вбивати» за comm/exe (sshd, systemd*, containerd...),
 *    краще з конфігу;
 *  - замір затримки вже є (latency_ns) — вивести p50/p99 у підсумку.
 * Тести: tests/unit/test_action.c.
 */
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "action.h"

int action_is_protected(__u32 pid, __u32 ppid)
{
	if (pid <= 2)			/* swapper, init, kthreadd */
		return 1;
	if (ppid == 2)			/* потоки ядра */
		return 1;
	if (pid == (__u32)getpid())	/* сам агент */
		return 1;
	return 0;
}

void action_execute(struct fl_ctx *c, const struct fl_event *e,
		    const struct fl_match *m, int n, struct fl_action_result *res)
{
	memset(res, 0, sizeof(*res));
	res->requested = engine_strongest(m, n);
	res->done = res->requested;

	if (res->requested == ACT_KILL) {
		if (c->cfg.dry_run || action_is_protected(e->pid, e->ppid))
			res->done = ACT_ALERT;
		else if (kill((pid_t)e->pid, SIGKILL) == 0)
			res->killed = 1;
		else
			res->err = errno;
	}

	/* У --replay час події — з іншого завантаження системи, затримка безглузда. */
	if (!c->cfg.replay_path)
		res->latency_ns = fl_now_ns() - e->ts_ns;
}
