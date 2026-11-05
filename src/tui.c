// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * TUI на ncurses. Власник: Назар.
 *
 * TODO(Назар):
 *  - tui_open: initscr(), cbreak(), noecho(), nodelay(stdscr, TRUE), кольори;
 *    стан (кільцевий буфер останніх рядків, лічильники) — у c->tui;
 *  - шапка: події/с за типами (c->stats.events), алерти, kill'и,
 *    втрати ring buffer (c->stats.drops), режим --dry-run;
 *  - стрічка подій (tui_event) і виділені алерти (tui_alert);
 *  - tui_tick: перемальовування не частіше ~5 разів на секунду, getch(): q — вихід
 *    (потрібен спосіб сказати main зупинитися — наприклад, прапорець у fl_ctx);
 *  - tui_close: endwin().
 *  Посилання на ncurses у Makefile вже є (-lncursesw).
 */
#include "output.h"

int tui_open(struct fl_ctx *c)
{
	(void)c;
	return -1; /* не реалізовано: output.c виведе текстом */
}

void tui_event(struct fl_ctx *c, const struct fl_event *e)
{
	(void)c;
	(void)e;
}

void tui_alert(struct fl_ctx *c, const struct fl_event *e,
	       const struct fl_match *m, int n, const struct fl_action_result *r)
{
	(void)c;
	(void)e;
	(void)m;
	(void)n;
	(void)r;
}

void tui_tick(struct fl_ctx *c)
{
	(void)c;
}

void tui_close(struct fl_ctx *c)
{
	(void)c;
}
