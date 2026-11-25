#include <ncurses.h>
#include <stdio.h>
#include <string.h>
#include "rules.h"
#include "tui.h"

#define TUI_LINES 200
#define TUI_WIDTH 512

static char lines[TUI_LINES][TUI_WIDTH];
static int kills[TUI_LINES];
static int head;
static int stored;

void tui_start(void)
{
	initscr();
	cbreak();
	noecho();
	nodelay(stdscr, TRUE);
	keypad(stdscr, TRUE);
	curs_set(0);
	if (has_colors()) {
		start_color();
		use_default_colors();
		init_pair(1, COLOR_RED, -1);
		init_pair(2, COLOR_YELLOW, -1);
		init_pair(3, COLOR_BLACK, COLOR_CYAN);
	}
}

void tui_stop(void)
{
	endwin();
}

void tui_add(const char *line, int is_kill)
{
	snprintf(lines[head], TUI_WIDTH, "%s", line);
	kills[head] = is_kill;
	head = (head + 1) % TUI_LINES;
	if (stored < TUI_LINES)
		stored++;
}

static void draw_header(const struct stats *s, int rules)
{
	unsigned long total = 0;
	for (int t = 1; t < EV_TYPE_COUNT; t++)
		total += s->events[t];

	attron(COLOR_PAIR(3) | A_BOLD);
	mvhline(0, 0, ' ', COLS);
	mvprintw(0, 1, "Falco-lite  rules: %d  events: %lu  alerts: %lu  killed: %lu  (q to quit)",
		 rules, total, s->alerts, s->kills);
	attroff(COLOR_PAIR(3) | A_BOLD);

	move(1, 1);
	for (int t = 1; t < EV_TYPE_COUNT; t++)
		printw("%s %lu   ", event_name(t), s->events[t]);

	attron(A_BOLD);
	mvprintw(3, 1, "Recent alerts");
	attroff(A_BOLD);
}

int tui_draw(const struct stats *s, int rules)
{
	int ch = getch();
	if (ch == 'q' || ch == 'Q')
		return 1;

	erase();
	draw_header(s, rules);

	int rows = LINES - 4;
	for (int i = 0; i < stored && i < rows; i++) {
		int idx = (head - 1 - i + TUI_LINES) % TUI_LINES;
		int pair = kills[idx] ? 1 : 2;
		attron(COLOR_PAIR(pair));
		mvaddnstr(4 + i, 1, lines[idx], COLS - 2);
		attroff(COLOR_PAIR(pair));
	}

	refresh();
	return 0;
}
