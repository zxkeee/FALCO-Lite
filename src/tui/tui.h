#ifndef FALCO_TUI_H
#define FALCO_TUI_H

#include "event.h"

struct stats {
	unsigned long events[EV_TYPE_COUNT];
	unsigned long alerts;
	unsigned long kills;
};

void tui_start(void);
void tui_stop(void);
void tui_add(const char *line, int is_kill);
int tui_draw(const struct stats *s, int rules);

#endif
