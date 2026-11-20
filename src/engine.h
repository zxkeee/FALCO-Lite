#ifndef FALCO_ENGINE_H
#define FALCO_ENGINE_H

#include "event.h"
#include "proctree.h"
#include "rules.h"

int engine_process(const struct ruleset *rs, struct proctree *t, const struct event *e,
		   const struct rule **matches, int max);

#endif
