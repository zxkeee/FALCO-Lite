/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Рушій правил: які правила збіглися з подією. Власник: Томас. */
#ifndef FALCO_ENGINE_H
#define FALCO_ENGINE_H

#include "rules.h"
#include "proctree.h"

#define FL_MAX_MATCHES 8

struct fl_match {
	const struct fl_rule *rule;
};

/* Усі правила, що збіглися (не більше max). Повертає їхню кількість. */
int engine_match(const struct fl_ruleset *rs, struct fl_proctree *tree,
		 const struct fl_event *e, struct fl_match *out, int max);

/* Найсильніша дія серед збігів: kill > alert > log. */
enum fl_action engine_strongest(const struct fl_match *m, int n);

#endif /* FALCO_ENGINE_H */
