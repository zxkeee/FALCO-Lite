#ifndef FALCO_RESPONSE_H
#define FALCO_RESPONSE_H

#include "proctree.h"

enum kill_result {
	KILL_DONE,
	KILL_DRY_RUN,
	KILL_REFUSED,
	KILL_GONE,
	KILL_FAILED,
};

int response_kill(struct proctree *t, int pid, int self, int dry_run);
const char *kill_result_name(int result);

#endif
