#include <errno.h>
#include <signal.h>
#include "response.h"

int response_kill(struct proctree *t, int pid, int self, int dry_run)
{
	if (pid <= 1 || pid == self || proctree_is_ancestor(t, pid, self))
		return KILL_REFUSED;
	if (dry_run)
		return KILL_DRY_RUN;
	if (kill(pid, SIGKILL) == 0)
		return KILL_DONE;
	return errno == ESRCH ? KILL_GONE : KILL_FAILED;
}

const char *kill_result_name(int result)
{
	switch (result) {
	case KILL_DONE:
		return "killed";
	case KILL_DRY_RUN:
		return "would_kill";
	case KILL_REFUSED:
		return "kill_refused";
	case KILL_GONE:
		return "already_exited";
	}
	return "kill_failed";
}
