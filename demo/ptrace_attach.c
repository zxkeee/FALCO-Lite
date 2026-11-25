#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
	pid_t child = fork();
	if (child == 0) {
		sleep(5);
		return 0;
	}

	usleep(100000);
	if (ptrace(PTRACE_ATTACH, child, NULL, NULL) == 0)
		waitpid(child, NULL, 0);
	sleep(5);
	kill(child, SIGKILL);
	return 0;
}
