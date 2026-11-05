/*
 * Запуск усіх юніт-тестів: make test.
 * Новий тест: TEST(ім'я) у своєму test_*.c і рядок RUN(ім'я) тут.
 */
#include <stdio.h>
#include "test.h"

int t_status;
static int passed, failed, skipped;

static void report(const char *name)
{
	switch (t_status) {
	case 0:
		passed++;
		printf("  ok    %s\n", name);
		break;
	case 1:
		failed++;
		printf("  FAIL  %s\n", name);
		break;
	default:
		skipped++;
		printf("  skip  %s\n", name);
		break;
	}
}

#define RUN(fn)                     \
	do {                        \
		void fn(void);      \
		t_status = 0;       \
		fn();               \
		report(#fn);        \
	} while (0)

int main(void)
{
	setvbuf(stdout, NULL, _IONBF, 0);

	printf("record\n");
	RUN(test_record_roundtrip);
	RUN(test_record_rejects_garbage);

	printf("rules\n");
	RUN(test_names);
	RUN(test_rules_missing_file);
	RUN(test_rules_load_default);
	RUN(test_rules_bad_field_reports_line);

	printf("engine\n");
	RUN(test_strongest_action);
	RUN(test_reverse_shell_matches);
	RUN(test_shell_without_webserver_no_match);
	RUN(test_wrong_syscall_no_match);

	printf("proctree\n");
	RUN(test_proctree_fork_exec_lookup);
	RUN(test_proctree_exit_removes);
	RUN(test_proctree_ancestor_glob_and_depth);
	RUN(test_proctree_unknown_pid);

	printf("action\n");
	RUN(test_protected_pids);
	RUN(test_dry_run_never_kills);

	printf("\n%d ok, %d skip, %d fail\n", passed, skipped, failed);
	return failed ? 1 : 0;
}
