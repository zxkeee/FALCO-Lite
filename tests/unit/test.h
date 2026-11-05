/* Міні-фреймворк юніт-тестів: без залежностей, один бінарник. */
#ifndef FL_TEST_H
#define FL_TEST_H

#include <stdio.h>
#include <string.h>

extern int t_status; /* 0 — ok, 1 — fail, 2 — skip */

#define TEST(name) void name(void)

#define CHECK(cond)                                                          \
	do {                                                                 \
		if (!(cond)) {                                               \
			fprintf(stderr, "    %s:%d: CHECK(%s)\n", __FILE__,     \
				__LINE__, #cond);                            \
			t_status = 1;                                        \
			return;                                              \
		}                                                            \
	} while (0)

/*
 * Тест на ще не реалізовану частину: пишеться заздалегідь, одразу після SKIP.
 * Коли модуль готовий — видалити рядок SKIP, і тест почне перевірятися.
 */
#define SKIP(why)                                                            \
	do {                                                                 \
		fprintf(stderr, "    skip: %s\n", why);                         \
		t_status = 2;                                                \
		return;                                                      \
	} while (0)

#endif /* FL_TEST_H */
