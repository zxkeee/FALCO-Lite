#ifndef FALCO_CHECK_H
#define FALCO_CHECK_H

#include <stdio.h>

static int check_failed;
static int check_total;

#define CHECK(cond)                                                              \
	do {                                                                     \
		check_total++;                                                   \
		if (!(cond)) {                                                   \
			check_failed++;                                          \
			fprintf(stderr, "%s:%d: FAIL %s\n", __FILE__, __LINE__, #cond); \
		}                                                                \
	} while (0)

#define CHECK_DONE(name)                                                         \
	do {                                                                     \
		printf("%-14s %d/%d passed\n", name, check_total - check_failed, check_total); \
		return check_failed ? 1 : 0;                                     \
	} while (0)

#endif
