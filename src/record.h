/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Запис і відтворення подій: --record / --replay.
 *
 * Файл = заголовок + сирі struct fl_event поспіль. Записується на машині
 * з робочим eBPF, відтворюється будь-де (без root і без BTF): так рушій
 * і вивід можна налагоджувати й тестувати без ядра.
 */
#ifndef FALCO_RECORD_H
#define FALCO_RECORD_H

#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include "loader.h" /* fl_event_cb */

int record_write_header(FILE *f);
int record_write(FILE *f, const struct fl_event *e);

/*
 * Прочитати файл запису й викликати cb на кожну подію.
 * Кількість подій або -1 (причина — в errbuf). stop може бути NULL.
 */
long record_replay(FILE *f, fl_event_cb cb, void *ctx, volatile sig_atomic_t *stop,
		   char *errbuf, size_t errlen);

#endif /* FALCO_RECORD_H */
