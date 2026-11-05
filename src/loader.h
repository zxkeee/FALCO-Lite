/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Завантаження BPF-програм і читання ring buffer. Власник: Микита.
 * Заголовок навмисно не тягне libbpf: решта коду про нього не знає.
 */
#ifndef FALCO_LOADER_H
#define FALCO_LOADER_H

#include "events.h"

typedef void (*fl_event_cb)(const struct fl_event *e, void *ctx);

struct fl_loader;

/* open + load + attach. 0 або -errno. */
int loader_open(struct fl_loader **out, int verbose, fl_event_cb cb, void *cb_ctx);

/* Прочитати події (cb викликається на кожну). >=0 — скільки прочитано, інакше -errno. */
int loader_poll(struct fl_loader *l, int timeout_ms);

/* Скільки подій втрачено через переповнення ring buffer. */
unsigned long long loader_drops(struct fl_loader *l);

/* Скільки програм завантажено та їхні імена через кому (для банера). */
int loader_prog_names(struct fl_loader *l, char *buf, int len);

void loader_close(struct fl_loader *l);

#endif /* FALCO_LOADER_H */
