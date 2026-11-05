// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <string.h>
#include "record.h"

static const char rec_magic[8] = { 'F', 'L', 'R', 'E', 'C', '1', 0, 0 };

struct fl_rec_header {
	char magic[8];
	__u32 event_size;	/* sizeof(struct fl_event) на момент запису */
	__u32 reserved;
};

int record_write_header(FILE *f)
{
	struct fl_rec_header h;

	memset(&h, 0, sizeof(h));
	memcpy(h.magic, rec_magic, sizeof(rec_magic));
	h.event_size = sizeof(struct fl_event);
	return fwrite(&h, sizeof(h), 1, f) == 1 ? 0 : -1;
}

int record_write(FILE *f, const struct fl_event *e)
{
	return fwrite(e, sizeof(*e), 1, f) == 1 ? 0 : -1;
}

long record_replay(FILE *f, fl_event_cb cb, void *ctx, volatile sig_atomic_t *stop,
		   char *errbuf, size_t errlen)
{
	struct fl_rec_header h;
	struct fl_event e;
	long n = 0;

	if (fread(&h, sizeof(h), 1, f) != 1 || memcmp(h.magic, rec_magic, sizeof(rec_magic))) {
		snprintf(errbuf, errlen, "це не файл запису falco-lite (--record)");
		return -1;
	}
	if (h.event_size != sizeof(struct fl_event)) {
		snprintf(errbuf, errlen,
			 "запис зроблено з іншою версією events.h (подія %u байтів, зараз %zu)",
			 h.event_size, sizeof(struct fl_event));
		return -1;
	}

	while ((!stop || !*stop) && fread(&e, sizeof(e), 1, f) == 1) {
		cb(&e, ctx);
		n++;
	}
	return n;
}
