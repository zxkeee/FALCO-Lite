#ifndef FALCO_LOADER_H
#define FALCO_LOADER_H

#include "rules.h"

#define MAX_LINKS 32

struct falco_bpf;
struct bpf_link;

struct loader {
	struct falco_bpf *skel;
	struct bpf_link *links[MAX_LINKS];
	int nlinks;
	int watched_once;
};

int loader_start(struct loader *l);
void loader_stop(struct loader *l);
int loader_events_fd(const struct loader *l);
void loader_watch_files(struct loader *l, const struct ruleset *rs);

#endif
