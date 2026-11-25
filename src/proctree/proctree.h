#ifndef FALCO_PROCTREE_H
#define FALCO_PROCTREE_H

#include <stddef.h>
#include "event.h"

#define TREE_BUCKETS 4096
#define CHAIN_DEPTH 4
#define MAX_DEPTH 4096
#define MAX_DEAD 65536

struct proc {
	int pid;
	int ppid;
	int children;
	int dead;
	char comm[COMM_LEN];
	char exe[PATH_LEN];
	struct proc *next;
};

struct proctree {
	struct proc *buckets[TREE_BUCKETS];
	int count;
	int dead;
};

struct proctree *proctree_new(void);
void proctree_free(struct proctree *t);
struct proc *proctree_get(struct proctree *t, int pid);
struct proc *proctree_set(struct proctree *t, int pid, int ppid, const char *comm, const char *exe);
void proctree_exit(struct proctree *t, int pid);
int proctree_seed(struct proctree *t, const char *proc_root);
int proctree_has_ancestor(struct proctree *t, int pid, const char *comm);
int proctree_is_ancestor(struct proctree *t, int ancestor, int pid);
void proctree_chain(struct proctree *t, int pid, const char *self, char *buf, size_t len);

#endif
