#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "proctree.h"

static unsigned int bucket(int pid)
{
	return (unsigned int)pid % TREE_BUCKETS;
}

static void copy_field(char *dst, size_t len, const char *src)
{
	snprintf(dst, len, "%s", src ? src : "");
}

struct proctree *proctree_new(void)
{
	return calloc(1, sizeof(struct proctree));
}

void proctree_free(struct proctree *t)
{
	if (!t)
		return;
	for (int i = 0; i < TREE_BUCKETS; i++) {
		struct proc *p = t->buckets[i];
		while (p) {
			struct proc *next = p->next;
			free(p);
			p = next;
		}
	}
	free(t);
}

struct proc *proctree_get(struct proctree *t, int pid)
{
	for (struct proc *p = t->buckets[bucket(pid)]; p; p = p->next)
		if (p->pid == pid)
			return p;
	return NULL;
}

static struct proc *parent_of(struct proctree *t, struct proc *p)
{
	return p->ppid == p->pid ? NULL : proctree_get(t, p->ppid);
}

static void unlink_node(struct proctree *t, int pid)
{
	struct proc **pp = &t->buckets[bucket(pid)];
	while (*pp) {
		if ((*pp)->pid == pid) {
			struct proc *gone = *pp;
			*pp = gone->next;
			if (gone->dead)
				t->dead--;
			free(gone);
			t->count--;
			return;
		}
		pp = &(*pp)->next;
	}
}

static void release(struct proctree *t, struct proc *p)
{
	while (p && p->dead && p->children <= 0) {
		struct proc *parent = parent_of(t, p);
		unlink_node(t, p->pid);
		if (parent && parent->children > 0)
			parent->children--;
		p = parent;
	}
}

static void set_parent(struct proctree *t, struct proc *p, int ppid)
{
	struct proc *old = parent_of(t, p);
	if (old && old->children > 0)
		old->children--;

	p->ppid = ppid;
	struct proc *parent = parent_of(t, p);
	if (parent)
		parent->children++;

	if (old && old != parent)
		release(t, old);
}

struct proc *proctree_set(struct proctree *t, int pid, int ppid, const char *comm, const char *exe)
{
	struct proc *p = proctree_get(t, pid);
	if (!p) {
		p = calloc(1, sizeof(*p));
		if (!p)
			return NULL;
		p->pid = pid;
		p->ppid = pid;
		p->next = t->buckets[bucket(pid)];
		t->buckets[bucket(pid)] = p;
		t->count++;
	}

	if (p->dead) {
		p->dead = 0;
		t->dead--;
	}
	if (p->ppid != ppid)
		set_parent(t, p, ppid);
	if (comm)
		copy_field(p->comm, sizeof(p->comm), comm);
	if (exe)
		copy_field(p->exe, sizeof(p->exe), exe);
	return p;
}

static void adopt_children(struct proctree *t, struct proc *p, struct proc *parent)
{
	for (int i = 0; i < TREE_BUCKETS; i++)
		for (struct proc *c = t->buckets[i]; c; c = c->next) {
			if (c == p || c->ppid != p->pid)
				continue;
			c->ppid = parent ? parent->pid : c->pid;
			if (parent)
				parent->children++;
		}
	p->children = 0;
}

void proctree_exit(struct proctree *t, int pid)
{
	struct proc *p = proctree_get(t, pid);
	if (!p || p->dead)
		return;

	p->dead = 1;
	t->dead++;

	struct proc *parent = parent_of(t, p);
	int same_name = parent && parent->dead && !strcmp(parent->comm, p->comm);
	if (p->children > 0 && (same_name || t->dead > MAX_DEAD))
		adopt_children(t, p, parent);

	release(t, p);
}

static int read_stat(const char *root, int pid, int *ppid, char *comm, size_t len)
{
	char path[PATH_LEN];
	char buf[512];
	snprintf(path, sizeof(path), "%s/%d/stat", root, pid);

	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	size_t n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';

	char *open = strchr(buf, '(');
	char *close = strrchr(buf, ')');
	if (!open || !close || close < open)
		return -1;

	*close = '\0';
	copy_field(comm, len, open + 1);
	return sscanf(close + 2, "%*c %d", ppid) == 1 ? 0 : -1;
}

static void recount(struct proctree *t)
{
	for (int i = 0; i < TREE_BUCKETS; i++)
		for (struct proc *p = t->buckets[i]; p; p = p->next)
			p->children = 0;

	for (int i = 0; i < TREE_BUCKETS; i++)
		for (struct proc *p = t->buckets[i]; p; p = p->next) {
			struct proc *parent = parent_of(t, p);
			if (parent)
				parent->children++;
		}
}

int proctree_seed(struct proctree *t, const char *proc_root)
{
	DIR *d = opendir(proc_root);
	if (!d)
		return -1;

	struct dirent *de;
	while ((de = readdir(d))) {
		if (!isdigit((unsigned char)de->d_name[0]))
			continue;

		int pid = atoi(de->d_name);
		int ppid;
		char comm[COMM_LEN];
		if (read_stat(proc_root, pid, &ppid, comm, sizeof(comm)))
			continue;

		char link[PATH_LEN];
		char exe[PATH_LEN] = "";
		snprintf(link, sizeof(link), "%s/%d/exe", proc_root, pid);
		ssize_t n = readlink(link, exe, sizeof(exe) - 1);
		exe[n > 0 ? n : 0] = '\0';

		proctree_set(t, pid, ppid, comm, exe);
	}

	closedir(d);
	recount(t);
	return 0;
}

int proctree_has_ancestor(struct proctree *t, int pid, const char *comm)
{
	struct proc *p = proctree_get(t, pid);
	for (int depth = 0; p && depth < MAX_DEPTH; depth++) {
		p = parent_of(t, p);
		if (p && !strcmp(p->comm, comm))
			return 1;
	}
	return 0;
}

void proctree_chain(struct proctree *t, int pid, const char *self, char *buf, size_t len)
{
	size_t off = 0;
	buf[0] = '\0';

	struct proc *p = proctree_get(t, pid);
	for (int depth = 0; p && depth <= CHAIN_DEPTH && off + 1 < len; depth++) {
		const char *sep = depth ? " ← " : "";
		const char *name = depth == CHAIN_DEPTH ? "…" : depth == 0 && self ? self : p->comm;
		int n = snprintf(buf + off, len - off, "%s%s", sep, name);
		if (n < 0)
			break;
		off += (size_t)n < len - off ? (size_t)n : len - off - 1;
		if (p->pid <= 1)
			break;
		p = parent_of(t, p);
	}
}

int proctree_is_ancestor(struct proctree *t, int ancestor, int pid)
{
	struct proc *p = proctree_get(t, pid);
	for (int depth = 0; p && depth < MAX_DEPTH; depth++) {
		if (p->ppid == ancestor && p->ppid != p->pid)
			return 1;
		p = parent_of(t, p);
	}
	return 0;
}
