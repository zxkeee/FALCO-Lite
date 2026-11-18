#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include "event.h"
#include "falco.skel.h"
#include "loader.h"

static int is_exec_path_hook(struct bpf_program *prog)
{
	static const char *names[] = { "on_alloc_bprm", "on_file_open", "on_begin_exec", "on_begin_exec_done" };
	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++)
		if (!strcmp(bpf_program__name(prog), names[i]))
			return 1;
	return 0;
}

static void disable_missing_hooks(struct falco_bpf *skel)
{
	struct btf *vmlinux = btf__load_vmlinux_btf();
	if (!vmlinux)
		return;

	int exec_path_missing = 0;
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, skel->obj) {
		const char *sec = bpf_program__section_name(prog);
		if (strncmp(sec, "fentry/", 7) && strncmp(sec, "fexit/", 6))
			continue;
		const char *fn = strchr(sec, '/') + 1;
		if (btf__find_by_name_kind(vmlinux, fn, BTF_KIND_FUNC) < 0) {
			bpf_program__set_autoload(prog, false);
			fprintf(stderr, "[!] %s: not in this kernel, hook disabled\n", fn);
			exec_path_missing |= is_exec_path_hook(prog);
		}
	}
	btf__free(vmlinux);

	if (exec_path_missing) {
		bpf_program__set_autoload(skel->progs.on_commit_creds, false);
		fprintf(stderr, "[!] exec path hooks unavailable, setuid hook disabled\n");
	}
}

static int attach_one(struct loader *l, struct bpf_program *prog)
{
	if (!bpf_program__autoload(prog) || l->nlinks >= MAX_LINKS)
		return 0;
	struct bpf_link *link = bpf_program__attach(prog);
	if (!link) {
		fprintf(stderr, "[!] %s: failed to attach hook\n", bpf_program__name(prog));
		return -1;
	}
	l->links[l->nlinks++] = link;
	return 0;
}

static int attach_all(struct loader *l)
{
	struct bpf_program *prog;
	int exec_path_failed = 0;

	bpf_object__for_each_program(prog, l->skel->obj) {
		if (prog == l->skel->progs.on_commit_creds)
			continue;
		if (attach_one(l, prog))
			exec_path_failed |= is_exec_path_hook(prog);
	}

	if (exec_path_failed)
		fprintf(stderr, "[!] exec path hooks unavailable, setuid hook disabled\n");
	else
		attach_one(l, l->skel->progs.on_commit_creds);

	return l->nlinks > 0 ? 0 : -1;
}

int loader_start(struct loader *l)
{
	memset(l, 0, sizeof(*l));

	struct stat ns;
	if (stat("/proc/self/ns/pid", &ns)) {
		perror("stat /proc/self/ns/pid");
		return -1;
	}

	l->skel = falco_bpf__open();
	if (!l->skel) {
		fprintf(stderr, "failed to open eBPF object\n");
		return -1;
	}
	l->skel->rodata->pidns_ino = ns.st_ino;
	disable_missing_hooks(l->skel);

	if (falco_bpf__load(l->skel)) {
		fprintf(stderr, "failed to load eBPF programs\n");
		loader_stop(l);
		return -1;
	}
	if (attach_all(l)) {
		fprintf(stderr, "failed to attach eBPF programs\n");
		loader_stop(l);
		return -1;
	}
	return 0;
}

void loader_stop(struct loader *l)
{
	for (int i = 0; i < l->nlinks; i++)
		bpf_link__destroy(l->links[i]);
	l->nlinks = 0;
	falco_bpf__destroy(l->skel);
	l->skel = NULL;
}

int loader_events_fd(const struct loader *l)
{
	return bpf_map__fd(l->skel->maps.events);
}

static int find_key(const struct file_id *key, const struct file_id *keys, int n)
{
	for (int i = 0; i < n; i++)
		if (!memcmp(key, &keys[i], sizeof(*key)))
			return i;
	return -1;
}

static int watch_file(struct bpf_map *map, const char *path, struct file_id *keys,
		      const char **paths, int n, int warn)
{
	struct stat st;
	if (n >= MAX_WATCHED || stat(path, &st))
		return n;

	struct file_id key;
	struct path_buf value;
	memset(&key, 0, sizeof(key));
	memset(&value, 0, sizeof(value));
	key.ino = st.st_ino;
	key.dev = (major(st.st_dev) << 20) | minor(st.st_dev);
	snprintf(value.path, sizeof(value.path), "%s", path);

	int same = find_key(&key, keys, n);
	if (same >= 0) {
		if (warn && strcmp(paths[same], path))
			fprintf(stderr, "[!] %s and %s are the same file, alerts will name %s\n",
				paths[same], path, paths[same]);
		return n;
	}

	if (bpf_map__update_elem(map, &key, sizeof(key), &value, sizeof(value), BPF_ANY)) {
		if (warn)
			fprintf(stderr, "[!] cannot watch %s\n", path);
		return n;
	}
	keys[n] = key;
	paths[n] = path;
	return n + 1;
}

static void prune_watched(struct bpf_map *map, const struct file_id *keys, int n)
{
	struct file_id cur, next;
	int has_cur = 0;
	while (bpf_map__get_next_key(map, has_cur ? &cur : NULL, &next, sizeof(next)) == 0) {
		if (find_key(&next, keys, n) < 0) {
			bpf_map__delete_elem(map, &next, sizeof(next), 0);
			continue;
		}
		cur = next;
		has_cur = 1;
	}
}

void loader_watch_files(struct loader *l, const struct ruleset *rs)
{
	struct bpf_map *map = l->skel->maps.watched_files;
	struct file_id keys[MAX_WATCHED];
	const char *paths[MAX_WATCHED];
	int n = 0;

	for (int i = 0; i < rs->count; i++) {
		const struct rule *r = &rs->rules[i];
		for (int c = 0; r->event == EV_OPEN && c < r->ncond; c++) {
			const struct condition *cond = &r->cond[c];
			for (int v = 0; cond->field == F_PATH && !cond->negate && v < cond->count; v++)
				n = watch_file(map, cond->values[v], keys, paths, n, !l->watched_once);
		}
	}
	l->watched_once = 1;
	prune_watched(map, keys, n);
}
