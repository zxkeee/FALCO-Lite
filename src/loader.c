// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "loader.h"
#include "falco.skel.h"

struct fl_loader {
	struct falco_bpf *skel;
	struct ring_buffer *rb;
	fl_event_cb cb;
	void *cb_ctx;
};

static int g_verbose;

static int print_libbpf(enum libbpf_print_level level, const char *fmt, va_list args)
{
	if (level == LIBBPF_DEBUG && !g_verbose)
		return 0;
	return vfprintf(stderr, fmt, args);
}

static int on_sample(void *ctx, void *data, size_t size)
{
	struct fl_loader *l = ctx;

	if (size < sizeof(struct fl_event))
		return 0;
	l->cb(data, l->cb_ctx);
	return 0;
}

int loader_open(struct fl_loader **out, int verbose, fl_event_cb cb, void *cb_ctx)
{
	struct fl_loader *l;
	int err;

	g_verbose = verbose;
	libbpf_set_print(print_libbpf);

	l = calloc(1, sizeof(*l));
	if (!l)
		return -ENOMEM;
	l->cb = cb;
	l->cb_ctx = cb_ctx;

	l->skel = falco_bpf__open();
	if (!l->skel) {
		err = -errno;
		fprintf(stderr, "[-] не вдалося відкрити BPF-об'єкт\n");
		goto fail;
	}
	l->skel->rodata->self_tgid = (__u32)getpid();

	err = falco_bpf__load(l->skel);
	if (err) {
		fprintf(stderr, "[-] завантаження BPF не вдалося (%d): потрібен root або CAP_BPF+CAP_PERFMON, "
				"і ядро 5.8+ з BTF (/sys/kernel/btf/vmlinux)\n", err);
		goto fail;
	}

	err = falco_bpf__attach(l->skel);
	if (err) {
		fprintf(stderr, "[-] не вдалося підключити BPF-програми (%d)\n", err);
		goto fail;
	}

	l->rb = ring_buffer__new(bpf_map__fd(l->skel->maps.events), on_sample, l, NULL);
	if (!l->rb) {
		err = -errno;
		fprintf(stderr, "[-] не вдалося відкрити ring buffer (%d)\n", err);
		goto fail;
	}

	*out = l;
	return 0;
fail:
	loader_close(l);
	return err ? err : -EINVAL;
}

int loader_poll(struct fl_loader *l, int timeout_ms)
{
	return ring_buffer__poll(l->rb, timeout_ms);
}

unsigned long long loader_drops(struct fl_loader *l)
{
	int ncpu = libbpf_num_possible_cpus();
	unsigned long long total = 0;
	__u64 *vals;
	__u32 key = 0;
	int i;

	if (ncpu <= 0)
		return 0;
	vals = calloc(ncpu, sizeof(*vals));
	if (!vals)
		return 0;
	if (!bpf_map__lookup_elem(l->skel->maps.drops, &key, sizeof(key),
				  vals, ncpu * sizeof(*vals), 0)) {
		for (i = 0; i < ncpu; i++)
			total += vals[i];
	}
	free(vals);
	return total;
}

int loader_prog_names(struct fl_loader *l, char *buf, int len)
{
	struct bpf_program *prog;
	int n = 0, off = 0;
	const char *name;

	buf[0] = '\0';
	bpf_object__for_each_program(prog, l->skel->obj) {
		name = bpf_program__name(prog);
		/* handle_exec -> exec */
		if (!strncmp(name, "handle_", 7))
			name += 7;
		if (off < len)
			off += snprintf(buf + off, len - off, "%s%s", n ? ", " : "", name);
		n++;
	}
	return n;
}

void loader_close(struct fl_loader *l)
{
	if (!l)
		return;
	ring_buffer__free(l->rb);
	falco_bpf__destroy(l->skel);
	free(l);
}
