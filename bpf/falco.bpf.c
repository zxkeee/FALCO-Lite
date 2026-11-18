#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "event.h"

#define OPEN_FOR_EXEC 0x20
#define MAX_NS_LEVEL 8
#define AF_INET 2
#define AF_INET6 10

char LICENSE[] SEC("license") = "GPL";

const volatile unsigned int pidns_ino = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, struct path_buf);
} exec_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, unsigned long long);
	__type(value, char);
} in_exec SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct file_id);
	__type(value, struct path_buf);
} watched_files SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct path_buf);
} scratch SEC(".maps");

static unsigned long long task_key(void)
{
	return bpf_get_current_task();
}

static int ns_tgid(struct task_struct *task)
{
	struct pid *pid = BPF_CORE_READ(task, group_leader, thread_pid);
	unsigned int level = BPF_CORE_READ(pid, level);

	for (unsigned int i = 0; i < MAX_NS_LEVEL && i <= level; i++) {
		struct upid upid;
		if (bpf_core_read(&upid, sizeof(upid), &pid->numbers[i]))
			return 0;
		if (BPF_CORE_READ(upid.ns, ns.inum) == pidns_ino)
			return upid.nr;
	}
	return 0;
}

static struct event *new_event(int type)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	int pid = ns_tgid(task);
	if (!pid)
		return NULL;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return NULL;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = type;
	e->ts = bpf_ktime_get_ns();
	e->pid = pid;
	e->ppid = ns_tgid(BPF_CORE_READ(task, real_parent));
	e->uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

static void copy_exec_path(struct event *e, unsigned long long key)
{
	struct path_buf *p = bpf_map_lookup_elem(&exec_paths, &key);
	if (p && p->path[0])
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), p->path);
}

SEC("fentry/alloc_bprm")
int on_alloc_bprm(void *ctx)
{
	unsigned long long key = task_key();
	bpf_map_delete_elem(&exec_paths, &key);
	return 0;
}

SEC("fentry/begin_new_exec")
int on_begin_exec(void *ctx)
{
	unsigned long long key = task_key();
	char one = 1;
	bpf_map_update_elem(&in_exec, &key, &one, BPF_ANY);
	return 0;
}

SEC("fexit/begin_new_exec")
int on_begin_exec_done(void *ctx)
{
	unsigned long long key = task_key();
	bpf_map_delete_elem(&in_exec, &key);
	return 0;
}

SEC("fentry/security_file_open")
int BPF_PROG(on_file_open, struct file *file)
{
	if (!(file->f_flags & OPEN_FOR_EXEC))
		return 0;

	int zero = 0;
	struct path_buf *buf = bpf_map_lookup_elem(&scratch, &zero);
	if (!buf)
		return 0;

	if (bpf_d_path((struct path *)&file->f_path, buf->path, sizeof(buf->path)) < 0)
		buf->path[0] = '\0';

	unsigned long long key = task_key();
	bpf_map_update_elem(&exec_paths, &key, buf, BPF_NOEXIST);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int on_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	unsigned long long key = task_key();
	struct event *e = new_event(EV_EXEC);

	if (e) {
		copy_exec_path(e, key);
		if (!e->path[0]) {
			unsigned int off = ctx->__data_loc_filename & 0xFFFF;
			bpf_probe_read_kernel_str(e->path, sizeof(e->path), (void *)ctx + off);
		}
		bpf_ringbuf_submit(e, 0);
	}

	bpf_map_delete_elem(&exec_paths, &key);
	return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))
		return 0;

	int pid = ns_tgid(child);
	if (!pid)
		return 0;

	struct event *e = new_event(EV_FORK);
	if (!e)
		return 0;

	e->pid = pid;
	e->ppid = ns_tgid(BPF_CORE_READ(child, real_parent));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int on_exit(void *ctx)
{
	unsigned long long key = task_key();
	bpf_map_delete_elem(&exec_paths, &key);
	bpf_map_delete_elem(&in_exec, &key);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (BPF_CORE_READ(task, signal, live.counter) != 0)
		return 0;

	struct event *e = new_event(EV_EXIT);
	if (e)
		bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/tcp_v4_connect")
int BPF_PROG(on_tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	if (BPF_CORE_READ(sin, sin_family) != AF_INET)
		return 0;

	struct event *e = new_event(EV_CONNECT);
	if (!e)
		return 0;

	unsigned int addr = BPF_CORE_READ(sin, sin_addr.s_addr);
	__builtin_memcpy(e->addr, &addr, sizeof(addr));
	e->family = AF_INET;
	e->port = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/tcp_v6_connect")
int BPF_PROG(on_tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;
	if (BPF_CORE_READ(sin6, sin6_family) != AF_INET6)
		return 0;

	unsigned char addr[16];
	BPF_CORE_READ_INTO(&addr, sin6, sin6_addr.in6_u.u6_addr8);

	int mapped = addr[10] == 0xff && addr[11] == 0xff;
	for (int i = 0; i < 10; i++)
		if (addr[i])
			mapped = 0;
	if (mapped)
		return 0;

	struct event *e = new_event(EV_CONNECT);
	if (!e)
		return 0;

	__builtin_memcpy(e->addr, addr, sizeof(addr));
	e->family = AF_INET6;
	e->port = bpf_ntohs(BPF_CORE_READ(sin6, sin6_port));
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fexit/may_open")
int BPF_PROG(on_may_open, struct mnt_idmap *idmap, const struct path *path, int acc_mode, int flag, int ret)
{
	struct inode *inode = BPF_CORE_READ(path, dentry, d_inode);
	struct file_id id = {};
	id.ino = BPF_CORE_READ(inode, i_ino);
	id.dev = BPF_CORE_READ(inode, i_sb, s_dev);

	struct path_buf *watched = bpf_map_lookup_elem(&watched_files, &id);
	if (!watched)
		return 0;

	struct event *e = new_event(EV_OPEN);
	if (!e)
		return 0;

	bpf_probe_read_kernel_str(e->path, sizeof(e->path), watched->path);
	e->target = acc_mode;
	e->ret = ret;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	unsigned int old_uid = BPF_CORE_READ(task, cred, uid.val);
	unsigned int old_euid = BPF_CORE_READ(task, cred, euid.val);
	unsigned int new_euid = BPF_CORE_READ(new, euid.val);
	if (old_uid == 0 || old_euid == 0 || new_euid != 0)
		return 0;

	struct event *e = new_event(EV_SETUID);
	if (!e)
		return 0;

	unsigned long long key = task_key();
	if (bpf_map_lookup_elem(&in_exec, &key))
		copy_exec_path(e, key);
	e->target = new_euid;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/ptrace_attach")
int BPF_PROG(on_ptrace_attach, struct task_struct *task, long request, unsigned long addr, unsigned long flags)
{
	struct event *e = new_event(EV_PTRACE);
	if (!e)
		return 0;

	e->target = ns_tgid(task);
	e->ret = request;
	bpf_ringbuf_submit(e, 0);
	return 0;
}
