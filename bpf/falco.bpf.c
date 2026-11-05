// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * eBPF-частина Falco-lite. Власник модуля: Микита.
 *
 * Кожен хук кладе в ring buffer одну struct fl_event (include/events.h).
 * Готово: exec, fork, exit (останні два потрібні дереву процесів).
 * TODO: connect, openat, setuid, ptrace — див. блоки нижче.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* Заповнюється завантажувачем до load(): події самого агента не надсилаємо. */
const volatile __u32 self_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20); /* 1 МБ */
} events SEC(".maps");

/* Скільки подій не вмістилося в ring buffer (per-CPU, тому без атомарних операцій). */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 key = 0;
	__u64 *v = bpf_map_lookup_elem(&drops, &key);

	if (v)
		*v += 1;
}

/*
 * Зарезервувати місце в ring buffer і заповнити спільну шапку події
 * даними поточного процесу. Структура живе прямо в ring buffer, а не на
 * стеку: у BPF-програми стек лише 512 байтів.
 */
static __always_inline struct fl_event *ev_reserve(__u32 type)
{
	struct task_struct *task;
	struct fl_event *e;
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;

	if (tgid == self_tgid)
		return NULL;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return NULL;
	}

	task = (struct task_struct *)bpf_get_current_task();
	e->ts_ns = bpf_ktime_get_ns();
	e->start_ns = BPF_CORE_READ(task, group_leader, start_boottime);
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->type = type;
	e->pid = tgid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->uid = (__u32)bpf_get_current_uid_gid();
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	return e;
}

/* ---------- execve ---------- */

/*
 * sched_process_exec спрацьовує після успішного exec: comm уже новий,
 * а невдалі execve сюди не потрапляють.
 */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct fl_event *e = ev_reserve(EV_EXEC);
	unsigned int off;

	if (!e)
		return 0;

	/* filename — __data_loc-рядок: молодші 16 біт — зсув від початку запису. */
	off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_kernel_str(e->exec.filename, sizeof(e->exec.filename),
				  (void *)ctx + off);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------- fork / exit: для дерева процесів ---------- */

SEC("tp_btf/sched_process_fork")
int BPF_PROG(handle_fork, struct task_struct *parent, struct task_struct *child)
{
	struct fl_event *e;

	/* Новий потік, а не процес — дереву він не потрібен. */
	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))
		return 0;

	e = ev_reserve(EV_FORK);
	if (!e)
		return 0;

	/* Шапку заповнено даними батька (current) — переписуємо на дитину. */
	e->pid = BPF_CORE_READ(child, tgid);
	e->ppid = BPF_CORE_READ(child, real_parent, tgid);
	e->start_ns = BPF_CORE_READ(child, start_boottime);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
	__u64 id = bpf_get_current_pid_tgid();
	struct task_struct *task;
	struct fl_event *e;

	/* Завершився потік, а не процес — пропускаємо. */
	if ((__u32)(id >> 32) != (__u32)id)
		return 0;

	e = ev_reserve(EV_EXIT);
	if (!e)
		return 0;

	task = (struct task_struct *)bpf_get_current_task();
	e->exit.exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---------- TODO(Микита): connect ----------
 *
 * SEC("kprobe/tcp_v4_connect")
 * int BPF_KPROBE(handle_connect, struct sock *sk, struct sockaddr *uaddr)
 *   - uaddr на цей момент уже скопійовано в пам'ять ядра:
 *       struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
 *       e->connect.daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
 *       e->connect.dport = bpf_ntohs(BPF_CORE_READ(sin, sin_port));
 *     (bpf_ntohs — з <bpf/bpf_endian.h>)
 *   - e->connect.family = 2 (AF_INET; у vmlinux.h макросів немає)
 *   - згодом: tcp_v6_connect для IPv6
 */

/* ---------- TODO(Микита): openat ----------
 *
 * SEC("tp/syscalls/sys_enter_openat")
 * int handle_openat(struct trace_event_raw_sys_enter *ctx)
 *   - шлях: bpf_probe_read_user_str(..., (const char *)ctx->args[1]); flags = ctx->args[2]
 *   - sys_enter бачить і невдалі спроби (як вимагає ТЗ).
 *   - ФІЛЬТР У ЯДРІ: openat — найчастіший syscall, надсилати все не можна.
 *     Прочитати шлях у тимчасовий буфер (per-CPU array map: 256 байтів на
 *     стеку — забагато), порівняти зі шляхами/префіксами з map, яку
 *     завантажувач заповнює з правил із file.path / file.path.prefix, і лише
 *     при збігу робити ev_reserve() + копію + submit.
 *   - те саме для openat2 (sys_enter_openat2) — за бажанням.
 */

/* ---------- TODO(Микита): setuid ----------
 *
 * SEC("tp/syscalls/sys_enter_setuid")
 * int handle_setuid(struct trace_event_raw_sys_enter *ctx)
 *   - e->setuid.target_uid = (__u32)ctx->args[0];
 *   - за бажанням: sys_enter_setreuid / sys_enter_setresuid (той самий EV_SETUID)
 */

/* ---------- TODO(Микита): ptrace ----------
 *
 * SEC("tp/syscalls/sys_enter_ptrace")
 * int handle_ptrace(struct trace_event_raw_sys_enter *ctx)
 *   - e->ptrace.request = ctx->args[0]; e->ptrace.target_pid = ctx->args[1];
 *   - можна відкидати в ядрі все, крім ATTACH(16)/SEIZE(0x4206)/POKE*(4,5)
 */
