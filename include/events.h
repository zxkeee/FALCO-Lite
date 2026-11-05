/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/*
 * Контракт ядро <-> userspace.
 *
 * Цю структуру BPF-програма пише в ring buffer, а демон читає як є
 * (так само вона лежить у файлах --record). Будь-яка зміна — лише за
 * домовленістю всієї команди: після неї старі .flrec-записи не читаються.
 */
#ifndef FALCO_EVENTS_H
#define FALCO_EVENTS_H

#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif

#define FL_COMM_LEN 16
#define FL_PATH_LEN 256

enum fl_event_type {
	EV_EXEC = 1,	/* tp/sched/sched_process_exec           */
	EV_CONNECT,	/* kprobe/tcp_v4_connect                 */
	EV_OPEN,	/* tp/syscalls/sys_enter_openat          */
	EV_SETUID,	/* tp/syscalls/sys_enter_setuid          */
	EV_PTRACE,	/* tp/syscalls/sys_enter_ptrace          */
	EV_FORK,	/* tp_btf/sched_process_fork (службове)  */
	EV_EXIT,	/* tp/sched/sched_process_exit (службове) */
	EV__MAX,
};

struct fl_event {
	__u64 ts_ns;		/* bpf_ktime_get_ns() == CLOCK_MONOTONIC у userspace */
	__u64 start_ns;		/* group_leader->start_boottime: відрізняє процес від
				 * нового процесу з тим самим повторно використаним pid */
	__u64 cgroup_id;	/* bpf_get_current_cgroup_id(): для контейнерів */
	__u32 type;		/* enum fl_event_type */
	__u32 pid;		/* tgid процесу (не id потоку) */
	__u32 ppid;		/* tgid батька (real_parent) */
	__u32 uid;		/* реальний uid */
	char comm[FL_COMM_LEN];
	union {
		struct {
			char filename[FL_PATH_LEN];	/* як передано в execve, може бути відносним */
		} exec;
		struct {
			__u32 daddr;	/* IPv4, мережевий порядок байтів */
			__u16 dport;	/* порядок хоста (уже bpf_ntohs) */
			__u16 family;	/* AF_INET */
		} connect;
		struct {
			char path[FL_PATH_LEN];	/* як передано в openat, може бути відносним */
			__s32 flags;
		} open;
		struct {
			__u32 target_uid;
		} setuid;
		struct {
			__s64 request;	/* PTRACE_ATTACH, PTRACE_SEIZE, ... */
			__u32 target_pid;
		} ptrace;
		/* EV_FORK без даних: pid/start_ns — нового процесу, ppid — батька */
		struct {
			__s32 exit_code;
		} exit;
	};
};

#endif /* FALCO_EVENTS_H */
