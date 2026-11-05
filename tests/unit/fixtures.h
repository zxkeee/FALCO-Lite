/* Конструктори синтетичних подій для тестів рушія, дерева та виводу. */
#ifndef FL_FIXTURES_H
#define FL_FIXTURES_H

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include "events.h"

static inline struct fl_event ev_base(__u32 type, __u32 pid, __u32 ppid, const char *comm)
{
	struct fl_event e;

	memset(&e, 0, sizeof(e));
	e.type = type;
	e.pid = pid;
	e.ppid = ppid;
	e.uid = 33; /* www-data */
	e.ts_ns = 1000000000ULL;
	e.start_ns = (__u64)pid * 1000ULL;
	snprintf(e.comm, sizeof(e.comm), "%s", comm);
	return e;
}

static inline struct fl_event ev_fork(__u32 pid, __u32 ppid, const char *comm)
{
	return ev_base(EV_FORK, pid, ppid, comm);
}

static inline struct fl_event ev_exec(__u32 pid, __u32 ppid, const char *comm, const char *filename)
{
	struct fl_event e = ev_base(EV_EXEC, pid, ppid, comm);

	snprintf(e.exec.filename, sizeof(e.exec.filename), "%s", filename);
	return e;
}

static inline struct fl_event ev_connect(__u32 pid, __u32 ppid, const char *comm,
					 const char *ip, __u16 port)
{
	struct fl_event e = ev_base(EV_CONNECT, pid, ppid, comm);

	inet_pton(AF_INET, ip, &e.connect.daddr);
	e.connect.dport = port;
	e.connect.family = AF_INET;
	return e;
}

static inline struct fl_event ev_open(__u32 pid, __u32 ppid, const char *comm, const char *path)
{
	struct fl_event e = ev_base(EV_OPEN, pid, ppid, comm);

	snprintf(e.open.path, sizeof(e.open.path), "%s", path);
	return e;
}

static inline struct fl_event ev_exit(__u32 pid, __u32 ppid, const char *comm)
{
	return ev_base(EV_EXIT, pid, ppid, comm);
}

#endif /* FL_FIXTURES_H */
