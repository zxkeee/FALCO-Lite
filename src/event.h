#ifndef FALCO_EVENT_H
#define FALCO_EVENT_H

#define COMM_LEN 16
#define PATH_LEN 256

enum event_type {
	EV_EXEC = 1,
	EV_FORK,
	EV_EXIT,
	EV_CONNECT,
	EV_OPEN,
	EV_SETUID,
	EV_PTRACE,
	EV_TYPE_COUNT,
};

struct event {
	int type;
	int pid;
	int ppid;
	unsigned int uid;
	char comm[COMM_LEN];
	char path[PATH_LEN];
	unsigned char addr[16];
	unsigned short family;
	unsigned short port;
	int target;
	int ret;
	unsigned long long ts;
};

struct file_id {
	unsigned long long ino;
	unsigned int dev;
	unsigned int pad;
};

struct path_buf {
	char path[PATH_LEN];
};

#endif
