#include <arpa/inet.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include "output.h"

struct sbuf {
	char *p;
	size_t len;
	size_t off;
};

static void put(struct sbuf *b, const char *fmt, ...)
{
	if (b->off + 1 >= b->len)
		return;
	va_list ap;
	va_start(ap, fmt);
	int n = vsnprintf(b->p + b->off, b->len - b->off, fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	b->off += (size_t)n < b->len - b->off ? (size_t)n : b->len - b->off - 1;
}

static int utf8_len(const unsigned char *s)
{
	unsigned char lo = 0x80, hi = 0xbf;
	int n;

	if (s[0] >= 0xc2 && s[0] <= 0xdf) {
		n = 2;
	} else if (s[0] >= 0xe0 && s[0] <= 0xef) {
		n = 3;
		lo = s[0] == 0xe0 ? 0xa0 : lo;
		hi = s[0] == 0xed ? 0x9f : hi;
	} else if (s[0] >= 0xf0 && s[0] <= 0xf4) {
		n = 4;
		lo = s[0] == 0xf0 ? 0x90 : lo;
		hi = s[0] == 0xf4 ? 0x8f : hi;
	} else {
		return 0;
	}

	if (s[1] < lo || s[1] > hi)
		return 0;
	for (int i = 2; i < n; i++)
		if (s[i] < 0x80 || s[i] > 0xbf)
			return 0;
	return n;
}

void sanitize_text(char *s)
{
	unsigned char *p = (unsigned char *)s;
	while (*p) {
		int n = *p < 0x80 ? 1 : utf8_len(p);
		if (n == 0 || *p < 0x20 || *p == 0x7f) {
			*p++ = '?';
			continue;
		}
		p += n;
	}
}

static void json_escape(char *dst, size_t len, const char *src)
{
	struct sbuf b = { dst, len, 0 };
	dst[0] = '\0';
	for (const unsigned char *s = (const unsigned char *)src; *s; s++) {
		if (*s == '"' || *s == '\\')
			put(&b, "\\%c", *s);
		else if (*s < 0x20 || *s == 0x7f)
			put(&b, "\\u%04x", *s);
		else
			put(&b, "%c", *s);
	}
}

static void format_time(const struct timespec *ts, char *buf, size_t len, int iso)
{
	struct tm tm;
	if (iso) {
		gmtime_r(&ts->tv_sec, &tm);
		size_t n = strftime(buf, len, "%Y-%m-%dT%H:%M:%S", &tm);
		snprintf(buf + n, len - n, ".%03ldZ", ts->tv_nsec / 1000000);
	} else {
		localtime_r(&ts->tv_sec, &tm);
		strftime(buf, len, "%H:%M:%S", &tm);
	}
}

void format_addr(const struct event *e, char *buf, size_t len)
{
	buf[0] = '\0';
	if (e->family == 2)
		inet_ntop(AF_INET, e->addr, buf, len);
	else if (e->family == 10)
		inet_ntop(AF_INET6, e->addr, buf, len);
}

void format_detail(const struct event *e, char *buf, size_t len)
{
	char addr[64];
	switch (e->type) {
	case EV_CONNECT:
		format_addr(e, addr, sizeof(addr));
		snprintf(buf, len, e->family == 10 ? "connect [%s]:%u" : "connect %s:%u", addr, e->port);
		break;
	case EV_OPEN:
		snprintf(buf, len, "open %s%s", e->path, e->ret < 0 ? " (denied)" : "");
		break;
	case EV_PTRACE:
		snprintf(buf, len, "ptrace pid %d", e->target);
		break;
	case EV_SETUID:
		snprintf(buf, len, "became root %s", e->path);
		break;
	default:
		snprintf(buf, len, "exec %s", e->path);
	}
}

void format_alert_json(char *buf, size_t len, const struct alert *a)
{
	const struct event *e = a->event;
	char time[40], name[NAME_LEN * 6], comm[COMM_LEN * 6], path[PATH_LEN * 6], chain[CHAIN_LEN * 6], addr[64];
	format_time(&a->ts, time, sizeof(time), 1);
	json_escape(name, sizeof(name), a->rule->name);
	json_escape(comm, sizeof(comm), e->comm);
	json_escape(path, sizeof(path), e->path);
	json_escape(chain, sizeof(chain), a->chain ? a->chain : "");
	format_addr(e, addr, sizeof(addr));

	struct sbuf b = { buf, len, 0 };
	buf[0] = '\0';
	put(&b, "{\"time\":\"%s\",\"rule\":\"%s\",\"action\":\"%s\",\"result\":\"%s\",\"event\":\"%s\",",
	    time, name, action_name(a->rule->action), a->result, event_name(e->type));
	put(&b, "\"pid\":%d,\"ppid\":%d,\"uid\":%u,\"comm\":\"%s\",\"path\":\"%s\",",
	    e->pid, e->ppid, e->uid, comm, path);
	put(&b, "\"addr\":\"%s\",\"port\":%u,\"target\":%d,\"ret\":%d,", addr, e->port, e->target, e->ret);
	put(&b, "\"chain\":\"%s\",\"reaction_us\":%ld}", chain, a->reaction_us);
}

void format_alert_text(char *buf, size_t len, const struct alert *a)
{
	const struct event *e = a->event;
	char time[16], detail[PATH_LEN + 64];
	format_time(&a->ts, time, sizeof(time), 0);
	format_detail(e, detail, sizeof(detail));
	snprintf(buf, len, "%s %-5s %-14s %-14s pid=%d uid=%u comm=%s %s",
		 time, action_name(a->rule->action), a->rule->name, a->result, e->pid, e->uid, e->comm, detail);
}

void format_alert_extra(char *buf, size_t len, const struct alert *a)
{
	struct sbuf b = { buf, len, 0 };
	buf[0] = '\0';
	put(&b, "         process tree: %s", a->chain && a->chain[0] ? a->chain : "?");
	if (a->reaction_us >= 0)
		put(&b, "   ·   SIGKILL %ld.%02ld ms after the kernel event",
		    a->reaction_us / 1000, (a->reaction_us % 1000) / 10);
}

int output_open(struct output *o, const char *json_path, int use_syslog)
{
	memset(o, 0, sizeof(*o));
	if (json_path) {
		o->json = fopen(json_path, "a");
		if (!o->json)
			return -1;
		setvbuf(o->json, NULL, _IOLBF, 0);
	}
	o->use_syslog = use_syslog;
	if (use_syslog)
		openlog("falco-lite", LOG_PID, LOG_AUTHPRIV);
	return 0;
}

void output_close(struct output *o)
{
	if (o->json)
		fclose(o->json);
	if (o->use_syslog)
		closelog();
	o->json = NULL;
}

void output_alert(struct output *o, const char *json)
{
	if (o->json)
		fprintf(o->json, "%s\n", json);
	if (o->use_syslog)
		syslog(LOG_WARNING, "%s", json);
}
