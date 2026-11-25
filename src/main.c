#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "engine.h"
#include "event.h"
#include "loader.h"
#include "output.h"
#include "response.h"
#include "tui.h"

#define MAX_MATCHES 8
#define WATCH_REFRESH_SEC 5

struct options {
	const char *config;
	const char *json;
	int use_syslog;
	int use_tui;
	int dry_run;
	int verbose;
};

struct app {
	struct options opt;
	struct ruleset *rules;
	struct proctree *tree;
	struct output out;
	struct stats stats;
	int self;
};

static volatile sig_atomic_t running = 1;
static struct app app;

static void on_signal(int sig)
{
	(void)sig;
	running = 0;
}

static int setup_signals(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL) || sigaction(SIGHUP, &sa, NULL))
		return -1;
	signal(SIGPIPE, SIG_IGN);
	return 0;
}

static void usage(const char *prog)
{
	printf("usage: %s [options]\n"
	       "  -c, --config FILE  rules file (default rules.yaml)\n"
	       "  -j, --json FILE    append alerts as JSON lines\n"
	       "  -s, --syslog       send alerts to syslog\n"
	       "  -t, --tui          ncurses dashboard\n"
	       "  -n, --dry-run      never kill, log would_kill instead\n"
	       "  -v, --verbose      print every event\n"
	       "  -h, --help         show this help\n", prog);
}

static int parse_options(int argc, char **argv, struct options *o)
{
	static const struct option longopts[] = {
		{ "config", required_argument, NULL, 'c' },
		{ "json", required_argument, NULL, 'j' },
		{ "syslog", no_argument, NULL, 's' },
		{ "tui", no_argument, NULL, 't' },
		{ "dry-run", no_argument, NULL, 'n' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};

	o->config = "rules.yaml";
	int c;
	while ((c = getopt_long(argc, argv, "c:j:stnvh", longopts, NULL)) != -1) {
		switch (c) {
		case 'c': o->config = optarg; break;
		case 'j': o->json = optarg; break;
		case 's': o->use_syslog = 1; break;
		case 't': o->use_tui = 1; break;
		case 'n': o->dry_run = 1; break;
		case 'v': o->verbose = 1; break;
		case 'h': usage(argv[0]); exit(0);
		default: usage(argv[0]); return -1;
		}
	}
	if (o->use_tui && o->verbose) {
		fprintf(stderr, "--tui and --verbose cannot be used together\n");
		return -1;
	}
	return 0;
}

static long since_event_us(const struct event *e)
{
	struct timespec now;
	clock_gettime(CLOCK_MONOTONIC, &now);
	long long ns = (long long)now.tv_sec * 1000000000LL + now.tv_nsec - (long long)e->ts;
	return ns > 0 ? (long)(ns / 1000) : 0;
}

static void report(struct alert *a, int killed)
{
	char json[LINE_LEN * 3];
	char text[LINE_LEN];
	char extra[LINE_LEN];

	clock_gettime(CLOCK_REALTIME, &a->ts);
	format_alert_json(json, sizeof(json), a);
	format_alert_text(text, sizeof(text), a);
	format_alert_extra(extra, sizeof(extra), a);
	output_alert(&app.out, json);

	if (app.opt.use_tui) {
		tui_add(text, killed);
		return;
	}

	if (isatty(STDOUT_FILENO)) {
		const char *color = a->rule->action == ACT_KILL ? "\033[1;31m" : "\033[1;33m";
		printf("%s%s\033[0m\n\033[2m%s\033[0m\n", color, text, extra);
	} else {
		printf("%s\n%s\n", text, extra);
	}
	fflush(stdout);
}

static int handle_event(void *ctx, void *data, size_t size)
{
	(void)ctx;
	if (size < sizeof(struct event))
		return 0;

	struct event e;
	memcpy(&e, data, sizeof(e));
	e.comm[COMM_LEN - 1] = '\0';
	e.path[PATH_LEN - 1] = '\0';
	sanitize_text(e.comm);
	sanitize_text(e.path);

	if (e.type > 0 && e.type < EV_TYPE_COUNT)
		app.stats.events[e.type]++;

	if (app.opt.verbose) {
		char detail[PATH_LEN + 64];
		format_detail(&e, detail, sizeof(detail));
		printf("%-7s pid=%d ppid=%d uid=%u comm=%s %s\n", event_name(e.type), e.pid, e.ppid,
		       e.uid, e.comm, e.type == EV_FORK || e.type == EV_EXIT ? "" : detail);
	}

	const struct rule *matches[MAX_MATCHES];
	int n = engine_process(app.rules, app.tree, &e, matches, MAX_MATCHES);

	struct proc *p = proctree_get(app.tree, e.pid);
	if (n && !e.path[0] && p) {
		snprintf(e.path, sizeof(e.path), "%s", p->exe);
		sanitize_text(e.path);
	}

	char chain[CHAIN_LEN];
	if (n)
		proctree_chain(app.tree, e.pid, e.comm, chain, sizeof(chain));
	if (n)
		sanitize_text(chain);

	for (int i = 0; i < n; i++) {
		struct alert a = { matches[i], &e, "alerted", chain, -1, { 0, 0 } };
		int killed = 0;
		if (matches[i]->action == ACT_KILL) {
			int r = response_kill(app.tree, e.pid, app.self, app.opt.dry_run);
			if (r == KILL_DONE)
				a.reaction_us = since_event_us(&e);
			a.result = kill_result_name(r);
			killed = r == KILL_DONE;
			if (killed)
				app.stats.kills++;
		}
		app.stats.alerts++;
		report(&a, killed);
	}
	return 0;
}

static void print_banner(int nlinks)
{
	struct utsname uts;
	uname(&uts);
	printf("[+] eBPF: %d programs loaded (execve, fork, exit, connect, openat, setuid, ptrace)\n", nlinks);
	printf("[+] ring buffer attached, kernel %s, CO-RE\n", uts.release);
	printf("[+] rules: %d from %s\n", app.rules->count, app.opt.config);
	if (app.opt.dry_run)
		printf("[+] dry-run: no process will be killed\n");
	printf("[+] watching...\n");
	fflush(stdout);
}

static int run_loop(struct loader *l)
{
	struct ring_buffer *rb = ring_buffer__new(loader_events_fd(l), handle_event, NULL, NULL);
	if (!rb) {
		fprintf(stderr, "failed to create ring buffer\n");
		return 1;
	}

	if (app.opt.use_tui)
		tui_start();

	int status = 0;
	time_t last_refresh = time(NULL);
	while (running) {
		int err = ring_buffer__poll(rb, 200);
		if (err < 0 && err != -EINTR) {
			status = 1;
			break;
		}
		if (time(NULL) - last_refresh >= WATCH_REFRESH_SEC) {
			loader_watch_files(l, app.rules);
			last_refresh = time(NULL);
		}
		if (app.opt.use_tui && tui_draw(&app.stats, app.rules->count))
			running = 0;
	}

	if (app.opt.use_tui)
		tui_stop();
	if (status)
		fprintf(stderr, "ring buffer poll failed\n");

	ring_buffer__free(rb);
	return status;
}

static int start(void)
{
	struct loader l;
	if (loader_start(&l))
		return 1;

	int status = 1;
	if (setup_signals() == 0) {
		loader_watch_files(&l, app.rules);
		print_banner(l.nlinks);
		status = run_loop(&l);
	} else {
		fprintf(stderr, "failed to set up signal handlers\n");
	}

	loader_stop(&l);
	return status;
}

int main(int argc, char **argv)
{
	if (parse_options(argc, argv, &app.opt))
		return 2;

	app.rules = calloc(1, sizeof(*app.rules));
	app.tree = proctree_new();
	if (!app.rules || !app.tree) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	char err[256];
	if (rules_load(app.opt.config, app.rules, err, sizeof(err))) {
		fprintf(stderr, "rules: %s\n", err);
		return 1;
	}

	if (geteuid() != 0) {
		fprintf(stderr, "falco-lite must run as root\n");
		return 1;
	}

	if (output_open(&app.out, app.opt.json, app.opt.use_syslog)) {
		fprintf(stderr, "cannot open %s: %s\n", app.opt.json, strerror(errno));
		return 1;
	}

	app.self = getpid();
	proctree_seed(app.tree, "/proc");

	int status = start();

	output_close(&app.out);
	proctree_free(app.tree);
	free(app.rules);
	return status;
}
