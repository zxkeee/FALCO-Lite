// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Falco-lite: агент runtime-захисту Linux на eBPF.
 *
 *   sudo ./falco-lite -c rules/rules.yaml
 *   sudo ./falco-lite -c rules/rules.yaml --record demo.flrec
 *        ./falco-lite -c rules/rules.yaml --replay demo.flrec
 */
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include "falco.h"
#include "loader.h"
#include "output.h"
#include "record.h"

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
	(void)sig;
	g_stop = 1;
}

static void usage(FILE *f, const char *prog)
{
	fprintf(f,
		"Використання: %s -c rules.yaml [опції]\n"
		"\n"
		"  -c, --config FILE   правила (обов'язково)\n"
		"  -j, --json FILE     писати алерти в JSONL-файл\n"
		"  -s, --syslog        надсилати алерти в syslog\n"
		"  -t, --tui           інтерфейс на ncurses\n"
		"  -n, --dry-run       не вбивати процеси, лише алерти\n"
		"  -r, --record FILE   записувати всі події у файл\n"
		"  -R, --replay FILE   прогнати записані події без eBPF (завжди dry-run)\n"
		"  -v, --verbose       показувати fork/exit і налагодження libbpf\n"
		"  -h, --help          ця довідка\n",
		prog);
}

static int run_live(struct fl_ctx *c)
{
	struct fl_loader *l = NULL;
	struct utsname u;
	char names[256];
	int n, err;

	c->t0_ns = fl_now_ns();
	err = loader_open(&l, c->cfg.verbose, pipeline_handle, c);
	if (err)
		return 1;

	/* Після attach: процеси, що стартували між скануванням і attach, не загубляться. */
	if (proctree_scan_proc(c->tree) < 0)
		fprintf(stderr, "[!] не вдалося прочитати /proc, дерево процесів неповне\n");

	n = loader_prog_names(l, names, sizeof(names));
	if (uname(&u))
		strcpy(u.release, "?");
	printf("[+] eBPF: завантажено програм: %d (%s)\n", n, names);
	printf("[+] ring buffer підключено, ядро %s, CO-RE\n", u.release);
	printf("[+] правила: %d із %s\n", c->rules.nrules, c->cfg.rules_path);
	printf("[+] спостерігаю…%s\n", c->cfg.dry_run ? " (dry-run: процеси не вбиваються)" : "");

	while (!g_stop) {
		err = loader_poll(l, 100);
		if (err == -EINTR)
			break;
		if (err < 0) {
			fprintf(stderr, "[-] помилка читання ring buffer: %d\n", err);
			break;
		}
		output_tick(c);
	}

	c->stats.drops = loader_drops(l);
	loader_close(l);
	return err < 0 && err != -EINTR ? 1 : 0;
}

static int run_replay(struct fl_ctx *c)
{
	char err[256];
	long n;
	FILE *f;

	f = fopen(c->cfg.replay_path, "rb");
	if (!f) {
		fprintf(stderr, "[-] %s: %s\n", c->cfg.replay_path, strerror(errno));
		return 1;
	}
	n = record_replay(f, pipeline_handle, c, &g_stop, err, sizeof(err));
	fclose(f);
	if (n < 0) {
		fprintf(stderr, "[-] %s: %s\n", c->cfg.replay_path, err);
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "config", required_argument, NULL, 'c' },
		{ "json", required_argument, NULL, 'j' },
		{ "syslog", no_argument, NULL, 's' },
		{ "tui", no_argument, NULL, 't' },
		{ "dry-run", no_argument, NULL, 'n' },
		{ "record", required_argument, NULL, 'r' },
		{ "replay", required_argument, NULL, 'R' },
		{ "verbose", no_argument, NULL, 'v' },
		{ "help", no_argument, NULL, 'h' },
		{ NULL, 0, NULL, 0 },
	};
	struct sigaction sa;
	struct fl_ctx c;
	char err[256];
	int opt, rc = 1;

	memset(&c, 0, sizeof(c));
	setvbuf(stdout, NULL, _IOLBF, 0);

	while ((opt = getopt_long(argc, argv, "c:j:stnr:R:vh", opts, NULL)) != -1) {
		switch (opt) {
		case 'c': c.cfg.rules_path = optarg; break;
		case 'j': c.cfg.json_path = optarg; break;
		case 's': c.cfg.use_syslog = 1; break;
		case 't': c.cfg.use_tui = 1; break;
		case 'n': c.cfg.dry_run = 1; break;
		case 'r': c.cfg.record_path = optarg; break;
		case 'R': c.cfg.replay_path = optarg; break;
		case 'v': c.cfg.verbose = 1; break;
		case 'h': usage(stdout, argv[0]); return 0;
		default: usage(stderr, argv[0]); return 2;
		}
	}
	if (!c.cfg.rules_path) {
		usage(stderr, argv[0]);
		return 2;
	}
	/* pid'и із запису належать іншій машині або іншому часу — не вбивати. */
	if (c.cfg.replay_path)
		c.cfg.dry_run = 1;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = on_signal;	/* без SA_RESTART: poll перерветься з EINTR */
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	if (rules_load(c.cfg.rules_path, &c.rules, err, sizeof(err))) {
		fprintf(stderr, "[-] %s\n", err);
		return 1;
	}
	c.tree = proctree_new();
	if (!c.tree) {
		fprintf(stderr, "[-] немає пам'яті\n");
		goto out_rules;
	}

	if (c.cfg.record_path) {
		c.record = fopen(c.cfg.record_path, "wb");
		if (!c.record || record_write_header(c.record)) {
			fprintf(stderr, "[-] %s: %s\n", c.cfg.record_path, strerror(errno));
			goto out_tree;
		}
	}

	if (output_open(&c)) {
		output_close(&c);
		goto out_record;
	}

	rc = c.cfg.replay_path ? run_replay(&c) : run_live(&c);

	output_close(&c);
	output_summary(&c);
out_record:
	if (c.record)
		fclose(c.record);
out_tree:
	proctree_free(c.tree);
out_rules:
	rules_free(&c.rules);
	return rc;
}
