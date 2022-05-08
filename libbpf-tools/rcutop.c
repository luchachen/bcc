/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */

/*
 * rcutop
 * Copyright (c) 2022 Joel Fernandes
 *
 * 05-May-2022   Joel Fernandes   Created this.
 */
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "rcutop.h"
#include "rcutop.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define warn(...) fprintf(stderr, __VA_ARGS__)
#define OUTPUT_ROWS_LIMIT 10240

static volatile sig_atomic_t exiting = 0;

static bool clear_screen = true;
static int output_rows = 20;
static int interval = 1;
static int count = 99999999;
static bool verbose = false;

const char *argp_program_version = "rcutop 0.1";
const char *argp_program_bug_address =
"https://github.com/iovisor/bcc/tree/master/libbpf-tools";
const char argp_program_doc[] =
"Show RCU callback queuing and execution stats.\n"
"\n"
"USAGE: rcutop [-h] [interval] [count]\n"
"\n"
"EXAMPLES:\n"
"    rcutop            # rcu activity top, refresh every 1s\n"
"    rcutop 5 10       # 5s summaries, 10 times\n";

static const struct argp_option opts[] = {
	{ "noclear", 'C', NULL, 0, "Don't clear the screen" },
	{ "rows", 'r', "ROWS", 0, "Maximum rows to print, default 20" },
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	long rows;
	static int pos_args;

	switch (key) {
		case 'C':
			clear_screen = false;
			break;
		case 'v':
			verbose = true;
			break;
		case 'h':
			argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
			break;
		case 'r':
			errno = 0;
			rows = strtol(arg, NULL, 10);
			if (errno || rows <= 0) {
				warn("invalid rows: %s\n", arg);
				argp_usage(state);
			}
			output_rows = rows;
			if (output_rows > OUTPUT_ROWS_LIMIT)
				output_rows = OUTPUT_ROWS_LIMIT;
			break;
		case ARGP_KEY_ARG:
			errno = 0;
			if (pos_args == 0) {
				interval = strtol(arg, NULL, 10);
				if (errno || interval <= 0) {
					warn("invalid interval\n");
					argp_usage(state);
				}
			} else if (pos_args == 1) {
				count = strtol(arg, NULL, 10);
				if (errno || count <= 0) {
					warn("invalid count\n");
					argp_usage(state);
				}
			} else {
				warn("unrecognized positional argument: %s\n", arg);
				argp_usage(state);
			}
			pos_args++;
			break;
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_int(int signo)
{
	exiting = 1;
}

static int print_stat(struct ksyms *ksyms, struct syms_cache *syms_cache,
		struct rcutop_bpf *obj)
{
	void *key, **prev_key = NULL;
	int n, err = 0;
	int qfd = bpf_map__fd(obj->maps.cbs_queued);
	int efd = bpf_map__fd(obj->maps.cbs_executed);
	const struct ksym *ksym;
	FILE *f;
	time_t t;
	struct tm *tm;
	char ts[16], buf[256];

	f = fopen("/proc/loadavg", "r");
	if (f) {
		time(&t);
		tm = localtime(&t);
		strftime(ts, sizeof(ts), "%H:%M:%S", tm);
		memset(buf, 0, sizeof(buf));
		n = fread(buf, 1, sizeof(buf), f);
		if (n)
			printf("%8s loadavg: %s\n", ts, buf);
		fclose(f);
	}

	printf("%-32s %-6s %-6s\n", "Callback", "Queued", "Executed");

	while (1) {
		int qcount = 0, ecount = 0;

		err = bpf_map_get_next_key(qfd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}

		err = bpf_map_lookup_elem(qfd, &key, &qcount);
		if (err) {
			warn("bpf_map_lookup_elem failed: %s\n", strerror(errno));
			return err;
		}
		prev_key = &key;

		bpf_map_lookup_elem(efd, &key, &ecount);

		ksym = ksyms__map_addr(ksyms, (unsigned long)key);
		printf("%-32s %-6d %-6d\n",
				ksym ? ksym->name : "Unknown",
				qcount, ecount);
	}
	printf("\n");
	prev_key = NULL;
	while (1) {
		err = bpf_map_get_next_key(qfd, prev_key, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				break;
			}
			warn("bpf_map_get_next_key failed: %s\n", strerror(errno));
			return err;
		}
		err = bpf_map_delete_elem(qfd, &key);
		if (err) {
			if (errno == ENOENT) {
				err = 0;
				continue;
			}
			warn("bpf_map_delete_elem failed: %s\n", strerror(errno));
			return err;
		}

		bpf_map_delete_elem(efd, &key);
		prev_key = &key;
	}

	return err;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct rcutop_bpf *obj;
	int err;
	struct syms_cache *syms_cache = NULL;
	struct ksyms *ksyms = NULL;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);

	err = ensure_core_btf(&open_opts);
	if (err) {
		fprintf(stderr, "failed to fetch necessary BTF for CO-RE: %s\n", strerror(-err));
		return 1;
	}

	obj = rcutop_bpf__open_opts(&open_opts);
	if (!obj) {
		warn("failed to open BPF object\n");
		return 1;
	}

	err = rcutop_bpf__load(obj);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = rcutop_bpf__attach(obj);
	if (err) {
		warn("failed to attach BPF programs: %d\n", err);
		goto cleanup;
	}

	ksyms = ksyms__load();
	if (!ksyms) {
		fprintf(stderr, "failed to load kallsyms\n");
		goto cleanup;
	}

	syms_cache = syms_cache__new(0);
	if (!syms_cache) {
		fprintf(stderr, "failed to create syms_cache\n");
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}

	while (1) {
		sleep(interval);

		if (clear_screen) {
			err = system("clear");
			if (err)
				goto cleanup;
		}

		err = print_stat(ksyms, syms_cache, obj);
		if (err)
			goto cleanup;

		count--;
		if (exiting || !count)
			goto cleanup;
	}

cleanup:
	rcutop_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);

	return err != 0;
}
