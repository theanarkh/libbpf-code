// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uv_uprobe.skel.h"
#include "uprobe_helper.h"
#include <signal.h>
#include <bpf/bpf.h>
#include "uv_uprobe.h"

#define PERF_BUFFER_PAGES       16
#define PERF_POLL_TIMEOUT_MS    100

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

static int exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct event *e = (const struct event *)data;
	printf("%s %llu\n", e->name, (e->end_time - e->start_time) / 1000 / 1000);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	// 
}

int main(int argc, char **argv)
{
	struct uv_uprobe_bpf *skel;
	long base_addr, uprobe_offset;
	int err, i;
	struct perf_buffer_opts pb_opts;
	struct perf_buffer *pb = NULL;
	char * pid_str = argv[1];
	if (!pid_str) {
		fprintf(stderr, "please input pid");
		return;
	}
	pid_t pid = (pid_t)atoi(pid_str);
	char execpath[500];
	int ret = get_pid_binary_path(pid, execpath, 500);
	if (ret == -1) {
		fprintf(stderr, "invalid pid: %ld\n", pid);
		return;
	}

	fprintf(stderr, "uprobe_execpath: %s\n", execpath);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Load and verify BPF application */
	skel = uv_uprobe_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	err = uv_uprobe_bpf__load(skel);
	if (err) {
		warn("failed to load BPF object: %d\n", err);
		goto cleanup;
	}
	/* Attach tracepoint handler */

	// get function str by readelf -s | grep your functionname
	

	#define ATTACH_UPROBE(type)  \
		do \
		{	char * func_##type = #type; \
			uprobe_offset = get_elf_func_offset(execpath, func_##type); \
			if (uprobe_offset == -1) { \
				fprintf(stderr, "invalid function &s: %s\n", func_##type); \
				break; \
			} \
			fprintf(stderr, "uprobe_offset: %ld\n", uprobe_offset);\
			skel->links.uprobe_##type = bpf_program__attach_uprobe(skel->progs.uprobe_##type,\
									false /* not uretprobe */,\
									pid,\
									execpath,\
									uprobe_offset);\
			err = libbpf_get_error(skel->links.uprobe_##type);\
			if (err) {\
				fprintf(stderr, "Failed to attach uprobe: %d\n", err);\
				goto cleanup;\
			}\
			skel->links.uretprobe_##type = bpf_program__attach_uprobe(skel->progs.uretprobe_##type,\
									true /* uretprobe */,\
									pid /* any pid */,\
									execpath,\
									uprobe_offset);\
			err = libbpf_get_error(skel->links.uretprobe_##type);\
			if (err) {\
				fprintf(stderr, "Failed to attach uprobe: %d\n", err);\
				goto cleanup;\
			}\
		} while(false); 

	PHASE(ATTACH_UPROBE)

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		printf("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
	pb = perf_buffer__new(bpf_map__fd(skel->maps.events), PERF_BUFFER_PAGES,
			      &pb_opts);
	printf("%-7s %-7s\n", "phase", "interval");			  
	for (i = 0; ; i++) {
		if (exiting) {
			break;
		}
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && errno != EINTR) {
			printf("error polling perf buffer: %s\n", strerror(errno));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	uv_uprobe_bpf__destroy(skel);
	return -err;
}
