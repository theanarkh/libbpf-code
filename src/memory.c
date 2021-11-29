// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "memory.skel.h"
#include "uprobe_helper.h"
#include <signal.h>

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

int main(int argc, char **argv)
{
	struct memory_bpf *skel;
	long base_addr, malloc_offset, free_offset;
	int err, i;

	char execpath[500] = "/snap/node/5485/bin/node";
	malloc_offset = get_elf_func_offset(execpath, "malloc");
	free_offset = get_elf_func_offset(execpath, "free");
	if (malloc_offset == -1 || free_offset == -1) {
		fprintf(stderr, "invalid function &s: %s\n");
		return;
	}
	fprintf(stderr, "malloc_offset free_offset: %ld\n", malloc_offset, free_offset);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Load and verify BPF application */
	skel = memory_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Attach tracepoint handler */
	skel->links.uprobe_malloc = bpf_program__attach_uprobe(skel->progs.uprobe_malloc,
							false /* not uretprobe */,
							-1,
							execpath,
							malloc_offset);
	err = libbpf_get_error(skel->links.uprobe_malloc);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	skel->links.uretprobe_malloc = bpf_program__attach_uprobe(skel->progs.uretprobe_malloc,
							   true /* uretprobe */,
							   -1 /* any pid */,
							   execpath,
							   malloc_offset);
	err = libbpf_get_error(skel->links.uretprobe_malloc);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Attach tracepoint handler */
	skel->links.uprobe_free = bpf_program__attach_uprobe(skel->progs.uprobe_free,
							false /* not uretprobe */,
							-1,
							execpath,
							free_offset);
	err = libbpf_get_error(skel->links.uprobe_free);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}
	
	skel->links.uretprobe_free = bpf_program__attach_uprobe(skel->progs.uretprobe_free,
							   true /* uretprobe */,
							   -1 /* any pid */,
							   execpath,
							   free_offset);
	err = libbpf_get_error(skel->links.uretprobe_free);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	if (signal(SIGINT, sig_int) == SIG_ERR) {
		warn("can't set signal handler: %s\n", strerror(errno));
		err = 1;
		goto cleanup;
	}
	for (i = 0; ; i++) {
		if (exiting) {
			break;
		}
		/* trigger our BPF programs */
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	memory_bpf__destroy(skel);
	return -err;
}