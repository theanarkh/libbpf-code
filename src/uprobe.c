// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobe.skel.h"
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
	struct uprobe_bpf *skel;
	long base_addr, uprobe_offset;
	int err, i;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Bump RLIMIT_MEMLOCK to allow BPF sub-system to do anything */
	bump_memlock_rlimit();

	/* Load and verify BPF application */
	skel = uprobe_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	// char * pid_str = argv[1];
	// pid_t pid = (pid_t)atoi(pid_str);
	char execpath[50000] = "/snap/node/5485/bin/node";
	//sprintf(execpath, "%s%s%s", "/proc/", pid_str, "/exe");
	// get function str by readelf -s | grep your functionname
	uprobe_offset = get_elf_func_offset(execpath, "_ZN4node11Environment16RunBootstrappingEv");
	fprintf(stderr, "uprobe_offset: %ld\n", uprobe_offset);
	fprintf(stderr, "uprobe_execpath: %s\n", execpath);
	/* Attach tracepoint handler */
	skel->links.uprobe = bpf_program__attach_uprobe(skel->progs.uprobe,
							false /* not uretprobe */,
							-1,
							execpath,
							uprobe_offset);
	err = libbpf_get_error(skel->links.uprobe);
	if (err) {
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
	 * processes that use the same binary executable; to do that we need
	 * to specify -1 as PID, as we do here
	 */
	// skel->links.uretprobe = bpf_program__attach_uprobe(skel->progs.uretprobe,
	// 						   true /* uretprobe */,
	// 						   -1 /* any pid */,
	// 						   execpath,
	// 						   uprobe_offset);
	// err = libbpf_get_error(skel->links.uretprobe);
	// if (err) {
	// 	fprintf(stderr, "Failed to attach uprobe: %d\n", err);
	// 	goto cleanup;
	// }

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
	uprobe_bpf__destroy(skel);
	return -err;
}