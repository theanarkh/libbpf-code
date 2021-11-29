// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("kprobe/__x64_sys_execve")
int BPF_KPROBE(__x64_sys_execve)
{
	pid_t pid;
	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE ENTRY pid = %d", pid);
	return 0;
}

SEC("kretprobe/__x64_sys_execve")
int BPF_KRETPROBE(__x64_sys_execve_exit)
{
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	bpf_printk("KPROBE EXIT: pid = %d\n", pid);
	return 0;
}