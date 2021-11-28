// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uv.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/RunBootstrapping")
int BPF_KPROBE(uprobe)
{
	bpf_printk("RunBootstrapping start");
	return 0;
}

SEC("uretprobe/RunBootstrapping")
int BPF_KRETPROBE(uretprobe)
{
	bpf_printk("RunBootstrapping end");
	return 0;
}
