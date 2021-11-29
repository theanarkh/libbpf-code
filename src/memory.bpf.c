// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <stddef.h>
char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/malloc")
int BPF_KPROBE(uprobe_malloc, size_t size)
{
	bpf_printk("malloc start %d\n", size);
	return 0;
}

SEC("uretprobe/malloc")
int BPF_KRETPROBE(uretprobe_malloc, void* p)
{
	bpf_printk("malloc end %p \n", p);
	return 0;
}

SEC("uprobe/free")
int BPF_KPROBE(uprobe_free, void * p)
{
	bpf_printk("free start\n");
	return 0;
}

SEC("uretprobe/free")
int BPF_KRETPROBE(uretprobe_free)
{
	bpf_printk("free end\n");
	return 0;
}



