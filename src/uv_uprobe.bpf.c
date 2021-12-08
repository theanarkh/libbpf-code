// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uv.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/uv__io_poll")
int BPF_KPROBE(uprobe, uv_loop_t* loop, int timeout)
{
	bpf_printk("timeout %d \n",timeout);
	return 0;
}
/*
SEC("uretprobe/uv_tcp_listen")
int BPF_KRETPROBE(uretprobe, int ret)
{
	bpf_printk("uv_tcp_listen end %d \n", ret);
	return 0;
}
*/
