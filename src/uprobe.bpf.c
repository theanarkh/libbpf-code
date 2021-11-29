// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uv.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe/uv_tcp_listen")
int BPF_KPROBE(uprobe, uv_tcp_t* tcp, int backlog, uv_connection_cb cb)
{
	bpf_printk("uv_tcp_listen start %d \n", backlog);
	return 0;
}

SEC("uretprobe/uv_tcp_listen")
int BPF_KRETPROBE(uretprobe, int ret)
{
	bpf_printk("uv_tcp_listen end %d \n", ret);
	return 0;
}
