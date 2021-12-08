// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uv.h"
#include "uv_uprobe.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u32);
	__type(value, const char *);
} values SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

static __u64 id = 0;
SEC("uprobe/uv__io_poll")
int BPF_KPROBE(uprobe_uv__io_poll, uv_loop_t* loop, int timeout)
{
	__u64 current_id = id;
	__u64 time = bpf_ktime_get_ns();
	bpf_map_update_elem(&values, &current_id, &time, BPF_ANY);
	return 0;
}

const char * uv__io_poll_name = "uv__io_poll";
SEC("uretprobe/uv__io_poll")
int BPF_KRETPROBE(uretprobe_uv__io_poll)
{	
	__u64 current_id = id;
	__u64 *time = bpf_map_lookup_elem(&values, &current_id);
	if (!time) {
		return 0;
	}
	// char comm[16];
	// bpf_get_current_comm(&comm, sizeof(comm));
	struct event e;
	//bpf_probe_read_user_str(e.name, sizeof(e.name), uv__io_poll_name);
	e.start_time = *time;
	e.end_time = bpf_ktime_get_ns();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	bpf_map_delete_elem(&values, &current_id);
	id++;
	return 0;
}
