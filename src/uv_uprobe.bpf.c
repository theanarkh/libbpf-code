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

#define PROBE(type) \
SEC("uprobe/" #type) \
int BPF_KPROBE(uprobe_##type) \
{ \
	char key[20] = #type; \
	__u64 time = bpf_ktime_get_ns(); \
	bpf_map_update_elem(&values, &key, &time, BPF_ANY); \
	return 0; \
} \
SEC("uretprobe/" #type) \
int BPF_KRETPROBE(uretprobe_##type) \
{	\
	char key[20] = #type; \
	__u64 *time = bpf_map_lookup_elem(&values, &key); \
	if (!time) { \
		return 0; \
	} \
	struct event e = { \
		.name=#type \
	}; \
	e.start_time = *time; \
	e.end_time = bpf_ktime_get_ns(); \
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e)); \
	bpf_map_delete_elem(&values, key); \
	return 0; \
}

PHASE(PROBE)