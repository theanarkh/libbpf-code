// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */

struct event 
{
	__u64 start_time;
	__u64 end_time; 
	char name[20];
};


#define PHASE(uprobe) \
	uprobe(uv__run_timers) \ 
	uprobe(uv__run_pending) \
	uprobe(uv__run_idle) \
	uprobe(uv__run_prepare) \
	uprobe(uv__io_poll) \
	uprobe(uv__run_check) \
	uprobe(uv__run_closing_handles)
