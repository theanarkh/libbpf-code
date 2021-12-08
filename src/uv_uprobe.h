// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <linux/bpf.h>
struct event 
{
	__u64 start_time;
	__u64 end_time; 
};
