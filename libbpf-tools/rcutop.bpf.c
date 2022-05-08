/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2021 Hengqi Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "rcutop.h"
#include "maps.bpf.h"

#define MAX_ENTRIES	10240

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, void *);
	__type(value, int);
} cbs_queued SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, void *);
	__type(value, int);
} cbs_executed SEC(".maps");

SEC("tracepoint/rcu/rcu_callback")
int tracepoint_rcu_callback(struct trace_event_raw_rcu_callback* ctx)
{
	void *key = ctx->func;
	int *val = NULL;
	static const int zero;

	val = bpf_map_lookup_or_try_init(&cbs_queued, &key, &zero);
	if (val) {
		__sync_fetch_and_add(val, 1);
	}

	return 0;
}

SEC("tracepoint/rcu/rcu_invoke_callback")
int tracepoint_rcu_invoke_callback(struct trace_event_raw_rcu_invoke_callback* ctx)
{
	void *key = ctx->func;
	int *val;
	int zero = 0;

	val = bpf_map_lookup_or_try_init(&cbs_executed, (void *)&key, (void *)&zero);
	if (val) {
		__sync_fetch_and_add(val, 1);
	}

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
