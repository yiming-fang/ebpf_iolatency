// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
/* Adapted by yanniszark in 2024 */

// All linux kernel type definitions are in vmlinux.h
#include "vmlinux.h"
// BPF helpers
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


#define MAX_REQS (1 << 20)
#define MAX_HIST 17

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct request *);
    __type(value, u64);
    __uint(max_entries, MAX_REQS);
} rqs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, u64);
	__type(value, u64);
	__uint(max_entries, MAX_REQS);
} hist SEC(".maps");


static __always_inline int rq_start(struct request *rq) {
    u64 t1 = bpf_ktime_get_ns();
    bpf_map_update_elem(&rqs, &rq, &t1, BPF_ANY);
    return 0;
}
static __always_inline u64 compute_bucket(u64 diff) {
    for (u64 i = 0; i < MAX_HIST; i++) {
        if (diff < ((u64) 1) << (i + 1))
            return i;
    }
    return MAX_HIST - 1;
}

SEC("tp_btf/block_rq_issue")
int BPF_PROG(block_rq_issue, struct request *rq) {
    return rq_start(rq);
}

SEC("tp_btf/block_rq_insert")
int BPF_PROG(block_rq_insert, struct request *rq) {
    return rq_start(rq);
}

SEC("tp_btf/block_rq_complete")
int BPF_PROG(block_rq_complete, struct request *rq, int error, 
             unsigned int nr_bytes) {
    u64 t2 = bpf_ktime_get_ns();
    u64 *t1p = bpf_map_lookup_elem(&rqs, &rq);
    if (!t1p || *t1p > t2)
        return 1;
    bpf_map_delete_elem(&rqs, &rq);

    u64 diff = (t2 - *t1p) / 1000U;
    u64 bucket = compute_bucket(diff);
    u64 *cnt = bpf_map_lookup_elem(&hist, &bucket);
    if (!cnt) {
        u64 one = 1;
        bpf_map_update_elem(&hist, &bucket, &one, BPF_ANY);
    } else {
        *cnt += 1;
    }

    return 0;
}
