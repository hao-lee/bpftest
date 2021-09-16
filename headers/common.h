#ifndef _COMMON_H_
#define _COMMON_H_

#include "constant.h"

typedef unsigned int u32;
typedef unsigned long long u64;
#define EFULLSTACK 1
#define EEMPTYSTACK 2

#define STACK_DEPTH 5

typedef struct {
	u64 start_ts;
	u64 payload;
} func_frame_t;

typedef struct {
	u32 top;
	u32 oversize;
	func_frame_t frames[STACK_DEPTH];
} func_stack_t;

typedef struct {
	u32 cgroup_id;
	u32 metric_id;
} cgroup_metric_id_t;


enum {
	BPF_ANY = 0,
	BPF_NOEXIST = 1,
	BPF_EXIST = 2,
	BPF_F_LOCK = 4,
};

struct host_metrics {
	/* host: compaction latency */
	u64 compaction_stat;
	/* host: page alloc latency in direct reclaim */
	u64 allocstall_stat;
	/*
	 * Disabled by default
	 */
	/* host & cg: counting allocated file pages */
	u64 pgfile_alloc;
	/* host & cg: counting allocated anon pages */
	u64 pganon_alloc;
	/* host: counting allocated slab pages */
	u64 pgslab_alloc;
	/* host & cg: freed file page count*/
	u64 pgfile_free;
	/* host & cg: freed anon page count */
	u64 pganon_free;
};

struct cgroup_metrics {
	/* cg: dritied page since boot */
	u64 nr_dirtied;
	/* cg: written page since boot */
	u64 nr_written;
	/* cg: direct reclaim latency caused by page alloc and try_charge */
	u64 directstall_stat;
	/* cg: direct reclaim count caused by page alloc and try_charge */
	u64 directstall_count;
	/* cg: numa balance pages */
	u64 numa_page_migrate;

	/*
	 * Disabled by default
	 */
	/* host & cg: counting allocated file pages */
	u64 pgfile_alloc;
	/* host & cg: counting allocated anon pages */
	u64 pganon_alloc;
	/* host & cg: freed file page count*/
	u64 pgfile_free;
	/* host & cg: freed anon page count */
	u64 pganon_free;
	/* cg: pages scaned by kswapd */
	u64 pgscan_kswapd;
	/* cg: pages reclaimed by kswapd */
	u64 pgsteal_kswapd;
	/* cg: pages scaned by allocation direct reclaim and try_charge reclaim */
	u64 pgscan_direct;
	/* cg: pages reclaimed by allocation direct reclaim and try_charge reclaim */
	u64 pgsteal_direct;

};
#endif /* _COMMON_H_ */
