#include "common.h"
#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* pid -> stack */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int); /* pid */
	__type(value, func_stack_t); /* stack */
	__uint(max_entries, 10240);
} func_stack SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int); /* key = 0 */
	__type(value, struct host_metrics); /* value */
	__uint(max_entries, 10240);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} host_metrictable SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int); /* cgroup id */
	__type(value, struct cgroup_metrics); /* value */
	__uint(max_entries, 10240);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} cgroup_metrictable SEC(".maps");

static inline int stack_pop(func_stack_t *stack, func_frame_t *frame)
{
	if (stack->top <= 0) {
		return -EEMPTYSTACK;
	}
	u32 index = --stack->top;
	/* bound check */
	if (index < STACK_DEPTH) {
		frame->start_ts = stack->frames[index].start_ts;
	}
	return 0;
}

static inline int stack_push(func_stack_t *stack, func_frame_t *frame)
{
	u32 index = stack->top;
	/* bound check */
	if (index > STACK_DEPTH - 1) {
		return -EFULLSTACK;
	}
	stack->top++;
	stack->frames[index].start_ts = frame->start_ts;
	return 0;
}

int get_current_pid(struct pt_regs *ctx)
{
	u64 pid_tgid = bpf_get_current_pid_tgid();
	return pid_tgid & 0xffffffff;
}

int start_timing_with_payload(struct pt_regs *ctx, u64 payload)
{
	int pid = get_current_pid(ctx);
	u64 ip = ctx->ip;
	u64 ts = bpf_ktime_get_ns();
	int ret = 0;
	func_frame_t frame = {
		.start_ts = ts,
		.payload = payload,
	};
	func_stack_t *stack = bpf_map_lookup_elem(&func_stack, &pid);
	if (!stack) {
		func_stack_t new_stack = {
			.top = 0,
			.oversize = 0,
		};
		ret = stack_push(&new_stack, &frame);
		if (ret == 0)
			bpf_map_update_elem(&func_stack, &pid, &new_stack, BPF_ANY);
		return ret;
	}
	ret = stack_push(stack, &frame);
	if (ret == 0)
		bpf_map_update_elem(&func_stack, &pid, stack, BPF_ANY);
	else
		stack->oversize++;
	return ret;
}

int start_timing(struct pt_regs *ctx)
{
	return start_timing_with_payload(ctx, 0);
}

int end_timing_get_payload(struct pt_regs *ctx, u64 *delta, u64 *payload)
{
	u64 start_ts;
	int pid = get_current_pid(ctx);
	int ret = 0;

	func_stack_t *stack = bpf_map_lookup_elem(&func_stack, &pid);
	/* missing start */
	if (!stack) {
		*delta = 0;
		*payload = 0;
		return ret;
	}
	
	/*
	 * Don't pop stack untill the oversize is decreased to zero.
	 * Otherwise, the stack frame will be corrupted.
	 */
	if (stack->oversize) {
		stack->oversize--;
		*delta = 0;
		*payload = 0;
		return ret;
	}

	func_frame_t frame = {};
	ret = stack_pop(stack, &frame);
	if (ret) {
		bpf_map_delete_elem(&func_stack, &pid);
		return ret;
	}

	start_ts = frame.start_ts;
	*delta = bpf_ktime_get_ns() - start_ts;
	*payload = frame.payload;
	if (stack->top == 0)
		bpf_map_delete_elem(&func_stack, &pid);
	return ret;
}

int end_timing(struct pt_regs *ctx, u64 *delta)
{
	u64 payload;
	return end_timing_get_payload(ctx, delta, &payload);
}

int get_cgroup_id_from_memcg(struct mem_cgroup *memcg)
{
	int ret = 0;
	struct cgroup *cgroup;
	int cgroup_id = 0;

	/*
	 * If pointer is NULL, ebpf will return weird value instead of
	 * reporting errors.
	 */
	if (!memcg) {
		bpf_printk("Warning: get_cgroup_id_from_memcg() encounters"
			" a NULL pointer\n");
		return 0;
	}

	ret = bpf_probe_read_kernel(&cgroup, sizeof(cgroup), memcg);
	if (ret)
		return ret;
	if (!cgroup)
		return ret;
	ret = bpf_probe_read_kernel(&cgroup_id, sizeof(cgroup_id), &cgroup->id);
	if (ret)
		return ret;
	return cgroup_id;
}

/*
 * Get cgroup->id from through a page pointer
 * aka. page->mem_cgroup->css.cgroup->id
 */
int get_cgroup_id_from_page(struct page *page)
{
	struct mem_cgroup *memcg;
	int ret = 0;

	if (!page)
		return ret;

	ret = bpf_probe_read_kernel(&memcg, sizeof(memcg), &page->mem_cgroup);
	if (ret)
		return ret;
	/*
	 * id 0 is not used in kernel. We use it to indicate the page doesn't
	 * belong to any memcg.
	 */
	if (!memcg)
		return 0;
	return get_cgroup_id_from_memcg(memcg);
}

#define offsetof(TYPE, MEMBER)  ((size_t)&((TYPE *)0)->MEMBER)
#define container_of(ptr, type, member) ({ \
		void *__mptr = (void *)(ptr); \
		((type *)(__mptr - offsetof(type, member))); })

int get_ns_id_from_memcg(struct mem_cgroup *memcg)
{
	struct cgroup *cgrp;
	struct task_struct *tsk;
	struct cgrp_cset_link *link;
	struct css_set *cset;
	struct cgroup_subsys_state *css;
	struct list_head *lh;
	u32 ns_id;
	int pid;

	css = (struct cgroup_subsys_state *)memcg;
	cgrp = BPF_CORE_READ(css, cgroup);
	lh = BPF_CORE_READ(cgrp, cset_links.next);
	link = container_of(lh, struct cgrp_cset_link, cset_link);
	cset = BPF_CORE_READ(link, cset);
	lh = BPF_CORE_READ(cset, tasks.next);
	tsk = container_of(lh, struct task_struct, cg_list);
	ns_id = BPF_CORE_READ(tsk, nsproxy, pid_ns_for_children, ns.inum);
	pid = BPF_CORE_READ(tsk, pid);
	bpf_printk("pid=%d ns_id=%u\n", pid, ns_id);
	return ns_id;
}

SEC("kprobe/account_page_dirtied")
int kprobe_account_page_dirtied(struct pt_regs *ctx)
{
	u64 initval = 1;
	struct cgroup_metrics *valp;
	int cgroup_id;

	cgroup_id = get_cgroup_id_from_page((struct page *)ctx->di);
	if (cgroup_id < 0)
		return 0;

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	if (!valp) {
		struct cgroup_metrics new_metrics = {
			.nr_dirtied = 1,
		};
		bpf_map_update_elem(&cgroup_metrictable, &cgroup_id, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->nr_dirtied, 1);

	return 0;
}

SEC("kprobe/test_clear_page_writeback")
int kprobe_test_clear_page_writeback(struct pt_regs *ctx)
{
	u64 initval = 1;
	struct cgroup_metrics *valp;
	unsigned long page_flags;
	struct page *page;
	int cgroup_id;

	page = (struct page *)ctx->di;
	bpf_probe_read_kernel(&page_flags, sizeof(page_flags), &page->flags);
	if (!(page_flags & (1 << PG_writeback)))
		return 0;

	cgroup_id = get_cgroup_id_from_page(page);
	if (cgroup_id < 0)
		return 0;

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	if (!valp) {
		struct cgroup_metrics new_metrics = {
			.nr_written = 1,
		};
		bpf_map_update_elem(&cgroup_metrictable, &cgroup_id, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->nr_written, 1);

	return 0;
}

SEC("kprobe/try_to_compact_pages")
int kprobe_try_to_compact_pages(struct pt_regs *ctx)
{
	if (start_timing(ctx)){
		/* stack is full */
		return 0;
	}

	return 0;
}

SEC("kretprobe/try_to_compact_pages")
int kretprobe_try_to_compact_pages(struct pt_regs *ctx)
{
	struct host_metrics *valp;
	u64 delta = 0;
	int key = 0;

	if (end_timing(ctx, &delta)) {
		/* Try to pop a empty stack */
		return 0;
	}

	valp = bpf_map_lookup_elem(&host_metrictable, &key);
	if (!valp) {
		struct host_metrics new_metrics = {
			.compaction_stat = delta,
		};
		bpf_map_update_elem(&host_metrictable, &key, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->compaction_stat, delta);

	return 0;
}

SEC("kprobe/try_to_free_pages")
int kprobe_try_to_free_pages(struct pt_regs *ctx)
{
	u64 initval = 1, *valp;
	u64 ts = bpf_ktime_get_ns();

	if (start_timing(ctx)){
		/* stack is full */
		return 0;
	}

	return 0;
}

SEC("kretprobe/try_to_free_pages")
int kretprobe_try_to_free_pages(struct pt_regs *ctx)
{
	u64 initval = 1;
	struct host_metrics *valp;
	u64 delta = 0;
	int key = 0;

	if (end_timing(ctx, &delta)) {
		/* Try to pop a empty stack */
		return 0;
	}

	valp = bpf_map_lookup_elem(&host_metrictable, &key);
	if (!valp) {
		struct host_metrics new_metrics = {
			.allocstall_stat = delta,
		};
		bpf_map_update_elem(&host_metrictable, &key, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->allocstall_stat, delta);
	return 0;
}

#define PF_KSWAPD               0x00020000
SEC("kprobe/shrink_node_memcg")
int kprobe_shrink_node_memcg(struct pt_regs *ctx)
{
	int ret = 0;
	int cgroup_id;
	struct task_struct *tsk;
	unsigned int task_flags = 0;

	tsk = (struct task_struct *)bpf_get_current_task();
	ret = bpf_probe_read_kernel(&task_flags, sizeof(task_flags), &tsk->flags);
	if (ret)
		return ret;
	if (task_flags & PF_KSWAPD)
		return ret;

	cgroup_id = get_cgroup_id_from_memcg((struct mem_cgroup *)ctx->si);
	if (cgroup_id < 0)
		cgroup_id = 0;
	if (start_timing_with_payload(ctx, cgroup_id)) {
		/* print something ? */
		return 0; /* stack is full */
	}
	return 0;
}

SEC("kretprobe/shrink_node_memcg")
int kretprobe_shrink_node_memcg(struct pt_regs *ctx)
{
	u64 initval = 1;
	u64 delta = 0;
	u64 cgroup_id = 0;
	struct cgroup_metrics *valp;
	int ret = 0;
	struct task_struct *tsk;
	unsigned int task_flags = 0;

	tsk = (struct task_struct *)bpf_get_current_task();
	ret = bpf_probe_read_kernel(&task_flags, sizeof(task_flags), &tsk->flags);
	if (ret)
		return ret;
	if (task_flags & PF_KSWAPD)
		return ret;

	if (end_timing_get_payload(ctx, &delta, &cgroup_id)) {
		/* Try to pop a empty stack */
		return 0;
	}

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	if (!valp) {
		struct cgroup_metrics new_metrics = {
			.directstall_stat = 1,
		};
		bpf_map_update_elem(&cgroup_metrictable, &cgroup_id, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->directstall_stat, delta);

	return 0;
}
SEC("kprobe/shrink_node_memcg_counting")
int kprobe_shrink_node_memcg_counting(struct pt_regs *ctx)
{
	u64 initval = 1;
	u64 delta = 0;
	int cgroup_id;
	struct cgroup_metrics *valp;
	int ret = 0;
	struct task_struct *tsk;
	unsigned int task_flags = 0;

	tsk = (struct task_struct *)bpf_get_current_task();
	ret = bpf_probe_read_kernel(&task_flags, sizeof(task_flags), &tsk->flags);
	if (ret)
		return ret;
	if (task_flags & PF_KSWAPD)
		return ret;

	cgroup_id = get_cgroup_id_from_memcg((struct mem_cgroup *)ctx->si);
	if (cgroup_id < 0)
		return 0;

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	if (!valp) {
		struct cgroup_metrics new_metrics = {
			.directstall_count = 1,
		};
		bpf_map_update_elem(&cgroup_metrictable, &cgroup_id, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->directstall_count, 1);
	return 0;
}

SEC("kprobe/migrate_misplaced_page")
int kprobe_migrate_misplaced_page(struct pt_regs *ctx)
{
	u64 initval = 1;
	int cgroup_id;
	struct cgroup_metrics *valp;

	cgroup_id = get_cgroup_id_from_page((struct page *)ctx->di);
	if (cgroup_id < 0)
		return 0;

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	if (!valp) {
		struct cgroup_metrics new_metrics = {
			.numa_page_migrate = 1,
		};
		bpf_map_update_elem(&cgroup_metrictable, &cgroup_id, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->numa_page_migrate, 1);
	return 0;
}

/*
optimized
SEC("kprobe/migrate_misplaced_transhuge_page")
int kprobe_migrate_misplaced_transhuge_page(struct pt_regs *ctx)
{
	u64 value = 512;
	int cgroup_id;
	struct metrics *valp;

	cgroup_id = get_cgroup_id_from_page((struct page *)ctx->r9);
	cg_metric_id.cgroup_id = cgroup_id;
	cg_metric_id.metric_id = METRIC_NUMA_PAGE_MIGRATE;

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cg_metric_id);
	if (!valp) {
		bpf_map_update_elem(&cgroup_metrictable, &cg_metric_id, &value, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, value); // huge page
	return 0;
}
*/

SEC("kretprobe/new_slab")
int kretprobe_new_slab(struct pt_regs *ctx)
{
	u64 value = 0;
	struct page *page;
	int order = 0, ret;
	unsigned long page_flags;
	int key = 0;
	struct host_metrics *valp;

	page = (struct page *)ctx->ax;
	ret = bpf_probe_read_kernel(&page_flags, sizeof(page_flags),
					&page->flags);
	if (ret) {
		bpf_printk("can't read slab page flags\n");
		return 0;
	}

	if (page_flags & (1 << PG_head)) {
		page = page + 1;
		ret = bpf_probe_read_kernel(&order,
					sizeof(page->compound_order),
					&page->compound_order);
		if (ret) {
			bpf_printk("can't read slab page order\n");
			return 0;
		}
	}
	value = 1UL << order;

	valp = bpf_map_lookup_elem(&host_metrictable, &key);
	if (!valp) {
		struct host_metrics new_metrics = {
			.pgslab_alloc = value,
		};
		bpf_map_update_elem(&host_metrictable, &key, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->pgslab_alloc, value); /* compound page */
	return 0;
}

SEC("kprobe/page_add_new_anon_rmap")
int kprobe_page_add_new_anon_rmap(struct pt_regs *ctx)
{
	u64 initval = 1;
	struct host_metrics *valp;
	int key = 0;

	valp = bpf_map_lookup_elem(&host_metrictable, &key);
	if (!valp) {
		struct host_metrics new_metrics = {
			.pganon_alloc = 1,
		};
		bpf_map_update_elem(&host_metrictable, &key, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->pganon_alloc, 1);
	return 0;
}

SEC("kprobe/page_cache_alloc")
int kprobe_page_cache_alloc(struct pt_regs *ctx)
{
	u64 initval = 1;
	struct host_metrics *valp;
	int key = 0;

	valp = bpf_map_lookup_elem(&host_metrictable, &key);
	if (!valp) {
		struct host_metrics new_metrics = {
			.pgfile_alloc = 1,
		};
		bpf_map_update_elem(&host_metrictable, &key, &new_metrics, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(&valp->pgfile_alloc, 1);
	return 0;
}

SEC("kprobe/mem_cgroup_commit_charge")
int kprobe_mem_cgroup_commit_charge(struct pt_regs *ctx)
{
	u64 initval = 1;
	int cgroup_id;
	struct cgroup_metrics *valp;
	unsigned long page_flags;
	struct page *page;
	struct mem_cgroup *memcg;

	memcg = (struct mem_cgroup *)ctx->si;
	get_ns_id_from_memcg(memcg);
	cgroup_id = get_cgroup_id_from_memcg(memcg);
	if (cgroup_id < 0)
		return 0;

	page = (struct page *)ctx->di;
	bpf_probe_read_kernel(&page_flags, sizeof(page_flags), &page->flags);

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	if (!valp) {
		struct cgroup_metrics new_metrics = {};
		if (page_flags & (1 << PG_swapbacked))
			new_metrics.pganon_alloc = 1;
		else
			new_metrics.pgfile_alloc = 1;
		bpf_map_update_elem(&cgroup_metrictable, &cgroup_id, &new_metrics, BPF_ANY);
		return 0;
	}
	if (page_flags & (1 << PG_swapbacked))
		__sync_fetch_and_add(&valp->pganon_alloc, 1);
	else
		__sync_fetch_and_add(&valp->pgfile_alloc, 1);
	return 0;
}

/*
 * Is this function reasonable for host metrics?
 */
SEC("kprobe/uncharge_page_host")
int kprobe_uncharge_page_host(struct pt_regs *ctx)
{
	u64 initval = 1;
	int cgroup_id, ret;
	unsigned long page_flags;
	struct page *page;
	struct mem_cgroup *memcg;
	int key = 0;
	struct host_metrics *valp;

	page = (struct page *)ctx->di;
	ret = bpf_probe_read_kernel(&page_flags, sizeof(page_flags), &page->flags);
	if (ret)
		return ret;

	valp = bpf_map_lookup_elem(&host_metrictable, &key);
	if (!valp) {
		struct host_metrics new_metrics = {};
		if (page_flags & (1 << PG_swapbacked))
			new_metrics.pganon_free = 1;
		else
			new_metrics.pgfile_free = 1;
		bpf_map_update_elem(&host_metrictable, &key, &new_metrics, BPF_ANY);
		return 0;
	}
	if (page_flags & (1 << PG_swapbacked))
		__sync_fetch_and_add(&valp->pganon_free, 1);
	else
		__sync_fetch_and_add(&valp->pgfile_free, 1);
		
	return 0;
}

SEC("kprobe/uncharge_page_cg")
int kprobe_uncharge_page_cg(struct pt_regs *ctx)
{
	u64 initval = 1;
	int cgroup_id, ret;
	struct cgroup_metrics *valp;
	unsigned long page_flags;
	struct page *page;
	struct mem_cgroup *memcg;

	page = (struct page *)ctx->di;
	cgroup_id = get_cgroup_id_from_page(page);
	if (cgroup_id < 0)
		return 0;

	ret = bpf_probe_read_kernel(&page_flags, sizeof(page_flags), &page->flags);
	if (ret)
		return ret;

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	if (!valp) {
		struct cgroup_metrics new_metrics = {};
		if (page_flags & (1 << PG_swapbacked))
			new_metrics.pganon_free = 1;
		else
			new_metrics.pgfile_free = 1;
		bpf_map_update_elem(&cgroup_metrictable, &cgroup_id, &new_metrics, BPF_ANY);
		return 0;
	}
	if (page_flags & (1 << PG_swapbacked))
		__sync_fetch_and_add(&valp->pganon_free, 1);
	else
		__sync_fetch_and_add(&valp->pgfile_free, 1);
	return 0;
}

SEC("kprobe/memcg_stat_show")
int kprobe_memcg_stat_show(struct pt_regs *ctx)
{
	int cgroup_id, ret;
	struct cgroup_metrics *valp;
	struct mem_cgroup *memcg;
	struct seq_file *seq;
	atomic64_t tmp;
	struct cgroup *cgrp;
	struct cftype *cft;
	int subsys_id;
	struct kernfs_open_file *of;
	struct cgroup_subsys_state *css;

	seq = (struct seq_file *)ctx->di;
	of = BPF_CORE_READ(seq, private);
	cgrp = BPF_CORE_READ(of, kn, parent, priv);
	cft = BPF_CORE_READ(of, kn, priv);
	subsys_id = BPF_CORE_READ(cft, ss, id);
	css = BPF_CORE_READ(cgrp, subsys[subsys_id]);
	memcg = (struct mem_cgroup *)css;
	if (!memcg)
		return 0;
	cgroup_id = get_cgroup_id_from_memcg(memcg);
	if (cgroup_id < 0)
		return 0;

	valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	if (!valp) {
		struct cgroup_metrics new_metrics = {0};
		bpf_map_update_elem(&cgroup_metrictable, &cgroup_id, &new_metrics, BPF_ANY);
		valp = bpf_map_lookup_elem(&cgroup_metrictable, &cgroup_id);
	}
	if (!valp)
		return 0;

	tmp = BPF_CORE_READ(memcg, events[PGSCAN_KSWAPD]);
	valp->pgscan_kswapd = tmp.counter;
	tmp = BPF_CORE_READ(memcg, events[PGSTEAL_KSWAPD]);
	valp->pgsteal_kswapd = tmp.counter;
	tmp = BPF_CORE_READ(memcg, events[PGSCAN_DIRECT]);
	valp->pgscan_direct = tmp.counter;
	tmp = BPF_CORE_READ(memcg, events[PGSTEAL_DIRECT]);
	valp->pgsteal_direct = tmp.counter;
	return 0;
}

