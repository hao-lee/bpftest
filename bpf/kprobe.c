#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct pid_namespace *dummy(struct nsproxy *nsproxy)
{
	struct pid_namespace *ns = 0;
	return ns;
}
u32 get_ns_id_from_memcg(struct mem_cgroup *memcg)
{
	struct cgroup *cgrp;
	struct task_struct *tsk;
	struct cgrp_cset_link *link;
	struct css_set *cset;
	struct cgroup_subsys_state *css;
	struct list_head *lh;
	int nr_tasks;
	struct nsproxy *nsproxy = 0;
	struct pid_namespace *ns;

	css = (struct cgroup_subsys_state *)memcg;
	cgrp = BPF_CORE_READ(css, cgroup);
	lh = BPF_CORE_READ(cgrp, cset_links.next);
	link = container_of(lh, struct cgrp_cset_link, cset_link);
	cset = BPF_CORE_READ(link, cset);
	nr_tasks = BPF_CORE_READ(cset, nr_tasks);
	if (nr_tasks == 0)
		return 0;
	lh = BPF_CORE_READ(cset, tasks.next);
	tsk = container_of(lh, struct task_struct, cg_list);
	bpf_probe_read(&nsproxy, sizeof(nsproxy), &tsk->nsproxy);
	bpf_probe_read(&ns, sizeof(ns), &nsproxy->pid_ns_for_children); // ???
	return 0;
}


SEC("kprobe/account_page_dirtied")
int kprobe_account_page_dirtied(struct pt_regs *ctx)
{
	u32 ns_id = 0;
	struct mem_cgroup *memcg;
	int ret = 0;
	struct page *page;

	page = (struct page *)ctx->di;
	if (!page)
		return 0;
	ret = bpf_probe_read_kernel(&memcg, sizeof(memcg), &page->mem_cgroup);
	if (ret)
		return 0;
	if (!memcg)
		return 0;
	ns_id = get_ns_id_from_memcg(memcg);
	if (ns_id == 0)
		return 0;
	return 0;
}
