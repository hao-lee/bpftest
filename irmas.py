import json
import re


host_metric_names = ["compaction_stat", "allocstall_stat", "pgfile_alloc",
        "pganon_alloc", "pgslab_alloc", "pgfile_free", "pganon_free"]
cgroup_metric_names = ["nr_dirtied", "nr_written",
        "directstall_stat", "directstall_count",
        "numa_page_migrate", "pgfile_alloc", "pganon_alloc",
        "pgfile_free", "pganon_free"]

'''
cgid : {
        "cg_name": xxx
        "metric_values": [x,x,x]
    }
'''
cg_metrics = {"0": {"cg_name": "NULL-CGROUP", "metric_values": []}}

host_metrics = None

def init_cg_metric_map():
    with open("/proc/cgroup_ids") as f:
        text = f.read().splitlines()
    for line in text:
        l = line.split()
        id = l[0]
        if len(l) == 2:
            name = l[1]
        else:
            name = ""
        cg_metrics[id] = {"cg_name": name, "metric_values": []}

def scan_cg_metrics():
    p = re.compile(r"[0-9]+")
    with open("/sys/fs/bpf/mm/cgroup_metrictable") as f:
        text = f.read().splitlines()
    for line in text:
        m = p.findall(line)
        if len(m)-1 != len(cgroup_metric_names):
            continue
        cgroup_id = m[0]
        try:
            metric_values = cg_metrics[cgroup_id]["metric_values"]
            metric_values.extend(m[1:])
        except:
            print(f"SKIP: cg_id={cgroup_id} is a temporary cgroup")

def scan_host_metrics():
    p = re.compile(r"[0-9]+")
    with open("/sys/fs/bpf/mm/host_metrictable") as f:
        text = f.read().splitlines()
    for line in text:
        m = p.findall(line)
        global host_metrics
        host_metrics = m[1:]


if __name__ == "__main__":
    init_cg_metric_map()
    scan_cg_metrics()
    print("===== CGroup Metrics =====")
    for _, v in cg_metrics.items():
        if (len(v["metric_values"])) == 0:
            continue
        print(v["cg_name"])
        for idx, metric_value in enumerate(v["metric_values"]):
            print(f"\t{cgroup_metric_names[idx]} {metric_value}")
    scan_host_metrics()
    print("===== Host Metrics =====")
    for idx, metric_value in enumerate(host_metrics):
        print(f"{host_metric_names[idx]} {metric_value}")
