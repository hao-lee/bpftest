//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"os"
	"os/signal"
	"path"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 Handler ./bpf/kprobe.c -- -I headers

const mapKey uint32 = 0

func main() {

	// Name of the kernel function to trace.
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Increase the rlimit of the current process to provide sufficient space
	// for locking memory for the eBPF map.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	pinPath := path.Join("/sys/fs/bpf", "mm")
	if err := os.MkdirAll(pinPath, os.ModePerm); err != nil {
		log.Fatalf("failed to create bpf fs subpath: %+v", err)
	}
	// Load pre-compiled programs and maps into the kernel.
	objs := HandlerObjects{}
	if err := LoadHandlerObjects(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinPath,
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	kp1, err := link.Kprobe("account_page_dirtied", objs.KprobeAccountPageDirtied)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp1.Close()

	kp2, err := link.Kprobe("test_clear_page_writeback", objs.KprobeTestClearPageWriteback)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp2.Close()

	kp3, err := link.Kprobe("try_to_compact_pages", objs.KprobeTryToCompactPages)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp3.Close()

	kp4, err := link.Kretprobe("try_to_compact_pages", objs.KretprobeTryToCompactPages)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp4.Close()

	kp5, err := link.Kprobe("try_to_free_pages", objs.KprobeTryToFreePages)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp5.Close()

	kp6, err := link.Kretprobe("try_to_free_pages", objs.KretprobeTryToFreePages)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp6.Close()

	kp7, err := link.Kprobe("shrink_node_memcg", objs.KprobeShrinkNodeMemcg)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp7.Close()

	kp8, err := link.Kretprobe("shrink_node_memcg", objs.KretprobeShrinkNodeMemcg)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp8.Close()

	kp9, err := link.Kprobe("shrink_node_memcg", objs.KprobeShrinkNodeMemcgCounting)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp9.Close()

	kp10, err := link.Kprobe("migrate_misplaced_page", objs.KprobeMigrateMisplacedPage)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp10.Close()

	kp11, err := link.Kretprobe("new_slab", objs.KretprobeNewSlab)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp11.Close()

	kp12, err := link.Kprobe("page_add_new_anon_rmap", objs.KprobePageAddNewAnonRmap)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp12.Close()

	kp13, err := link.Kprobe("__page_cache_alloc", objs.KprobePageCacheAlloc)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp13.Close()

	kp14, err := link.Kprobe("mem_cgroup_commit_charge", objs.KprobeMemCgroupCommitCharge)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp14.Close()

	kp15, err := link.Kprobe("uncharge_page", objs.KprobeUnchargePageHost)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp15.Close()

	kp16, err := link.Kprobe("uncharge_page", objs.KprobeUnchargePageCg)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp16.Close()
	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	log.Println("Waiting for events..")
	for {
		select {
		case <-ticker.C:
			//var value uint64
			//if err := objs.HostMetrictable.Lookup(mapKey, &value); err != nil {
				//log.Fatalf("reading map: %v", err)
			//}
			//log.Printf("%v times\n", value)
		case <-stopper:
			return
		}
	}
}
