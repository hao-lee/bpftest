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
