package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/sys/unix"
	"ebpf-memleak/internal/probe"
)

var (
	pid           = flag.Int("pid", 0, "PID to trace memleak (0 = trace kernel memory allocation)")
	minSize       = flag.Uint64("min-size", 0, "Minimum allocation size to trace")
	maxSize       = flag.Uint64("max-size", ^uint64(0), "Maximum allocation size to trace")
	pageSize      = flag.Uint64("page-size", 4096, "Page size")
	sampleRate    = flag.Uint64("sample-rate", 1, "Sample rate for tracing")
	traceAll      = flag.Bool("trace-all", false, "Trace all allocations")
	waMissingFree = flag.Bool("wa-missing-free", false, "Workaround for missing free")
	nTopStacks    = flag.Int("n-top-stacks", 3, "Number of top stacks to display")
)

func signalHandler(cancel context.CancelFunc) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("\nCaught SIGINT... Exiting")
		cancel()
	}()
}

func main() {
	flag.Parse()

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	var stackFlag uint64
	if *pid == 0 {
		stackFlag = 0
	} else {
		stackFlag = uint64(unix.BPF_F_USER_STACK)
	}
	log.Printf("Starting memleak tracer for PID %d", *pid)
	signalHandler(cancel)
	if err := probe.Run(ctx, *pid, *minSize, *maxSize, *pageSize, *sampleRate, *traceAll, stackFlag, *waMissingFree, *nTopStacks); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}
}
