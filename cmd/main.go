package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"ebpf-memleak/internal/probe"
)

var (
	pid           = flag.Int("pid", 0, "PID to trace memleak (0 = all)")
	minSize       = flag.Uint64("min-size", 0, "Minimum allocation size to trace")
	maxSize       = flag.Uint64("max-size", ^uint64(0), "Maximum allocation size to trace")
	pageSize      = flag.Uint64("page-size", 4096, "Page size")
	sampleRate    = flag.Uint64("sample-rate", 1, "Sample rate for tracing")
	traceAll      = flag.Bool("trace-all", false, "Trace all allocations")
	stackFlags    = flag.Uint64("stack-flags", 0, "Stack flags for stack capture")
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

	// Require pid to be provided and > 0
	if *pid <= 0 {
		flag.Usage()
		log.Fatalf("-pid is required and must be > 0")
	}

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	signalHandler(cancel)
	if err := probe.Run(ctx, *pid, *minSize, *maxSize, *pageSize, *sampleRate, *traceAll, *stackFlags, *waMissingFree, *nTopStacks); err != nil {
		log.Fatalf("Failed running the probe: %v", err)
	}
}
