generate: 
	go generate ./...

build-ebpf-memleak:
	go build -ldflags "-s -w" -o ebpf-memleak cmd/main.go

build: generate build-ebpf-memleak

clean:
	rm -f ebpf-memleak
	rm -f internal/probe/probe_bpf*.go
	rm -f internal/probe/probe_bpf*.o