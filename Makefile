generate: 
	go generate ./...

build-ebpf-memleak:
	go build -ldflags "-s -w" -o ebpf-memleak cmd/main.go

build-test-memleak:
	gcc -g -O0 -o bpf/test_memleak bpf/test_memleak.c

build: generate build-ebpf-memleak

clean:
	rm -f ebpf-memleak
	rm -f bpf/test_memleak
	rm -f internal/probe/probe_bpf*.go
	rm -f internal/probe/probe_bpf*.o