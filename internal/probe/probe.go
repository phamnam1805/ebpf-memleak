package probe

import (
	"log"
	"context"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/source-code.bpf.c -- -O2

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2

type probe struct {
	bpfObjects 	*probeObjects
}

func setRlimit() error {
     log.Println("Setting rlimit")

     return unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
         Cur: twentyMegaBytes,
         Max: fortyMegaBytes,
     })
}

func setUnlimitedRlimit() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Failed setting infinite rlimit: %v", err)
		return err
	}
	return nil
}

func newProbe() (*probe, error) {
	log.Println("Creating a new probe")

	prbe := probe{}

	if err := prbe.loadObjects(); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.attachPrograms(); err != nil {
		log.Printf("Failed attaching ebpf programs: %v", err)
		return nil, err
	}

	return &prbe, nil
}

func (p *probe) loadObjects() error {
	return nil
}

func (p *probe) attachPrograms() error {
	return nil
}

func (p *probe) Close() error {
	return nil
}

func Run(ctx context.Context) error {
	probe, err := newProbe()
	if err != nil {
		log.Printf("Failed creating new probe: %v", err)
		return err
	}
	<-ctx.Done()
    return probe.Close()
}