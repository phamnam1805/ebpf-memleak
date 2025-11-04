package probe

import (
	"context"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/memleak.bpf.c -- -O2 -target x86_64-unknown-linux-gnu -D__TARGET_ARCH_x86

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2

type probe struct {
	bpfObjects 	*probeObjects
	links 		[]link.Link
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

func newProbe(pid int, minSize uint64, maxSize uint64, pageSize uint64, sampleRate uint64, traceAll bool, stackFlags uint64, waMissingFree bool) (*probe, error) {
	log.Println("Creating a new probe")

	prbe := probe{}

	if err := prbe.loadObjects(minSize, maxSize, pageSize, sampleRate, traceAll, stackFlags, waMissingFree); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.attachPrograms(pid); err != nil {
		log.Printf("Failed attaching ebpf programs: %v", err)
		return nil, err
	}

	return &prbe, nil
}

func (p *probe) loadObjects(minSize uint64, maxSize uint64, pageSize uint64, sampleRate uint64, traceAll bool, stackFlags uint64, waMissingFree bool) error {
	log.Printf("Loading probe object into kernel")

	objs := probeObjects{}

	spec, err := loadProbe()
	if err != nil {
		return err
	}

	if minSize > 0 {
		if err := spec.Variables["min_size"].Set(minSize); err != nil {
			log.Printf("Failed setting min_size: %v", err)
			return err
		}

		log.Printf("Set min_size to %d", minSize)
	}

	if maxSize > 0 {
		if err := spec.Variables["max_size"].Set(maxSize); err != nil {
			log.Printf("Failed setting max_size: %v", err)
			return err
		}

		log.Printf("Set max_size to %d", maxSize)
	}

	if pageSize > 0 {
		if err := spec.Variables["page_size"].Set(pageSize); err != nil {
			log.Printf("Failed setting page_size: %v", err)
			return err
		}

		log.Printf("Set page_size to %d", pageSize)
	}

	if sampleRate > 0 {
		if err := spec.Variables["sample_rate"].Set(sampleRate); err != nil {
			log.Printf("Failed setting sample_rate: %v", err)
			return err
		}

		log.Printf("Set sample_rate to %d", sampleRate)
	}

	if traceAll {
		if err := spec.Variables["trace_all"].Set(uint8(1)); err != nil {
			log.Printf("Failed setting trace_all: %v", err)
			return err
		}

		log.Printf("Enabled trace_all")
	}

	if stackFlags > 0 {
		if err := spec.Variables["stack_flags"].Set(stackFlags); err != nil {
			log.Printf("Failed setting stack_flags: %v", err)
			return err
		}

		log.Printf("Set stack_flags to %d", stackFlags)
	}

	if waMissingFree {
		if err := spec.Variables["wa_missing_free"].Set(uint8(1)); err != nil {
			log.Printf("Failed setting wa_missing_free: %v", err)
			return err
		}

		log.Printf("Enabled wa_missing_free")
	}

	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf",
		},
	}); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return err
	}

	p.bpfObjects = &objs

	return nil
}

func (p *probe) attachPrograms(pid int) error {
	log.Printf("Attaching bpf programs to kernel")

	libcPath := "/lib/x86_64-linux-gnu/libc.so.6"
	executable, err := link.OpenExecutable(libcPath)
	if err != nil {
		log.Fatalf("Failed to open libc: %v", err)
	}

	p.links = make([]link.Link, 35)

	mallocEnterLink, err := executable.Uprobe("malloc", p.bpfObjects.MallocEnter, &link.UprobeOptions{
		PID: pid,
	})

	if err != nil {
		log.Fatalf("Failed to attach uprobe/malloc_enter: %v", err)
	}
	p.links = append(p.links, mallocEnterLink)

	mallocExitLink, err := executable.Uretprobe("malloc", p.bpfObjects.MallocExit, &link.UprobeOptions{
		PID: pid,
	})
	
	if err != nil {
		log.Fatalf("Failed to attach uprobe/malloc_exit: %v", err)
	}

	p.links = append(p.links, mallocExitLink)
	
	freeEnterLink, err := executable.Uprobe("free", p.bpfObjects.FreeEnter, &link.UprobeOptions{
		PID: pid,
	})
	
	if err != nil {
		log.Fatalf("Failed to attach uprobe/free_enter uprobe: %v", err)
	}

	p.links = append(p.links, freeEnterLink)
	
	callocEnterLink, err := executable.Uprobe("calloc", p.bpfObjects.CallocEnter, &link.UprobeOptions{
		PID: pid,
	})
	
	if err != nil {
		log.Fatalf("Failed to attach uprobe/calloc_enter: %v", err)
	}

	p.links = append(p.links, callocEnterLink)
	
	callocExitLink, err := executable.Uretprobe("calloc", p.bpfObjects.CallocExit, &link.UprobeOptions{
		PID: pid,
	})
	
	if err != nil {
		log.Fatalf("Failed to attach uprobe/calloc_exit: %v", err)
	}

	p.links = append(p.links, callocExitLink)

	reallocEnterLink, err := executable.Uprobe("realloc", p.bpfObjects.ReallocEnter, &link.UprobeOptions{
		PID: pid,
	})
	
	if err != nil {
		log.Fatalf("Failed to attach uprobe/realloc_enter: %v", err)
	}

	p.links = append(p.links, reallocEnterLink)
	
	reallocExitLink, err := executable.Uretprobe("realloc", p.bpfObjects.ReallocExit, &link.UprobeOptions{
		PID: pid,
	})
	
	if err != nil {
		log.Fatalf("Failed to attach uprobe/realloc_exit: %v", err)
	}	

	p.links = append(p.links, reallocExitLink)

	return nil
}

func (p *probe) Close() error {

	for _, l := range p.links {
		if l != nil {
			if err := l.Close(); err != nil {
				log.Printf("Failed closing link: %v", err)
				return err
			}
		}
	}
	return nil
}

func Run(ctx context.Context, pid int, minSize uint64, maxSize uint64, pageSize uint64, sampleRate uint64, traceAll bool, stackFlags uint64, waMissingFree bool) error {
	probe, err := newProbe(pid, minSize, maxSize, pageSize, sampleRate, traceAll, stackFlags, waMissingFree)
	if err != nil {
		log.Printf("Failed creating new probe: %v", err)
		return err
	}
	<-ctx.Done()
	return probe.Close()
}
