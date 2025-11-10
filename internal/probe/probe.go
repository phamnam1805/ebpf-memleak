package probe

import (
	"bufio"
	"container/heap"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"golang.org/x/sys/unix"

	"ebpf-memleak/internal/info"
	"ebpf-memleak/internal/symbolizer"
)

//go:generate env GOPACKAGE=probe go run github.com/cilium/ebpf/cmd/bpf2go probe ../../bpf/memleak.bpf.c -- -O2 -target x86_64-unknown-linux-gnu -D__TARGET_ARCH_x86

const tenMegaBytes = 1024 * 1024 * 10
const twentyMegaBytes = tenMegaBytes * 2
const fortyMegaBytes = twentyMegaBytes * 2
const maxStackDepth = 127

type MinHeap []*info.CombinedAllocInfo
type StackTrace [maxStackDepth]uint64

func (h MinHeap) Len() int           { return len(h) }
func (h MinHeap) Less(i, j int) bool { return h[i].TotalSize < h[j].TotalSize } // min-heap
func (h MinHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *MinHeap) Push(x any) {
	*h = append(*h, x.(*info.CombinedAllocInfo))
}

func (h *MinHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

type probe struct {
	bpfObjects *probeObjects
	links      []link.Link
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

	if err := prbe.loadObjects(pid, minSize, maxSize, pageSize, sampleRate, traceAll, stackFlags, waMissingFree); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return nil, err
	}

	if err := prbe.attachPrograms(pid); err != nil {
		log.Printf("Failed attaching ebpf programs: %v", err)
		return nil, err
	}

	return &prbe, nil
}

func (p *probe) loadObjects(pid int, minSize uint64, maxSize uint64, pageSize uint64, sampleRate uint64, traceAll bool, stackFlags uint64, waMissingFree bool) error {
	log.Printf("Loading probe object into kernel")

	objs := probeObjects{}

	spec, err := loadProbe()
	if err != nil {
		return err
	}

	if pid > 0 {
		if err := spec.Variables["target_pid"].Set(int32(pid)); err != nil {
			log.Printf("Failed setting target_pid: %v", err)
			return err
		}

		log.Printf("Set target_pid to %d", pid)
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

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Printf("Failed loading probe objects: %v", err)
		return err
	}

	// if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
	// 	Maps: ebpf.MapOptions{
	// 		PinPath: "/sys/fs/bpf",
	// 	},
	// }); err != nil {
	// 	log.Printf("Failed loading probe objects: %v", err)
	// 	return err
	// }

	p.bpfObjects = &objs

	return nil
}

func getLibcPath(pid int) (string, error) {
	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	f, err := os.Open(mapsFile)
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "/libc-") || strings.Contains(line, "/libc.so") {
			// Extract the path
			fields := strings.Fields(line)
			if len(fields) >= 6 {
				path := fields[len(fields)-1]
				// Return the first occurrence
				return path, nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read /proc/%d/maps: %w", pid, err)
	}

	return "", fmt.Errorf("failed to read /proc/%d/maps: %w", pid, err)
}

func (p *probe) attachPrograms(pid int) error {
	log.Printf("Attaching bpf programs to kernel")

	if pid > 0 {
		log.Printf("Attaching to trace memory allocations of PID: %d", pid)
		libcPath, err := getLibcPath(pid)
		if err != nil {
			return fmt.Errorf("Failed to get libc path: %v", err)
		}
		executable, err := link.OpenExecutable(libcPath)
		if err != nil {
			return fmt.Errorf("Failed to open libc: %v", err)
		}

		p.links = make([]link.Link, 35)

		mallocEnterLink, err := executable.Uprobe("malloc", p.bpfObjects.MallocEnter, &link.UprobeOptions{
			PID: pid,
		})

		if err != nil {
			log.Fatalf("Failed to attach uprobe/malloc_enter: %v", err)
		}
		log.Printf("Successfully linked tracepoint uprobe/malloc_enter")
		p.links = append(p.links, mallocEnterLink)

		mallocExitLink, err := executable.Uretprobe("malloc", p.bpfObjects.MallocExit, &link.UprobeOptions{
			PID: pid,
		})

		if err != nil {
			log.Fatalf("Failed to attach uprobe/malloc_exit: %v", err)
		}
		log.Printf("Successfully linked tracepoint uprobe/malloc_exit")
		p.links = append(p.links, mallocExitLink)

		freeEnterLink, err := executable.Uprobe("free", p.bpfObjects.FreeEnter, &link.UprobeOptions{
			PID: pid,
		})

		if err != nil {
			log.Fatalf("Failed to attach uprobe/free_enter uprobe: %v", err)
		}
		log.Printf("Successfully linked tracepoint uprobe/free_enter")
		p.links = append(p.links, freeEnterLink)

		callocEnterLink, err := executable.Uprobe("calloc", p.bpfObjects.CallocEnter, &link.UprobeOptions{
			PID: pid,
		})

		if err != nil {
			log.Fatalf("Failed to attach uprobe/calloc_enter: %v", err)
		}
		log.Printf("Successfully linked tracepoint uprobe/calloc_enter")
		p.links = append(p.links, callocEnterLink)

		callocExitLink, err := executable.Uretprobe("calloc", p.bpfObjects.CallocExit, &link.UprobeOptions{
			PID: pid,
		})

		if err != nil {
			log.Fatalf("Failed to attach uprobe/calloc_exit: %v", err)
		}
		log.Printf("Successfully linked tracepoint uprobe/calloc_exit")
		p.links = append(p.links, callocExitLink)

		reallocEnterLink, err := executable.Uprobe("realloc", p.bpfObjects.ReallocEnter, &link.UprobeOptions{
			PID: pid,
		})

		if err != nil {
			log.Fatalf("Failed to attach uprobe/realloc_enter: %v", err)
		}
		log.Printf("Successfully linked tracepoint uprobe/realloc_enter")
		p.links = append(p.links, reallocEnterLink)

		reallocExitLink, err := executable.Uretprobe("realloc", p.bpfObjects.ReallocExit, &link.UprobeOptions{
			PID: pid,
		})

		if err != nil {
			log.Fatalf("Failed to attach uprobe/realloc_exit: %v", err)
		}
		log.Printf("Successfully linked tracepoint uprobe/realloc_exit")
		p.links = append(p.links, reallocExitLink)
	} else {
		log.Printf("Attaching to trace Kernel memory allocations")
		memleakKmallocLink, err := link.Tracepoint("kmem", "kmalloc", p.bpfObjects.MemleakKmalloc, nil)
		if err != nil {
			log.Printf("Failed to link tracepoint tracepoint/kmem/kmalloc %v", err)
			return err
		}
		log.Printf("Successfully linked tracepoint tracepoint/kmem/kmalloc")
		p.links = append(p.links, memleakKmallocLink)

		memleakKfreeLink, err := link.Tracepoint("kmem", "kfree", p.bpfObjects.MemleakKfree, nil)
		if err != nil {
			log.Printf("Failed to link tracepoint tracepoint/kmem/kfree %v", err)
			return err
		}
		log.Printf("Successfully linked tracepoint tracepoint/kmem/kfree")
		p.links = append(p.links, memleakKfreeLink)
	}

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

func getUserspaceStackTrace(stackId uint32, stackTracesMap *ebpf.Map, pid int) ([]string, error) {
	var stackTrace StackTrace
	err := stackTracesMap.Lookup(stackId, &stackTrace)
	if err != nil {
		return nil, err
	}

	mapsFile := fmt.Sprintf("/proc/%d/maps", pid)
	symResolver, err := symbolizer.NewUserspaceSymbolResolver(mapsFile)

	if err != nil {
		return nil, err
	}

	f, err := os.Open(mapsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	frames := []string{}
	for _, pc := range stackTrace {
		if pc == 0 {
			continue
		}
		// fmt.Printf("Resolving pc=0x%x\n", pc)
		sym, err := symResolver.Resolve(pc)
		if err != nil {
			// log.Printf("Failed to resolve symbol for pc=0x%x: %v", pc, err)
			frames = append(frames, fmt.Sprintf("0x%x [unknown]", pc))
		} else {
			frames = append(frames, fmt.Sprintf("0x%x %s", pc, sym))
		}
	}
	return frames, nil
}

func isProcessAlive(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}

	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func Run(ctx context.Context, pid int, minSize uint64, maxSize uint64, pageSize uint64, sampleRate uint64, traceAll bool, stackFlags uint64, waMissingFree bool, nTopStacks int) error {
	probe, err := newProbe(pid, minSize, maxSize, pageSize, sampleRate, traceAll, stackFlags, waMissingFree)
	if err != nil {
		log.Printf("Failed creating new probe: %v", err)
		return err
	}
	allocsMap := probe.bpfObjects.probeMaps.Allocs
	defer allocsMap.Close()

	combinedAllocsMap := probe.bpfObjects.probeMaps.CombinedAllocs
	defer combinedAllocsMap.Close()

	go func() {
		for (pid > 0 && isProcessAlive(pid)) || pid == 0 {
			fmt.Println("=== Reading combined allocs map entries ===")

			combinedAllocsMapIter := combinedAllocsMap.Iterate()
			h := &MinHeap{}
			heap.Init(h)
			var combinedAllocKey uint64
			var combinedAllocVal info.CombinedAllocInfoRaw
			for combinedAllocsMapIter.Next(&combinedAllocKey, &combinedAllocVal) {
				combinedInfo, err := info.GetCombinedAllocInfo(uint32(combinedAllocKey), combinedAllocVal)
				if err != nil {
					log.Printf("Failed to unmarshal combined alloc info: %v", err)
					continue
				}
				if combinedInfo.TotalSize > 0 {
					if h.Len() < nTopStacks {
						heap.Push(h, combinedInfo)
					} else if combinedInfo.TotalSize > (*h)[0].TotalSize {
						heap.Pop(h)
						heap.Push(h, combinedInfo)
					}
				}
			}
			if err := combinedAllocsMapIter.Err(); err != nil {
				log.Printf("Iterator error: %v", err)
			}

			topStacks := make([]*info.CombinedAllocInfo, h.Len())
			allocs := make(map[uint32][]info.AllocInfo)
			for i := len(topStacks) - 1; i >= 0; i-- {
				topStacks[i] = heap.Pop(h).(*info.CombinedAllocInfo)
				allocs[topStacks[i].StackId] = []info.AllocInfo{}
			}

			allocsIter := allocsMap.Iterate()
			var allocKey uint64
			var allocRawVal info.AllocInfoRaw
			for allocsIter.Next(&allocKey, &allocRawVal) {
				if allocs[allocRawVal.StackId] != nil {
					allocs[allocRawVal.StackId] = append(allocs[allocRawVal.StackId], info.GetAllocInfo(allocKey, allocRawVal))
				}
			}

			fmt.Printf("[%s] Top %d stacks with outstanding allocations:\n", time.Now().Format(time.RFC3339), len(topStacks))
			if err != nil {
				log.Printf("Failed to create symbol resolver: %v", err)
				continue
			}

			for _, stackInfo := range topStacks {
				fmt.Printf("%d Bytes in %d allocations from stack\n", stackInfo.TotalSize, stackInfo.NumberOfAllocs)
				if pid > 0 {
					stackFrames, err := getUserspaceStackTrace(stackInfo.StackId, probe.bpfObjects.probeMaps.StackTraces, pid)
					if err != nil {
						log.Printf("Failed to get stack trace for stack id %d: %v", stackInfo.StackId, err)
						continue
					}
					for _, frame := range stackFrames {
						fmt.Printf("    %s\n", frame)
					}
				} else {
					fmt.Printf("Not yet supported")
				}
			}
			fmt.Println("===========================")
			time.Sleep(5 * time.Second)
		}
	}()

	<-ctx.Done()
	return probe.Close()
}
