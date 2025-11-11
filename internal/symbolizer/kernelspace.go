package symbolizer

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

func LoadKernelSymbolsFromKallsyms() (map[uint64]string, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	syms := make(map[uint64]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		// format: addr type name [module]
		if len(fields) < 3 {
			continue
		}
		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			continue
		}
		name := fields[2]
		syms[addr] = name
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return syms, nil
}

// NewKernelResolverFromKallsyms returns a resolver with single mapping covering whole address space.
func NewKernelResolverFromKallsyms() (*SymbolResolver, error) {
	syms, err := LoadKernelSymbolsFromKallsyms()
	if err != nil {
		return nil, err
	}
	entry := ProcMapEntry{
		start:   0,
		end:     ^uint64(0),
		offset:  0,
		path:    "/proc/kallsyms",
		symbols: syms,
	}
	return &SymbolResolver{mappings: []ProcMapEntry{entry}}, nil
}

// NewKernelResolverFromVmlinux loads symbols from a vmlinux ELF file (if available).
func NewKernelResolverFromVmlinux(vmlinuxPath string) (*SymbolResolver, error) {
	syms, err := loadSymbols(vmlinuxPath)
	if err != nil {
		return nil, err
	}
	entry := ProcMapEntry{
		start:   0,
		end:     ^uint64(0),
		offset:  0,
		path:    vmlinuxPath,
		symbols: syms,
	}
	return &SymbolResolver{mappings: []ProcMapEntry{entry}}, nil
}
