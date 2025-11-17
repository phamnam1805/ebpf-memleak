package symbolizer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
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

// KernelSymbolResolver resolves kernel symbols using kallsyms and optionally vmlinux for debug info
type KernelSymbolResolver struct {
	kallsyms    map[uint64]string
	vmlinuxPath string
}

// NewKernelSymbolResolver creates a resolver that uses kallsyms (always) and vmlinux (if available)
func NewKernelSymbolResolver(vmlinuxPath string) (*KernelSymbolResolver, error) {
	// Load kallsyms (always available and accurate for runtime addresses)
	kallsyms, err := LoadKernelSymbolsFromKallsyms()
	if err != nil {
		return nil, fmt.Errorf("failed to load kallsyms: %w", err)
	}

	// Check if vmlinux exists (optional, for debug info)
	if vmlinuxPath != "" {
		if _, err := os.Stat(vmlinuxPath); err != nil {
			vmlinuxPath = "" // Disable vmlinux if not found
		}
	}

	return &KernelSymbolResolver{
		kallsyms:    kallsyms,
		vmlinuxPath: vmlinuxPath,
	}, nil
}

// Resolve resolves a kernel address to symbol name and optionally source location
func (r *KernelSymbolResolver) Resolve(addr uint64) (string, error) {
	// Find the closest symbol from kallsyms
	var closestAddr uint64
	var closestSym string

	for symAddr, symName := range r.kallsyms {
		if symAddr <= addr && symAddr > closestAddr {
			closestAddr = symAddr
			closestSym = symName
		}
	}

	if closestSym == "" {
		return "", fmt.Errorf("symbol not found for address 0x%x", addr)
	}

	// If we have vmlinux, try to get source file:line info
	if r.vmlinuxPath != "" {
		// For kernel, addresses in kallsyms are already runtime addresses
		// We can use addr2line directly (no KASLR adjustment needed if using runtime addr)
		cmd := exec.Command("addr2line", "-e", r.vmlinuxPath, fmt.Sprintf("0x%x", addr))
		output, err := cmd.Output()
		if err == nil {
			fileLine := strings.TrimSpace(string(output))
			// log.Printf("addr2line output for 0x%x: %s", addr, fileLine)
			if fileLine != "??:?" && fileLine != "??:0" && fileLine != "" {
				return fmt.Sprintf("%s (%s)", closestSym, fileLine), nil
			}
		}
	}

	// Fallback to just symbol name
	if addr != closestAddr {
		// Show offset if not exact match
		offset := addr - closestAddr
		return fmt.Sprintf("%s+0x%x", closestSym, offset), nil
	}
	return closestSym, nil
}
