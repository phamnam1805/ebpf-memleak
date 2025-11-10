package symbolizer

import (
	"bufio"
	"debug/elf"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// https://github.com/naftalyava/ebpf_and_xdp_examples/blob/main/leak_detector/main.go

type ProcMapEntry struct {
	start, end uint64
	offset     uint64
	path       string
	symbols    map[uint64]string
}

type SymbolResolver struct {
	mappings []ProcMapEntry
}

func loadSymbols(path string) (map[uint64]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Parse the ELF file
	symbols := make(map[uint64]string)
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return nil, err
	}

	// Collect symbols from the symbol tables
	collectSymbols := func(syms []elf.Symbol) {
		for _, sym := range syms {
			if sym.Value == 0 || sym.Size == 0 {
				continue
			}
			symbols[sym.Value] = sym.Name
		}
	}

	// Read the symbols from the symbol table
	syms, err := elfFile.Symbols()
	if err == nil {
		collectSymbols(syms)
	}

	// Read the symbols from the dynamic symbol table
	dynSyms, err := elfFile.DynamicSymbols()
	if err == nil {
		collectSymbols(dynSyms)
	}

	return symbols, nil
}

func NewUserspaceSymbolResolver(mapsFile string) (*SymbolResolver, error) {
	f, err := os.Open(mapsFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	resolver := &SymbolResolver{}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		addresses := strings.Split(fields[0], "-")
		if len(addresses) != 2 {
			continue
		}
		start, err := strconv.ParseUint(addresses[0], 16, 64)
		if err != nil {
			continue
		}
		end, err := strconv.ParseUint(addresses[1], 16, 64)
		if err != nil {
			continue
		}
		offset, err := strconv.ParseUint(fields[2], 16, 64)
		if err != nil {
			continue
		}
		path := fields[5]
		if strings.HasPrefix(path, "/") && strings.Contains(fields[1], "x") {
			// Load symbols from the binary
			symbols, err := loadSymbols(path)
			if err != nil {
				continue
			}

			procMapEntry := ProcMapEntry{
				start:   start,
				end:     end,
				offset:  offset,
				path:    path,
				symbols: symbols,
			}
			resolver.mappings = append(resolver.mappings, procMapEntry)
			// log.Printf("Loaded %d symbols from %s", len(symbols), path)
		}
	}

	return resolver, nil
}

func demangleSymbol(sym string) string {
	cmd := exec.Command("c++filt", sym)
	output, err := cmd.Output()
	if err != nil {
		return sym // Return the original symbol if demangling fails
	}
	return strings.TrimSpace(string(output))
}

func (r *SymbolResolver) Resolve(pc uint64) (string, error) {
	for _, m := range r.mappings {
		// Adjust pc to file offset
		// println(m.start, m.end, pc)
		if pc >= m.start && pc < m.end {
			// Find the closest symbol
			fileOffset := pc - m.start + m.offset
			var closestAddr uint64
			var closestSym string
			for addr, sym := range m.symbols {
				if addr <= fileOffset && addr >= closestAddr {
					closestAddr = addr
					closestSym = sym
				}
			}
			if closestSym != "" {
				// Demangle the symbol
				demangledSym := demangleSymbol(closestSym)
				// return fmt.Sprintf("%s (%s)", demangledSym, m.path), nil

				cmd := exec.Command("addr2line", "-e", m.path, fmt.Sprintf("0x%x", fileOffset))
				output, err := cmd.Output()
				var fileLine string
				if err == nil {
					fileLine = strings.TrimSpace(string(output))
				} else {
					fileLine = "??:?"
				}

				if fileLine == "??:?" {
					fileLine = m.path
				}

				return fmt.Sprintf("%s (%s)", demangledSym, fileLine), nil
			}
		}
	}
	return "", fmt.Errorf("symbol not found for address 0x%x", pc)
}
