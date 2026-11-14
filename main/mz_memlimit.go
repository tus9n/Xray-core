package main

import (
	"bufio"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// Marzban patch: soft heap ceiling. Without it the Go heap may grow to about
// twice the live data under bursts and stay there; on 2 GB nodes that memory
// is shared with haproxy, nginx and the kernel's network buffers. A soft
// limit of 25% of RAM (min 256 MiB) only makes the GC work harder near it —
// typical heaps (80–150 MiB) never reach it. GOMEMLIMIT overrides.
func init() {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	total := memTotalBytes()
	if total <= 0 {
		return
	}
	limit := total / 4
	if limit < 256<<20 {
		limit = 256 << 20
	}
	debug.SetMemoryLimit(limit)
}

func memTotalBytes() int64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}
