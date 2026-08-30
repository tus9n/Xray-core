// Package localpush is the shared 127.0.0.1-only HTTP listener that
// Marzban-node's process pushes config onto after an admin change in the
// panel, and right after every xray-core start/restart. Originally lived
// inside common/speedlimit (the first consumer, see its own history for
// the run-gating and retry-loop fixes folded in here); pulled out once a
// second consumer (common/torrentguard) needed the same delivery
// mechanism, so the package name doesn't lie about its scope, and both
// consumers share the run-gating/retry fixes instead of re-deriving them.
//
// Nothing outside this host can ever reach the listener (net.Listen binds
// 127.0.0.1 literally, never 0.0.0.0), so no auth is needed on top of that.
// Consumers only ever WRITE to their own path on an incoming request, never
// dial out from here.
package localpush

import (
	"context"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Addr is 127.0.0.1-only by construction (net.Listen below) — nothing
// outside this host can ever reach it, hence no auth needed.
const Addr = "127.0.0.1:62053"

var (
	once sync.Once
	mux  = http.NewServeMux()
)

// Register wires handler to path on the shared listener, arming it (once,
// lazily) on first call. Call from an init() in the consuming package —
// actual binding only happens for `xray run` (see isRunCommand), so a bare
// `xray version`/`xray -test` never touches the socket.
func Register(path string, handler http.HandlerFunc) {
	mux.HandleFunc(path, handler)
	once.Do(func() {
		if IsRunCommand() {
			go start()
		}
	})
}

// IsRunCommand mirrors speedlimit's original check: Go runs every imported
// package's init() unconditionally at process start, before main() ever
// looks at os.Args — so a bare `xray version` or `xray -test` (e.g. the
// node install/update script's own "Installed: $(xray-real version)"
// banner) would otherwise trigger the same bind attempt as a real
// `xray run`, and predictably fail with "address already in use" against
// the actually-running instance's listener. Harmless (that process exits
// right after printing the version anyway) but confusing log noise, and
// needless work — only bind for `run`.
func IsRunCommand() bool {
	for _, a := range os.Args[1:] {
		if a == "run" {
			return true
		}
		if len(a) > 0 && a[0] != '-' {
			return false // first non-flag arg is the subcommand; anything but "run" means don't bind
		}
	}
	return false
}

// start binds the shared listener for the lifetime of the process, retrying
// for ~30s before giving up: with network_mode: host on the node side, a
// container restart briefly races the dying old xray-core process's socket
// against this one's — losing that race without retrying used to be
// permanent (only ran once, at startup), silently disabling every consumer
// for the process's entire lifetime. A missing push endpoint after retries
// are exhausted just means every consumer's config stays at whatever it
// was, the same fail-open posture each of them already has individually.
func start() {
	var ln net.Listener
	var err error
	for attempt := 0; attempt < 15; attempt++ {
		ln, err = net.Listen("tcp", Addr)
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		errors.LogWarning(context.Background(), "localpush: failed to bind shared push listener on ", Addr, " after retries: ", err)
		return
	}
	go http.Serve(ln, mux) //nolint:errcheck
}
