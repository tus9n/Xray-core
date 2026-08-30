// Package torrentguard detects BitTorrent-shaped traffic that no signature
// sniffer can see (encrypted MSE/PE handshakes, protocol obfuscation) by
// watching connection topology instead of payload bytes: a P2P swarm can't
// avoid opening many parallel connections to distinct remote peers with
// roughly symmetric upload/download, no matter how the payload is
// disguised.
//
// Two independent thresholds, both evaluated and acted on locally — no
// round-trip to the panel, mirrors Marzban's own app/jobs/ip_abuse_alert.py
// (alert-threshold vs ban-threshold, both instant, both fire from a single
// pass over the data):
//   - max_unique_ips_alert: crossing it only logs TORRENTGUARD_ALERT — a
//     signal for the panel to notify admins, traffic is untouched.
//   - max_unique_ips_enforce (> alert): crossing it logs
//     TORRENTGUARD_ENFORCED and starts throttling/dropping this
//     (username, source-IP) pair's traffic immediately. Never auto-clears
//     once set (matches ip_abuse_alert.py's autoban: an admin has to lift
//     it, here via the exempt_users push).
//
// Counted per (username, client source-IP), not per account: several real
// people sharing one Marzban account from different networks/IPs don't sum
// into each other's counters, so a family/shared account isn't punished for
// one member's unrelated activity.
//
// Fail-open by design, same posture as common/speedlimit: any error (no
// config pushed yet, disabled, exempt) means NO action, never a dropped or
// throttled connection.
package torrentguard

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"encoding/json"
	"io"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/localpush"

	"golang.org/x/time/rate"
)

const idleTTL = 5 * time.Minute

// ── remote config shape (pushed by the panel via localpush) ────────────────

type remoteConfig struct {
	Enabled             bool     `json:"enabled"`
	WindowSec           int      `json:"window_sec"`
	SymmetryRatioMin    float64  `json:"symmetry_ratio_min"`
	MaxUniqueIPsAlert   int      `json:"max_unique_ips_alert"`
	MaxUniqueIPsEnforce int      `json:"max_unique_ips_enforce"`
	Action              string   `json:"action"` // "throttle" | "drop"
	ThrottleMbps        float64  `json:"throttle_mbps"`
	ExemptUsers         []string `json:"exempt_users"`
}

var (
	cfgMu       sync.RWMutex
	cfg         remoteConfig
	exemptSet   map[string]struct{}
	hasConfig   bool
	hasConfigMu sync.RWMutex
)

func handlePush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var next remoteConfig
	if err := json.Unmarshal(body, &next); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	exempt := make(map[string]struct{}, len(next.ExemptUsers))
	for _, u := range next.ExemptUsers {
		exempt[u] = struct{}{}
	}

	cfgMu.Lock()
	cfg = next
	exemptSet = exempt
	cfgMu.Unlock()

	// A fresh exempt list clears any standing enforcement for those users —
	// matches ip_abuse_alert.py's "admin lifts the ban manually" semantics:
	// the panel's own exempt/clear action is that manual lift, delivered as
	// a push same as everything else here.
	clearEnforcementFor(exempt)

	hasConfigMu.Lock()
	hasConfig = true
	hasConfigMu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func init() {
	localpush.Register("/torrent-guard", handlePush)
	if localpush.IsRunCommand() {
		go idleSweeper()
	}
}

// Enabled reports whether this node has ever received a torrent-guard push
// AND the pushed config has enabled=true.
func Enabled() bool {
	hasConfigMu.RLock()
	got := hasConfig
	hasConfigMu.RUnlock()
	if !got {
		return false
	}
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg.Enabled
}

func isExempt(username string) bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if exemptSet == nil {
		return false
	}
	_, ok := exemptSet[username]
	return ok
}

func snapshot() remoteConfig {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	return cfg
}

// ── per (username, source-IP) sliding-window state ─────────────────────────

// ConnHandle is returned by RecordOpen and passed to TrackWriter; nil means
// torrentguard is disabled or this user is exempt — callers must treat a
// nil handle as "do nothing" (TrackWriter/EnforceWriter both no-op on nil).
type ConnHandle struct {
	state     *userState
	destIP    string
	openedAt  int64
	bytesUp   int64 // atomic
	bytesDown int64 // atomic
}

type userState struct {
	mu       sync.Mutex
	conns    []*ConnHandle
	enforced atomic.Bool
	lastUsed int64 // unix seconds, only bumped under mu

	limiter *rate.Limiter // lazily created only once enforced+action=="throttle"
}

func key(username, sourceIP string) string {
	return username + "\x00" + sourceIP
}

var (
	regMu sync.Mutex
	reg   = map[string]*userState{}
)

func getOrCreateState(k string) *userState {
	regMu.Lock()
	defer regMu.Unlock()
	s, ok := reg[k]
	if !ok {
		s = &userState{}
		reg[k] = s
	}
	return s
}

func clearEnforcementFor(exempt map[string]struct{}) {
	if len(exempt) == 0 {
		return
	}
	regMu.Lock()
	defer regMu.Unlock()
	for k, s := range reg {
		for u := range exempt {
			if len(k) > len(u) && k[:len(u)] == u && k[len(u)] == 0 {
				s.enforced.Store(false)
			}
		}
	}
}

func idleSweeper() {
	for range time.Tick(idleTTL) {
		cutoff := time.Now().Add(-idleTTL).Unix()
		regMu.Lock()
		for k, s := range reg {
			s.mu.Lock()
			idle := s.lastUsed < cutoff
			s.mu.Unlock()
			if idle {
				delete(reg, k)
			}
		}
		regMu.Unlock()
	}
}

// RecordOpen registers a newly-dialed outbound connection for
// (username, sourceIP), prunes connections outside the sliding window, and
// evaluates both thresholds. Returns nil if disabled/exempt/no config yet —
// callers must skip TrackWriter/EnforceWriter wrapping entirely on nil,
// same fail-open contract as speedlimit.LimitWriter.
func RecordOpen(ctx context.Context, username, sourceIP, destIP string) *ConnHandle {
	if username == "" || !Enabled() || isExempt(username) {
		return nil
	}
	c := snapshot()
	windowSec := c.WindowSec
	if windowSec <= 0 {
		windowSec = 20
	}

	s := getOrCreateState(key(username, sourceIP))
	now := time.Now().Unix()

	handle := &ConnHandle{state: s, destIP: destIP, openedAt: now}

	s.mu.Lock()
	cutoff := now - int64(windowSec)
	kept := s.conns[:0]
	for _, e := range s.conns {
		if e.openedAt >= cutoff {
			kept = append(kept, e)
		}
	}
	s.conns = append(kept, handle)
	s.lastUsed = now
	conns := append([]*ConnHandle(nil), s.conns...)
	s.mu.Unlock()

	evaluate(username, sourceIP, s, conns, c)
	return handle
}

func uniqueDestIPs(conns []*ConnHandle) int {
	seen := make(map[string]struct{}, len(conns))
	for _, e := range conns {
		seen[e.destIP] = struct{}{}
	}
	return len(seen)
}

// symmetricFraction is the share of connections (that have actually moved
// bytes in both directions) whose up/down ratio is within symmetryRatioMin
// of 1:1. Connections with no traffic yet in one direction are excluded
// from the denominator — a brand-new connection with 0 downloaded bytes
// isn't evidence either way, and would otherwise dilute the signal exactly
// when a swarm is actively opening new peers.
func symmetricFraction(conns []*ConnHandle, symmetryRatioMin float64) float64 {
	var withTraffic, symmetric int
	for _, e := range conns {
		up := atomic.LoadInt64(&e.bytesUp)
		down := atomic.LoadInt64(&e.bytesDown)
		if up == 0 || down == 0 {
			continue
		}
		withTraffic++
		lo, hi := up, down
		if lo > hi {
			lo, hi = hi, lo
		}
		if float64(lo)/float64(hi) >= symmetryRatioMin {
			symmetric++
		}
	}
	if withTraffic == 0 {
		return 0
	}
	return float64(symmetric) / float64(withTraffic)
}

func evaluate(username, sourceIP string, s *userState, conns []*ConnHandle, c remoteConfig) {
	uniqueIPs := uniqueDestIPs(conns)
	symRatioMin := c.SymmetryRatioMin
	if symRatioMin <= 0 {
		symRatioMin = 0.6
	}
	symFrac := symmetricFraction(conns, symRatioMin)
	// Require a majority of active connections to look symmetric — a swarm's
	// defining trait — not just a handful out of a much larger unrelated set.
	const symFracMin = 0.5
	symmetric := symFrac >= symFracMin

	alertThreshold := c.MaxUniqueIPsAlert
	enforceThreshold := c.MaxUniqueIPsEnforce
	if alertThreshold <= 0 || enforceThreshold <= 0 || enforceThreshold <= alertThreshold {
		return // misconfigured push — fail open rather than guess
	}

	if !symmetric {
		return
	}

	if uniqueIPs >= enforceThreshold {
		if !s.enforced.Swap(true) {
			errors.LogWarning(context.Background(),
				"TORRENTGUARD_ENFORCED user=", username, " src=", sourceIP,
				" uniqueIPs=", uniqueIPs, " symmetry=", symFrac)
		}
		return
	}
	if uniqueIPs > alertThreshold {
		errors.LogWarning(context.Background(),
			"TORRENTGUARD_ALERT user=", username, " src=", sourceIP,
			" uniqueIPs=", uniqueIPs, " symmetry=", symFrac)
	}
}

// ── writers ─────────────────────────────────────────────────────────────

type trackWriter struct {
	buf.Writer
	handle *ConnHandle
	up     bool
}

func (w *trackWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := int64(mb.Len()); n > 0 && w.handle != nil {
		if w.up {
			atomic.AddInt64(&w.handle.bytesUp, n)
		} else {
			atomic.AddInt64(&w.handle.bytesDown, n)
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// TrackWriter wraps w so bytes moved over handle's connection are counted
// for the symmetry calculation. No-op (returns w unchanged) if handle is
// nil, i.e. RecordOpen decided not to track this connection at all.
func TrackWriter(w buf.Writer, handle *ConnHandle, up bool) buf.Writer {
	if handle == nil {
		return w
	}
	return &trackWriter{Writer: w, handle: handle, up: up}
}

type enforceWriter struct {
	buf.Writer
	ctx          context.Context
	handle       *ConnHandle
	throttleMbps float64
	up           bool
}

func (w *enforceWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if w.handle != nil && w.handle.state.enforced.Load() {
		if n := int(mb.Len()); n > 0 {
			limiter := w.handle.state.limiterFor(w.throttleMbps)
			if limiter != nil {
				burst := limiter.Burst()
				for n > 0 {
					take := n
					if take > burst {
						take = burst
					}
					if err := limiter.WaitN(w.ctx, take); err != nil {
						break // fail-open: never hang the proxy on our own account
					}
					n -= take
				}
			}
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (s *userState) limiterFor(throttleMbps float64) *rate.Limiter {
	if throttleMbps <= 0 {
		throttleMbps = 0.5
	}
	bytesPerSec := throttleMbps * 1000000 / 8
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.limiter == nil {
		burst := int(bytesPerSec * 0.2)
		if burst < 16*1024 {
			burst = 16 * 1024
		}
		s.limiter = rate.NewLimiter(rate.Limit(bytesPerSec), burst)
	}
	return s.limiter
}

// EnforceWriter wraps w so writes are throttled once handle's
// (username, source-IP) has crossed the enforce threshold. No-op until
// then, and no-op forever if action isn't "throttle" (a "drop" action is
// handled by ShouldDrop at dial time instead, before any writer exists).
func EnforceWriter(ctx context.Context, w buf.Writer, handle *ConnHandle, up bool) buf.Writer {
	if handle == nil {
		return w
	}
	c := snapshot()
	if c.Action == "drop" {
		return w // drop is enforced at dial time, see ShouldDrop
	}
	return &enforceWriter{Writer: w, ctx: ctx, handle: handle, throttleMbps: c.ThrottleMbps, up: up}
}

// ShouldDrop reports whether a brand-new connection for (username, sourceIP)
// should be refused outright — only true once that pair has crossed the
// enforce threshold AND the pushed action is "drop". Already-open
// connections are never killed retroactively; this only gates new dials,
// matching ip_abuse_alert.py's "existing sessions ride out, new activity is
// what actually gets refused" posture.
func ShouldDrop(username, sourceIP string) bool {
	if username == "" || !Enabled() {
		return false
	}
	if snapshot().Action != "drop" {
		return false
	}
	regMu.Lock()
	s, ok := reg[key(username, sourceIP)]
	regMu.Unlock()
	if !ok {
		return false
	}
	return s.enforced.Load()
}
