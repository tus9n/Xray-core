// Package speedlimit implements Marzban's per-user/per-inbound bandwidth
// caps INSIDE xray-core, at the point data is actually copied for a proxied
// connection — as opposed to the external tc/flower-based node daemon
// (speed_shaper.py), which has to reactively install a kernel packet filter
// after seeing a connection in xray's access log. For inbounds where a
// client can open hundreds of short-lived parallel connections within
// seconds (verified live: XHTTP upload behind a CDN-fronted reverse proxy
// opened 500+ ports in 30s, most too short-lived for a reactive filter to
// ever attach), that reaction lag lets the bulk of the traffic bypass the
// external shaper entirely. Limiting bytes here instead needs no reaction
// time and no network-level address matching at all — by the time any byte
// reaches this package, xray has already resolved exactly which user it
// belongs to.
//
// Fail-open by design everywhere: any error (no config pushed yet, unknown
// user/tag) results in NO limiting, never a blocked or dropped connection.
// This is a bandwidth cap, not an access control — the failure mode of "no
// limit" is always safe; the failure mode of "connection hangs" is not.
//
// Config delivery: PUSHED, not polled. Marzban-node's own process (node.py)
// runs a plain HTTP listener on 127.0.0.1 (see LocalServerAddr) that
// receives a POST whenever an admin changes a limit in the panel, AND right
// after every xray-core start/restart (node.py re-sends whatever it last
// had, since a restarted xray-core's in-memory cfg here is empty) — so
// there's never a polling loop or a stored credential on this side at all;
// this package only ever WRITES to on incoming request, never dials out.
package speedlimit

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	idleTTL = 5 * time.Minute
	// LocalServerAddr — 127.0.0.1-only by construction (net.Listen below),
	// nothing outside this host can ever reach it, hence no auth needed.
	LocalServerAddr = "127.0.0.1:62053"
)

// hasConfig flips true on the first successfully received push — Enabled()
// (and therefore WaitN/LimitWriter) stays a no-op until then, same
// fail-open intent the old env-gated "enabled" flag had.
var (
	hasConfig   bool
	hasConfigMu sync.RWMutex
)

// ── remote config shape (mirrors GET /api/speed-limits-config) ─────────────
type nodeLimits struct {
	DownMbps       *float64 `json:"down_mbps"`
	UpMbps         *float64 `json:"up_mbps"`
	PerUserDownMbps *float64 `json:"per_user_down_mbps"`
	PerUserUpMbps   *float64 `json:"per_user_up_mbps"`
}

type inboundLimits struct {
	DownMbps *float64 `json:"down_mbps"`
	UpMbps   *float64 `json:"up_mbps"`
}

type userLimits struct {
	DownMbps *float64 `json:"down_mbps"`
	UpMbps   *float64 `json:"up_mbps"`
	// Scope: "total" — DownMbps/UpMbps (and, if unset here, Default) is one
	// bucket shared across every inbound tag this user is active on, on this
	// node. "per_inbound" (or unset) — the current/original behaviour: each
	// tag gets its own independent bucket, so N simultaneous inbounds give
	// the user up to N× the nominal cap in aggregate. Never applies to
	// Inbounds[tag]/UserInboundOverrides — those stay per-tag by definition
	// regardless of Scope, see effectiveScope/localLimitBytesPerSec.
	Scope *string `json:"scope"`
}

type remoteConfig struct {
	Default struct {
		DownMbps *float64 `json:"down_mbps"`
		UpMbps   *float64 `json:"up_mbps"`
	} `json:"default"`
	// DefaultScope — fallback Scope (see userLimits.Scope) for any user that
	// doesn't set its own; "" behaves as "per_inbound".
	DefaultScope         string                            `json:"default_scope"`
	Node                 *nodeLimits                       `json:"node"`
	Inbounds             map[string]inboundLimits          `json:"inbounds"`
	Users                map[string]userLimits             `json:"users"`
	UserInboundOverrides map[string]map[string]userLimits `json:"user_inbound_overrides"`
}

var (
	cfgMu sync.RWMutex
	cfg   remoteConfig
)

// startLocalServer listens on 127.0.0.1 only (net.Listen with that literal
// address — never 0.0.0.0) for node.py's pushes. Runs for the lifetime of
// the process. Retries the bind for a while before giving up: with
// network_mode: host on the node side, a container restart briefly races
// the dying old xray-core process's socket against this one's — losing
// that race used to be permanent (this function only ever ran once, at
// startup), silently disabling the limiter for the process's entire
// lifetime until the next restart happened to win the race instead. A
// missing push endpoint after retries are exhausted just means limits
// stay at whatever they were, the same fail-open posture as everywhere
// else here.
func startLocalServer() {
	var ln net.Listener
	var err error
	for attempt := 0; attempt < 15; attempt++ {
		ln, err = net.Listen("tcp", LocalServerAddr)
		if err == nil {
			break
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		errors.LogWarning(context.Background(), "speedlimit: failed to bind local push listener on ", LocalServerAddr, " after retries: ", err)
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/speed-limits", func(w http.ResponseWriter, r *http.Request) {
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
		cfgMu.Lock()
		cfg = next
		cfgMu.Unlock()
		hasConfigMu.Lock()
		hasConfig = true
		hasConfigMu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	go http.Serve(ln, mux) //nolint:errcheck
}

func mbpsToBytesPerSec(mbps float64) float64 {
	return mbps * 1000000 / 8
}

func minPositive(vals ...*float64) *float64 {
	var best *float64
	for _, v := range vals {
		if v == nil || *v <= 0 {
			continue
		}
		if best == nil || *v < *best {
			best = v
		}
	}
	return best
}

// effectiveScope reports whether username's default/user-tier cap should be
// one bucket shared across every inbound tag ("total") rather than the
// original independent-bucket-per-tag behaviour. Per-user Scope wins over
// DefaultScope; both empty/unset means "per_inbound" (unchanged behaviour).
func effectiveScope(username string) bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if u, ok := cfg.Users[username]; ok && u.Scope != nil && *u.Scope != "" {
		return *u.Scope == "total"
	}
	return cfg.DefaultScope == "total"
}

// localLimitBytesPerSec is the min() of every applicable tag-scoped cap —
// node and this specific inbound/user-inbound-override — deliberately
// EXCLUDING the user/default tier (see userDefaultLimitBytesPerSec). Always
// enforced per (username, tag, direction), regardless of Scope: an explicit
// per-inbound number always stays independent of what other inbounds the
// user has open, by design (see userLimits.Scope doc and the admin UI's own
// "Лимит на конкретном инбаунде" tooltip).
// explicitUnlimited reports whether this user has an explicit 0 override
// for this exact tag — "unlimited on this inbound", which must suppress the
// user/default fallback too (matches the pre-Scope original behaviour).
func explicitUnlimitedOverride(username, tag string, up bool) bool {
	cfgMu.RLock()
	defer cfgMu.RUnlock()
	if overrides, ok := cfg.UserInboundOverrides[username]; ok {
		if ui, ok := overrides[tag]; ok {
			return zeroOrNil(ui, up)
		}
	}
	return false
}

func localLimitBytesPerSec(username, tag string, up bool) *float64 {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	var node, inbound, userInbound *float64
	if cfg.Node != nil {
		if up {
			node = minPositive(cfg.Node.UpMbps, cfg.Node.PerUserUpMbps)
		} else {
			node = minPositive(cfg.Node.DownMbps, cfg.Node.PerUserDownMbps)
		}
	}
	if ib, ok := cfg.Inbounds[tag]; ok {
		if up {
			inbound = ib.UpMbps
		} else {
			inbound = ib.DownMbps
		}
	}
	if overrides, ok := cfg.UserInboundOverrides[username]; ok {
		if ui, ok := overrides[tag]; ok {
			if up {
				userInbound = ui.UpMbps
			} else {
				userInbound = ui.DownMbps
			}
		}
	}

	limitMbps := minPositive(node, inbound, userInbound)
	if limitMbps == nil || *limitMbps <= 0 {
		return nil
	}
	bps := mbpsToBytesPerSec(*limitMbps)
	return &bps
}

// userDefaultLimitBytesPerSec is username's own cap, falling back to the
// global default unless username (or its per-inbound override, checked by
// the caller separately) explicitly set 0 ("unlimited", not "unset").
// Ignores tag entirely — same number regardless of which inbound asks.
func userDefaultLimitBytesPerSec(username string, up bool) *float64 {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	u, userSet := cfg.Users[username]
	var user *float64
	if userSet {
		if up {
			user = u.UpMbps
		} else {
			user = u.DownMbps
		}
	}
	limitMbps := user
	if limitMbps == nil {
		if userSet && zeroOrNil(u, up) {
			return nil // explicit 0 at user level means unlimited
		}
		var def *float64
		if up {
			def = cfg.Default.UpMbps
		} else {
			def = cfg.Default.DownMbps
		}
		limitMbps = def
	}
	if limitMbps == nil || *limitMbps <= 0 {
		return nil
	}
	bps := mbpsToBytesPerSec(*limitMbps)
	return &bps
}

// effectiveLimitBytesPerSec is the original (pre-Scope) combined cap: min()
// of node/inbound/user/user-inbound-override, default as fallback. Used
// as-is for the "per_inbound" (default) scope, where everything shares one
// per-tag bucket exactly like before Scope existed.
func effectiveLimitBytesPerSec(username, tag string, up bool) *float64 {
	local := localLimitBytesPerSec(username, tag, up)
	if explicitUnlimitedOverride(username, tag, up) {
		// Explicit 0 on this exact inbound overrides the user/default tier
		// too, same as before Scope existed — a bare 0 (no other number set
		// on this override) already made local nil, so this only matters
		// when it's the SOLE thing set (nothing to combine with anyway).
		return local
	}
	// minPositive skips nils, so this is correct whether userDefault is nil
	// because nothing applies or because of an explicit unlimited-0 at user
	// level (userDefaultLimitBytesPerSec already resolves that distinction).
	return minPositive(local, userDefaultLimitBytesPerSec(username, up))
}

func zeroOrNil(u userLimits, up bool) bool {
	v := u.DownMbps
	if up {
		v = u.UpMbps
	}
	return v != nil && *v == 0
}

// ── shared limiter registry, keyed by (username, tag, direction) ───────────
// One limiter per user+inbound+direction, shared across every concurrent
// connection that user has open on that inbound — mirrors _GroupState in
// speed_shaper.py: without this, a client with 100 parallel connections
// would get 100 independent buckets and the effective aggregate cap would
// scale with connection count instead of staying fixed.
type entry struct {
	limiter  *rate.Limiter
	lastUsed int64 // unix seconds, atomic-free: only ever bumped under regMu
}

var (
	regMu sync.Mutex
	reg   = map[string]*entry{}
)

func key(username, tag, dir string) string {
	return username + "\x00" + tag + "\x00" + dir
}

func init() {
	// Go runs every imported package's init() unconditionally at process
	// start, before main() ever looks at os.Args — so a bare `xray version`
	// or `xray -test` (e.g. the node install/update script's own "Installed:
	// $(xray-real version)" banner) triggered this same bind attempt as a
	// real `xray run`, and predictably failed with "address already in use"
	// against the actually-running instance's listener. Harmless (this
	// process exits right after printing the version anyway) but confusing
	// log noise, and needless work — only start the listener for `run`.
	isRun := false
	for _, a := range os.Args[1:] {
		if a == "run" {
			isRun = true
			break
		}
		if len(a) > 0 && a[0] != '-' {
			break // first non-flag arg is the subcommand; anything but "run" means don't bind
		}
	}
	if !isRun {
		return
	}
	startLocalServer()
	go idleSweeper()
}

func idleSweeper() {
	for range time.Tick(idleTTL) {
		cutoff := time.Now().Add(-idleTTL).Unix()
		regMu.Lock()
		for k, e := range reg {
			if e.lastUsed < cutoff {
				delete(reg, k)
			}
		}
		regMu.Unlock()
	}
}

// globalTag is the key()'s tag component for the "total" scope's
// shared-across-all-inbounds bucket — never a legal xray inbound tag
// (those come from config, always non-empty), so it can't collide with any
// real per-tag bucket.
const globalTag = ""

func getLimiter(k string, bytesPerSec float64) *rate.Limiter {
	regMu.Lock()
	defer regMu.Unlock()
	e, ok := reg[k]
	now := time.Now()
	if !ok {
		// Burst = ~0.2s worth of the cap (min 16KiB) — enough to not choke a
		// single small request/response to a trickle, small enough that a
		// fresh connection can't blow straight through the cap before the
		// bucket empties.
		burst := int(bytesPerSec * 0.2)
		if burst < 16*1024 {
			burst = 16 * 1024
		}
		e = &entry{limiter: rate.NewLimiter(rate.Limit(bytesPerSec), burst)}
		reg[k] = e
	} else if e.limiter.Limit() != rate.Limit(bytesPerSec) {
		// Limit changed since last fetch (admin edited it in the panel) —
		// update in place so already-open connections pick it up without
		// needing to be torn down and reconnected.
		e.limiter.SetLimit(rate.Limit(bytesPerSec))
	}
	e.lastUsed = now.Unix()
	return e.limiter
}

// drainLimiter blocks until n bytes' worth of tokens are available from
// limiter. rate.Limiter caps WaitN's n at its own burst size — a single
// chunk larger than the burst would otherwise always error out instead of
// just taking longer to drain. buf.Buffer chunks are bounded (2000-ish
// bytes) in practice, well under any realistic burst, but split defensively
// anyway rather than assume that never changes upstream.
func drainLimiter(ctx context.Context, limiter *rate.Limiter, n int) {
	burst := limiter.Burst()
	for n > 0 {
		take := n
		if take > burst {
			take = burst
		}
		if err := limiter.WaitN(ctx, take); err != nil {
			return // fail-open: context cancelled or similar — never block the proxy on our own account
		}
		n -= take
	}
}

// WaitN blocks until n bytes' worth of tokens are available for
// username+tag+direction, or returns immediately if no limit applies
// (unlimited, or no config has ever been pushed to this node yet).
// Direction: true for upload (client->outbound), false for download
// (outbound->client).
//
// Under Scope=="total" (see effectiveScope), the user/default tier is
// enforced through a SECOND bucket shared across every tag that user is
// active on — layered on top of (not instead of) the tag-scoped bucket
// that still enforces node/inbound/user-inbound-override caps. Both are
// drained independently, so actual throughput is capped by whichever is
// more restrictive at any given moment.
func WaitN(ctx context.Context, username, tag string, up bool, n int) error {
	if !Enabled() || username == "" || n <= 0 {
		return nil
	}
	dir := "down"
	if up {
		dir = "up"
	}

	if effectiveScope(username) {
		if bps := localLimitBytesPerSec(username, tag, up); bps != nil {
			drainLimiter(ctx, getLimiter(key(username, tag, dir), *bps), n)
		}
		if !explicitUnlimitedOverride(username, tag, up) {
			if bps := userDefaultLimitBytesPerSec(username, up); bps != nil {
				drainLimiter(ctx, getLimiter(key(username, globalTag, dir), *bps), n)
			}
		}
		return nil
	}

	if bps := effectiveLimitBytesPerSec(username, tag, up); bps != nil {
		drainLimiter(ctx, getLimiter(key(username, tag, dir), *bps), n)
	}
	return nil
}

// limitedWriter wraps a buf.Writer so every WriteMultiBuffer call first
// blocks (via WaitN) for however many tokens its byte length costs, then
// passes through unchanged. Zero overhead when unlimited (WaitN no-ops).
type limitedWriter struct {
	buf.Writer
	ctx      context.Context
	username string
	tag      string
	up       bool
}

func (w *limitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := int(mb.Len()); n > 0 {
		_ = WaitN(w.ctx, w.username, w.tag, w.up, n) // fail-open, see WaitN doc
	}
	return w.Writer.WriteMultiBuffer(mb)
}

// LimitWriter wraps w so every write is throttled to the effective
// username+tag+direction cap, if any (see WaitN). email is xray's raw
// inbound.User.Email ("{id}.{username}[#tag]") — normalized internally.
//
// Deliberately does NOT gate on Enabled() here: unlike the old poll design
// (where enabled was fixed true from process start, before any traffic
// flowed), the push design's Enabled() can flip from false to true AFTER a
// connection is already established — right after a restart, before
// node.py's post-restart push has landed. Gating the wrap here would freeze
// that connection unwrapped for its entire (possibly long-lived XHTTP/
// VLESS) lifetime even once a push arrives. WaitN() already checks
// Enabled() on every call, so wrapping unconditionally costs one no-op
// function call per write when disabled — negligible, and always correct.
func LimitWriter(ctx context.Context, w buf.Writer, email, tag string, up bool) buf.Writer {
	if email == "" {
		return w
	}
	return &limitedWriter{Writer: w, ctx: ctx, username: Username(email), tag: tag, up: up}
}

// Enabled reports whether this node has ever received a speed-limits push
// from node.py yet — i.e. whether this package does anything at all right
// now. False right after a fresh xray-core start, until node.py's
// post-start push (or the next admin-triggered push) lands.
func Enabled() bool {
	hasConfigMu.RLock()
	defer hasConfigMu.RUnlock()
	return hasConfig
}

// Username normalizes xray's inbound.User.Email ("{id}.{username}" or
// "{id}.{username}#{tag}", see config.py: include_db_users) down to the bare
// username speed-limits-config.Users/UserInboundOverrides are keyed by.
func Username(email string) string {
	if idx := strings.IndexByte(email, '.'); idx >= 0 {
		email = email[idx+1:]
	}
	if idx := strings.IndexByte(email, '#'); idx >= 0 {
		email = email[:idx]
	}
	return email
}
