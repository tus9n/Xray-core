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
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/localpush"

	"golang.org/x/time/rate"
)

const idleTTL = 5 * time.Minute

// LocalServerAddr — kept for anything still referencing it — is just an
// alias to the shared listener's address; see common/localpush for the
// actual bind/retry/run-gating logic (now shared with common/torrentguard).
const LocalServerAddr = localpush.Addr

// ── remote config shape (mirrors GET /api/speed-limits-config) ─────────────
type nodeLimits struct {
	DownMbps        *float64 `json:"down_mbps"`
	UpMbps          *float64 `json:"up_mbps"`
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
	DefaultScope         string                           `json:"default_scope"`
	Node                 *nodeLimits                      `json:"node"`
	Inbounds             map[string]inboundLimits         `json:"inbounds"`
	Users                map[string]userLimits            `json:"users"`
	UserInboundOverrides map[string]map[string]userLimits `json:"user_inbound_overrides"`
}

// configState is immutable after publication. Readers on the traffic hot
// path therefore need one atomic load instead of several independently
// locked map lookups for every ~2 KiB buffer.
type configState struct {
	cfg remoteConfig
}

var currentConfig atomic.Pointer[configState]

// Fast-path registrations are deliberately separate from the atomic read
// path. A config push is rare, while every proxied buffer consults the
// config. Serialising only pushes/registrations lets a push interrupt any
// already-spliced connection before a newly-added limit could be bypassed.
var (
	fastPathMu       sync.Mutex
	fastPathNextID   uint64
	fastPathWatchers = map[uint64]*fastPathWatcher{}
)

type fastPathWatcher struct {
	active    atomic.Bool
	interrupt func()
}

// handleSpeedLimitsPush is registered on the shared listener (see
// common/localpush) at "/speed-limits" — node.py POSTs here whenever an
// admin changes a limit in the panel, and again right after every
// xray-core start/restart.
func handleSpeedLimitsPush(w http.ResponseWriter, r *http.Request) {
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
	publishConfig(next)
	w.WriteHeader(http.StatusOK)
}

func publishConfig(next remoteConfig) {
	fastPathMu.Lock()
	currentConfig.Store(&configState{cfg: next})
	watchers := fastPathWatchers
	fastPathWatchers = map[uint64]*fastPathWatcher{}
	fastPathMu.Unlock()

	// Closing a net.Conn is non-blocking and is intentionally done outside
	// fastPathMu. It makes long-lived zero-copy connections reconnect and be
	// re-evaluated against the just-published limits.
	for _, watcher := range watchers {
		if watcher.active.Swap(false) {
			watcher.interrupt()
		}
	}
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
func effectiveScope(cfg *remoteConfig, username string) bool {
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
func explicitUnlimitedOverride(cfg *remoteConfig, username, tag string, up bool) bool {
	if overrides, ok := cfg.UserInboundOverrides[username]; ok {
		if ui, ok := overrides[tag]; ok {
			return zeroOrNil(ui, up)
		}
	}
	return false
}

func localLimitBytesPerSec(cfg *remoteConfig, username, tag string, up bool) float64 {
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
		return 0
	}
	return mbpsToBytesPerSec(*limitMbps)
}

// userDefaultLimitBytesPerSec is username's own cap, falling back to the
// global default unless username (or its per-inbound override, checked by
// the caller separately) explicitly set 0 ("unlimited", not "unset").
// Ignores tag entirely — same number regardless of which inbound asks.
func userDefaultLimitBytesPerSec(cfg *remoteConfig, username string, up bool) float64 {
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
			return 0 // explicit 0 at user level means unlimited
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
		return 0
	}
	return mbpsToBytesPerSec(*limitMbps)
}

// effectiveLimitBytesPerSec is the original (pre-Scope) combined cap: min()
// of node/inbound/user/user-inbound-override, default as fallback. Used
// as-is for the "per_inbound" (default) scope, where everything shares one
// per-tag bucket exactly like before Scope existed.
func effectiveLimitBytesPerSec(cfg *remoteConfig, username, tag string, up bool) float64 {
	local := localLimitBytesPerSec(cfg, username, tag, up)
	if explicitUnlimitedOverride(cfg, username, tag, up) {
		// Explicit 0 on this exact inbound overrides the user/default tier
		// too, same as before Scope existed — a bare 0 (no other number set
		// on this override) already made local nil, so this only matters
		// when it's the SOLE thing set (nothing to combine with anyway).
		return local
	}
	// minPositive skips nils, so this is correct whether userDefault is nil
	// because nothing applies or because of an explicit unlimited-0 at user
	// level (userDefaultLimitBytesPerSec already resolves that distinction).
	userDefault := userDefaultLimitBytesPerSec(cfg, username, up)
	if local == 0 || userDefault > 0 && userDefault < local {
		return userDefault
	}
	return local
}

func zeroOrNil(u userLimits, up bool) bool {
	v := u.DownMbps
	if up {
		v = u.UpMbps
	}
	return v != nil && *v == 0
}

// limitPlan is the fully resolved enforcement plan for one user, inbound and
// direction under one immutable config snapshot. tagBytesPerSec uses the
// per-inbound bucket; globalBytesPerSec uses Scope="total"'s cross-inbound
// bucket. Zero means that bucket does not apply.
type limitPlan struct {
	tagBytesPerSec    float64
	globalBytesPerSec float64
}

func resolveLimitPlan(cfg *remoteConfig, username, tag string, up bool) limitPlan {
	if cfg == nil || username == "" {
		return limitPlan{}
	}
	if effectiveScope(cfg, username) {
		plan := limitPlan{tagBytesPerSec: localLimitBytesPerSec(cfg, username, tag, up)}
		if !explicitUnlimitedOverride(cfg, username, tag, up) {
			plan.globalBytesPerSec = userDefaultLimitBytesPerSec(cfg, username, up)
		}
		return plan
	}
	return limitPlan{tagBytesPerSec: effectiveLimitBytesPerSec(cfg, username, tag, up)}
}

func (p limitPlan) limited() bool {
	return p.tagBytesPerSec > 0 || p.globalBytesPerSec > 0
}

// ── shared limiter registry, keyed by (username, tag, direction) ───────────
// One limiter per user+inbound+direction, shared across every concurrent
// connection that user has open on that inbound — mirrors _GroupState in
// speed_shaper.py: without this, a client with 100 parallel connections
// would get 100 independent buckets and the effective aggregate cap would
// scale with connection count instead of staying fixed.
type entry struct {
	limiter  *rate.Limiter
	lastUsed atomic.Int64 // unix seconds
	retired  atomic.Bool  // removed by idleSweeper; cached writers must refresh
}

var (
	regMu sync.Mutex
	reg   = map[string]*entry{}
)

func key(username, tag, dir string) string {
	return username + "\x00" + tag + "\x00" + dir
}

func init() {
	localpush.Register("/speed-limits", handleSpeedLimitsPush)
	// idleSweeper is just in-memory cleanup, but keep it gated the same way
	// the listener bind is (see localpush.IsRunCommand) — no point ticking
	// this for a one-shot `xray version`/`xray -test` invocation.
	if localpush.IsRunCommand() {
		go idleSweeper()
	}
}

func idleSweeper() {
	for range time.Tick(idleTTL) {
		cutoff := time.Now().Add(-idleTTL).Unix()
		regMu.Lock()
		for k, e := range reg {
			if e.lastUsed.Load() < cutoff {
				e.retired.Store(true)
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

func limiterBurst(bytesPerSec float64) int {
	burst := int(bytesPerSec * 0.2)
	if burst < 16*1024 {
		burst = 16 * 1024
	}
	return burst
}

func getLimiter(k string, bytesPerSec float64) *entry {
	regMu.Lock()
	defer regMu.Unlock()
	e, ok := reg[k]
	now := time.Now()
	if !ok {
		// Burst = ~0.2s worth of the cap (min 16KiB) — enough to not choke a
		// single small request/response to a trickle, small enough that a
		// fresh connection can't blow straight through the cap before the
		// bucket empties.
		burst := limiterBurst(bytesPerSec)
		e = &entry{limiter: rate.NewLimiter(rate.Limit(bytesPerSec), burst)}
		reg[k] = e
	} else if e.limiter.Limit() != rate.Limit(bytesPerSec) {
		// Limit changed since last fetch (admin edited it in the panel) —
		// update in place so already-open connections pick it up without
		// needing to be torn down and reconnected.
		e.limiter.SetLimitAt(now, rate.Limit(bytesPerSec))
		e.limiter.SetBurstAt(now, limiterBurst(bytesPerSec))
	}
	e.lastUsed.Store(now.Unix())
	return e
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

func drainEntry(ctx context.Context, e *entry, n int, now int64) {
	e.lastUsed.Store(now)
	drainLimiter(ctx, e.limiter, n)
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
	state := currentConfig.Load()
	if state == nil || username == "" || n <= 0 {
		return nil
	}
	dir := "down"
	if up {
		dir = "up"
	}

	plan := resolveLimitPlan(&state.cfg, username, tag, up)
	now := time.Now().Unix()
	if plan.tagBytesPerSec > 0 {
		drainEntry(ctx, getLimiter(key(username, tag, dir), plan.tagBytesPerSec), n, now)
	}
	if plan.globalBytesPerSec > 0 {
		drainEntry(ctx, getLimiter(key(username, globalTag, dir), plan.globalBytesPerSec), n, now)
	}
	return nil
}

// limitedWriter resolves and caches the shared limiter entries once per
// config generation. The steady-state limited path does no config locking or
// registry locking; the unlimited path is one atomic pointer comparison.
type limitedWriter struct {
	buf.Writer
	ctx      context.Context
	username string
	tag      string
	up       bool
	limits   atomic.Pointer[cachedLimitPlan]
}

type cachedLimitPlan struct {
	state   *configState
	entries [2]*entry
}

func (w *limitedWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	if n := int(mb.Len()); n > 0 {
		state := currentConfig.Load()
		limits := w.limits.Load()
		if limits == nil || state != limits.state || limits.entries[0] != nil && limits.entries[0].retired.Load() || limits.entries[1] != nil && limits.entries[1].retired.Load() {
			limits = w.resolve(state)
			w.limits.Store(limits)
		}
		if limits.entries[0] != nil || limits.entries[1] != nil {
			now := time.Now().Unix()
			for _, e := range limits.entries {
				if e != nil {
					drainEntry(w.ctx, e, n, now)
				}
			}
		}
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *limitedWriter) resolve(state *configState) *cachedLimitPlan {
	limits := &cachedLimitPlan{state: state}
	if state == nil {
		return limits
	}
	dir := "down"
	if w.up {
		dir = "up"
	}
	plan := resolveLimitPlan(&state.cfg, w.username, w.tag, w.up)
	if plan.tagBytesPerSec > 0 {
		limits.entries[0] = getLimiter(key(w.username, w.tag, dir), plan.tagBytesPerSec)
	}
	if plan.globalBytesPerSec > 0 {
		limits.entries[1] = getLimiter(key(w.username, globalTag, dir), plan.globalBytesPerSec)
	}
	return limits
}

// LimitWriter wraps w so every write is throttled to the effective
// username+tag+direction cap, if any (see WaitN). email is xray's raw
// inbound.User.Email ("{id}.{username}[#tag]") — normalized internally.
//
// Deliberately does NOT gate on Enabled() here: config can arrive or change
// after a connection is established. The wrapper's atomic generation check
// makes that update visible on its next write without registry/config locks
// in steady state.
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
	return currentConfig.Load() != nil
}

// FastPathGuard proves that no speed limit applies to one connection
// direction under a specific immutable config snapshot. It must be activated
// immediately before entering a zero-copy path; activation fails if a newer
// snapshot won the race in between.
type FastPathGuard struct {
	state *configState
}

// AllowFastPath returns a guard only for an identified user whose fully
// resolved effective limit is unlimited for this inbound and direction. It
// intentionally returns nil before the first config push: the short startup
// window stays on the buffered path so a later push can affect the connection.
func AllowFastPath(email, tag string, up bool) *FastPathGuard {
	username := Username(email)
	state := currentConfig.Load()
	if state == nil || username == "" || resolveLimitPlan(&state.cfg, username, tag, up).limited() {
		return nil
	}
	return &FastPathGuard{state: state}
}

// Activate registers interrupt for the lifetime of a zero-copy operation.
// Every config push interrupts all active fast paths so long-lived sessions
// reconnect and cannot retain an outdated unlimited decision. The returned
// stop function is safe to call more than once.
func (g *FastPathGuard) Activate(interrupt func()) (stop func(), ok bool) {
	if g == nil || interrupt == nil {
		return func() {}, false
	}
	watcher := &fastPathWatcher{interrupt: interrupt}
	watcher.active.Store(true)

	fastPathMu.Lock()
	if currentConfig.Load() != g.state {
		fastPathMu.Unlock()
		watcher.active.Store(false)
		return func() {}, false
	}
	fastPathNextID++
	id := fastPathNextID
	fastPathWatchers[id] = watcher
	fastPathMu.Unlock()

	return func() {
		if !watcher.active.Swap(false) {
			return
		}
		fastPathMu.Lock()
		delete(fastPathWatchers, id)
		fastPathMu.Unlock()
	}, true
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
