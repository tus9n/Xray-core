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
// Fail-open by design everywhere: any error (config fetch failure, no
// SPEED_LIMIT_CONFIG_URL set, unknown user/tag) results in NO limiting,
// never a blocked or dropped connection. This is a bandwidth cap, not an
// access control — the failure mode of "no limit" is always safe; the
// failure mode of "connection hangs" is not.
package speedlimit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/xtls/xray-core/common/buf"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	refreshInterval = 60 * time.Second
	idleTTL         = 5 * time.Minute
	fetchTimeout    = 10 * time.Second
)

var (
	configURL = os.Getenv("SPEED_LIMIT_CONFIG_URL")
	authToken = os.Getenv("SPEED_LIMIT_TOKEN")
	enabled   = configURL != "" && authToken != ""
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
}

type remoteConfig struct {
	Default struct {
		DownMbps *float64 `json:"down_mbps"`
		UpMbps   *float64 `json:"up_mbps"`
	} `json:"default"`
	Node                 *nodeLimits                         `json:"node"`
	Inbounds             map[string]inboundLimits             `json:"inbounds"`
	Users                map[string]userLimits                `json:"users"`
	UserInboundOverrides map[string]map[string]userLimits     `json:"user_inbound_overrides"`
}

var (
	cfgMu sync.RWMutex
	cfg   remoteConfig
)

func fetchLoop() {
	fetchOnce()
	for range time.Tick(refreshInterval) {
		fetchOnce()
	}
}

func fetchOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, configURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+authToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return // keep serving the last-known-good config
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var next remoteConfig
	if err := json.Unmarshal(body, &next); err != nil {
		return
	}
	cfgMu.Lock()
	cfg = next
	cfgMu.Unlock()
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

// effectiveLimitBytesPerSec mirrors app/jobs/... speed_shaper.py's
// _effective_limit(): min() of every applicable down/up limit (node /
// inbound / user / user-on-this-inbound), falling back to the global
// default only when NEITHER the user nor the user-inbound override
// explicitly set 0 (0 there means "explicitly unlimited", not "unset").
func effectiveLimitBytesPerSec(username, tag string, up bool) *float64 {
	cfgMu.RLock()
	defer cfgMu.RUnlock()

	var node, inbound, user, userInbound *float64
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
	u, userSet := cfg.Users[username]
	if userSet {
		if up {
			user = u.UpMbps
		} else {
			user = u.DownMbps
		}
	}
	var userInboundSet bool
	if overrides, ok := cfg.UserInboundOverrides[username]; ok {
		if ui, ok := overrides[tag]; ok {
			userInboundSet = true
			if up {
				userInbound = ui.UpMbps
			} else {
				userInbound = ui.DownMbps
			}
		}
	}

	limitMbps := minPositive(node, inbound, user, userInbound)
	if limitMbps == nil {
		// Nothing explicitly set at any level — explicit 0 at user/
		// user-inbound level means "unlimited", not "fall through to
		// default" (matches speed_shaper.py's _effective_limit).
		explicitZero := (userSet && zeroOrNil(u, up)) || (userInboundSet && zeroOrNilOverride(cfg.UserInboundOverrides[username][tag], up))
		if explicitZero {
			return nil
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

func zeroOrNil(u userLimits, up bool) bool {
	v := u.DownMbps
	if up {
		v = u.UpMbps
	}
	return v != nil && *v == 0
}

func zeroOrNilOverride(u userLimits, up bool) bool {
	return zeroOrNil(u, up)
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
	if !enabled {
		return
	}
	go fetchLoop()
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

func getLimiter(username, tag, dir string, bytesPerSec float64) *rate.Limiter {
	k := key(username, tag, dir)
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

// WaitN blocks until n bytes' worth of tokens are available for
// username+tag+direction, or returns immediately if no limit applies
// (unlimited, config not loaded yet, or the package is disabled because
// SPEED_LIMIT_CONFIG_URL/SPEED_LIMIT_TOKEN aren't set). Direction: true for
// upload (client->outbound), false for download (outbound->client).
func WaitN(ctx context.Context, username, tag string, up bool, n int) error {
	if !enabled || username == "" || n <= 0 {
		return nil
	}
	bps := effectiveLimitBytesPerSec(username, tag, up)
	if bps == nil {
		return nil
	}
	dir := "down"
	if up {
		dir = "up"
	}
	limiter := getLimiter(username, tag, dir, *bps)
	// rate.Limiter caps WaitN's n at its own burst size — a single chunk
	// larger than the burst would otherwise always error out instead of
	// just taking longer to drain. buf.Buffer chunks are bounded (2000-ish
	// bytes) in practice, well under any realistic burst, but split
	// defensively anyway rather than assume that never changes upstream.
	burst := limiter.Burst()
	for n > 0 {
		take := n
		if take > burst {
			take = burst
		}
		if err := limiter.WaitN(ctx, take); err != nil {
			return nil // fail-open: context cancelled or similar — never block the proxy on our own account
		}
		n -= take
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
func LimitWriter(ctx context.Context, w buf.Writer, email, tag string, up bool) buf.Writer {
	if !enabled || email == "" {
		return w
	}
	return &limitedWriter{Writer: w, ctx: ctx, username: Username(email), tag: tag, up: up}
}

// Enabled reports whether SPEED_LIMIT_CONFIG_URL/SPEED_LIMIT_TOKEN are set —
// i.e. whether this package does anything at all on this node.
func Enabled() bool {
	return enabled
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
