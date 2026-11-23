package torrentguard

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Quarantine (Marzban patch).
//
// A sniffed BitTorrent signature (handshake, DHT, tracker, LSD — not uTP on
// its own) proves a torrent client runs behind this (username, source IP).
// Routing already blackholes the plaintext part, but the client keeps
// swarming over encrypted peer connections no sniffer recognises. On the
// first strong signature(s) the pair is quarantined locally, without waiting
// for the panel: for quarantine_min minutes every connection of that pair to
// a bare IP on a port outside quarantine_allow_ports (web, DNS) is refused,
// and the ones already open are closed. Sites, messengers and anything
// addressed by domain or recognised as TLS/HTTP/QUIC keep working.
//
//	TORRENTGUARD_QUARANTINE user=<username> src=<ip> min=<n> killed=<n> kinds=dht:1
//
// is logged once when a quarantine starts. Every further strong signature
// during the quarantine extends it. Refused connections are reported as
//
//	TORRENTGUARD_REFUSED user=<username> src=<ip> refused=<n> peers=<n> left=<sec> sample=udp:1.2.3.4:6881,...
//
// the first one at once, later ones summed up at most once per
// refusedLogEvery for the pair (refused — connections since the previous
// line, peers — distinct destinations among them, left — seconds of
// quarantine remaining, sample — up to refusedSample destinations).

var defaultAllowPorts = []int{53, 80, 443, 853}

const (
	refusedLogEvery = 30 * time.Second
	refusedSample   = 3
)

type qConn struct {
	close func()
}

type quarState struct {
	until time.Time
	hits  []time.Time
	kinds map[string]int
	conns map[*qConn]struct{}

	// refused connections not yet logged
	refused int
	rPeers  map[string]struct{}
	rSample []string
	rLast   time.Time
}

var (
	qMu     sync.Mutex
	qStates = map[string]*quarState{}
)

type quarCfg struct {
	on     bool
	dur    time.Duration
	need   int
	window time.Duration
	allow  map[int]struct{}
}

var (
	qCfgMu  sync.RWMutex
	qCfgVal quarCfg
)

// setQuarantineConfig is called from handlePush with the freshly pushed config.
func setQuarantineConfig(c remoteConfig) {
	q := quarCfg{on: c.Enabled && c.QuarantineEnabled}
	q.dur = time.Duration(c.QuarantineMin) * time.Minute
	if q.dur <= 0 {
		q.dur = 30 * time.Minute
	}
	q.need = c.QuarantineHits
	if q.need <= 0 {
		q.need = 1
	}
	q.window = time.Duration(c.QuarantineWindowMin) * time.Minute
	if q.window <= 0 {
		q.window = 10 * time.Minute
	}
	ports := c.QuarantineAllowPorts
	if len(ports) == 0 {
		ports = defaultAllowPorts
	}
	q.allow = make(map[int]struct{}, len(ports))
	for _, p := range ports {
		q.allow[p] = struct{}{}
	}
	qCfgMu.Lock()
	qCfgVal = q
	qCfgMu.Unlock()
}

func quarantineConfig() quarCfg {
	qCfgMu.RLock()
	defer qCfgMu.RUnlock()
	return qCfgVal
}

func strongKind(kind string) bool {
	return kind != "" && kind != "utp"
}

// noteSignature counts a sniffed signature towards the quarantine of the
// pair; called from ReportSignature (enabled, not exempt).
func noteSignature(username, sourceIP, kind string) {
	if !strongKind(kind) {
		return
	}
	q := quarantineConfig()
	if !q.on {
		return
	}
	now := time.Now()
	k := key(username, sourceIP)

	qMu.Lock()
	st := qStates[k]
	if st == nil {
		st = &quarState{}
		qStates[k] = st
	}
	if now.Before(st.until) {
		st.until = now.Add(q.dur) // still swarming — keep it closed
		qMu.Unlock()
		return
	}
	kept := st.hits[:0]
	for _, h := range st.hits {
		if now.Sub(h) <= q.window {
			kept = append(kept, h)
		}
	}
	st.hits = append(kept, now)
	if st.kinds == nil {
		st.kinds = map[string]int{}
	}
	st.kinds[kind]++
	if len(st.hits) < q.need {
		qMu.Unlock()
		return
	}
	st.until = now.Add(q.dur)
	kinds := formatKinds(st.kinds)
	st.hits, st.kinds = nil, nil
	victims := make([]*qConn, 0, len(st.conns))
	for c := range st.conns {
		victims = append(victims, c)
	}
	qMu.Unlock()

	for _, c := range victims {
		func() {
			defer func() { _ = recover() }()
			c.close()
		}()
	}
	errors.LogWarning(context.Background(),
		"TORRENTGUARD_QUARANTINE user=", username, " src=", sourceIP,
		" min=", strconv.Itoa(int(q.dur/time.Minute)), " killed=", strconv.Itoa(len(victims)),
		" kinds=", kinds)
}

// webProtocol: sniffed as a protocol that is not P2P — kept even in quarantine.
func webProtocol(p string) bool {
	switch p {
	case "tls", "http1", "http2", "quic":
		return true
	}
	return false
}

// closerHolder gathers the ways to tear one connection down: the dispatcher's
// pipes and, once dialed, the outbound socket itself (freedom splices raw
// sockets past the pipes, so closing the pipes alone leaves it running).
type closerHolder struct {
	mu     sync.Mutex
	fns    []func()
	closed bool
}

func (h *closerHolder) add(f func()) {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		f()
		return
	}
	h.fns = append(h.fns, f)
	h.mu.Unlock()
}

func (h *closerHolder) run() {
	h.mu.Lock()
	h.closed = true
	fns := h.fns
	h.fns = nil
	h.mu.Unlock()
	for _, f := range fns {
		func() {
			defer func() { _ = recover() }()
			f()
		}()
	}
}

type holderKey struct{}

// AttachConn lets a quarantine close the dialed outbound connection of this
// dispatch too (no-op unless QuarantineGate remembered the connection).
func AttachConn(ctx context.Context, c interface{ Close() error }) {
	if h, _ := ctx.Value(holderKey{}).(*closerHolder); h != nil && c != nil {
		h.add(func() { _ = c.Close() })
	}
}

// QuarantineGate decides about a new connection of (username, sourceIP) to a
// destination addressed by IP (isIP) or domain on port, sniffed as protocol.
// Returns true when the pair is quarantined and the connection must be
// refused. Otherwise a connection that quarantine would cut is remembered
// with closer, so a quarantine starting later closes it; it is forgotten
// when ctx ends. The returned context must be used for the rest of the
// dispatch: the outbound attaches its socket to it (AttachConn).
func QuarantineGate(ctx context.Context, username, sourceIP string, isIP bool, port int,
	protocol, dest string, closer func()) (bool, context.Context) {
	if username == "" || !isIP || webProtocol(protocol) {
		return false, ctx
	}
	q := quarantineConfig()
	if !q.on {
		return false, ctx
	}
	if _, ok := q.allow[port]; ok {
		return false, ctx
	}
	if !Enabled() || isExempt(username) {
		return false, ctx
	}
	k := key(username, sourceIP)
	now := time.Now()

	qMu.Lock()
	st := qStates[k]
	if st != nil && now.Before(st.until) {
		line := noteRefused(username, sourceIP, st, dest, now)
		qMu.Unlock()
		if line != "" {
			errors.LogWarning(context.Background(), line)
		}
		return true, ctx
	}
	if st == nil {
		st = &quarState{}
		qStates[k] = st
	}
	if st.conns == nil {
		st.conns = map[*qConn]struct{}{}
	}
	h := &closerHolder{}
	if closer != nil {
		h.add(closer)
	}
	c := &qConn{close: h.run}
	st.conns[c] = struct{}{}
	qMu.Unlock()

	context.AfterFunc(ctx, func() {
		qMu.Lock()
		if st := qStates[k]; st != nil {
			delete(st.conns, c)
			if len(st.conns) == 0 && len(st.hits) == 0 && time.Now().After(st.until) {
				delete(qStates, k)
			}
		}
		qMu.Unlock()
	})
	return false, context.WithValue(ctx, holderKey{}, h)
}

// noteRefused counts a refused connection of a quarantined pair and returns
// the log line when it is due; called under qMu.
func noteRefused(username, sourceIP string, st *quarState, dest string, now time.Time) string {
	if st.rPeers == nil {
		st.rPeers = map[string]struct{}{}
	}
	st.refused++
	if dest != "" {
		if _, seen := st.rPeers[dest]; !seen && len(st.rPeers) < 10000 {
			st.rPeers[dest] = struct{}{}
			if len(st.rSample) < refusedSample {
				st.rSample = append(st.rSample, dest)
			}
		}
	}
	if now.Sub(st.rLast) < refusedLogEvery {
		return ""
	}
	return takeRefused(username, sourceIP, st, now)
}

// takeRefused formats and resets the pending refusals; called under qMu.
func takeRefused(username, sourceIP string, st *quarState, now time.Time) string {
	left := 0
	if now.Before(st.until) {
		left = int(st.until.Sub(now) / time.Second)
	}
	line := "TORRENTGUARD_REFUSED user=" + username + " src=" + sourceIP +
		" refused=" + strconv.Itoa(st.refused) + " peers=" + strconv.Itoa(len(st.rPeers)) +
		" left=" + strconv.Itoa(left) + " sample=" + strings.Join(st.rSample, ",")
	st.refused, st.rPeers, st.rSample, st.rLast = 0, nil, nil, now
	return line
}

// refusedFlusher logs refusals left pending when they stopped right after a
// line: without it they would wait for the next refusal forever.
func refusedFlusher() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for now := range t.C {
		var lines []string
		qMu.Lock()
		for k, st := range qStates {
			if st.refused > 0 && now.Sub(st.rLast) >= refusedLogEvery {
				user, src, _ := strings.Cut(k, "\x00")
				lines = append(lines, takeRefused(user, src, st, now))
			}
		}
		qMu.Unlock()
		for _, l := range lines {
			errors.LogWarning(context.Background(), l)
		}
	}
}

// Quarantined reports whether the pair is quarantined right now.
func Quarantined(username, sourceIP string) bool {
	qMu.Lock()
	defer qMu.Unlock()
	st := qStates[key(username, sourceIP)]
	return st != nil && time.Now().Before(st.until)
}

// clearQuarantineFor lifts quarantines of users that became exempt.
func clearQuarantineFor(exempt map[string]struct{}) {
	if len(exempt) == 0 {
		return
	}
	qMu.Lock()
	defer qMu.Unlock()
	for k, st := range qStates {
		for u := range exempt {
			if len(k) > len(u) && k[:len(u)] == u && k[len(u)] == 0 {
				st.until = time.Time{}
				st.hits, st.kinds = nil, nil
			}
		}
	}
}

// quarantineSweeper drops idle states (no open candidates, no recent hits,
// quarantine over) that AfterFunc did not get to remove.
func quarantineSweeper() {
	for range time.Tick(idleTTL) {
		now := time.Now()
		window := quarantineConfig().window
		qMu.Lock()
		for k, st := range qStates {
			if len(st.conns) > 0 || now.Before(st.until) || st.refused > 0 {
				continue
			}
			if n := len(st.hits); n > 0 && now.Sub(st.hits[n-1]) <= window {
				continue
			}
			delete(qStates, k)
		}
		qMu.Unlock()
	}
}
