package torrentguard

import (
	"context"
	"strconv"
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
// during the quarantine extends it.

var defaultAllowPorts = []int{53, 80, 443, 853}

type qConn struct {
	close func()
}

type quarState struct {
	until time.Time
	hits  []time.Time
	kinds map[string]int
	conns map[*qConn]struct{}
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

// QuarantineGate decides about a new connection of (username, sourceIP) to a
// destination addressed by IP (isIP) or domain on port, sniffed as protocol.
// Returns true when the pair is quarantined and the connection must be
// refused. Otherwise a connection that quarantine would cut is remembered
// with closer, so a quarantine starting later closes it; it is forgotten
// when ctx ends.
func QuarantineGate(ctx context.Context, username, sourceIP string, isIP bool, port int,
	protocol string, closer func()) bool {
	if username == "" || !isIP || webProtocol(protocol) {
		return false
	}
	q := quarantineConfig()
	if !q.on {
		return false
	}
	if _, ok := q.allow[port]; ok {
		return false
	}
	if !Enabled() || isExempt(username) {
		return false
	}
	k := key(username, sourceIP)
	now := time.Now()

	qMu.Lock()
	st := qStates[k]
	if st != nil && now.Before(st.until) {
		qMu.Unlock()
		return true
	}
	if closer == nil {
		qMu.Unlock()
		return false
	}
	if st == nil {
		st = &quarState{}
		qStates[k] = st
	}
	if st.conns == nil {
		st.conns = map[*qConn]struct{}{}
	}
	c := &qConn{close: closer}
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
	return false
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
			if len(st.conns) > 0 || now.Before(st.until) {
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
