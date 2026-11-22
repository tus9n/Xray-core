package torrentguard

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func gate(ctx context.Context, user, src string, isIP bool, port int, proto string, closer func()) bool {
	r, _ := QuarantineGate(ctx, user, src, isIP, port, proto, closer)
	return r
}

func resetQuarantine() {
	qMu.Lock()
	qStates = map[string]*quarState{}
	qMu.Unlock()
}

func TestQuarantine_SignatureKillsAndRefuses(t *testing.T) {
	pushConfig(t, `{"enabled":true,"window_sec":20,"symmetry_ratio_min":0.8,"max_unique_ips_alert":60,"max_unique_ips_enforce":1000000,"action":"throttle","quarantine_enabled":true,"quarantine_min":30,"quarantine_hits":1,"quarantine_window_min":10}`)
	resetQuarantine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var peer, web atomic.Int32
	// encrypted peer: bare IP, high port, nothing sniffed — remembered
	if gate(ctx, "alice", "1.1.1.1", true, 51413, "", func() { peer.Add(1) }) {
		t.Fatal("no quarantine yet")
	}
	// web: never remembered, never refused
	if gate(ctx, "alice", "1.1.1.1", true, 443, "", func() { web.Add(1) }) {
		t.Fatal("443 must pass")
	}
	ReportSignature("alice", "1.1.1.1", "utp", "2.2.2.2:6881")
	if Quarantined("alice", "1.1.1.1") {
		t.Fatal("uTP alone must not quarantine")
	}
	ReportSignature("alice", "1.1.1.1", "dht", "3.3.3.3:6881")
	if !Quarantined("alice", "1.1.1.1") || peer.Load() != 1 || web.Load() != 0 {
		t.Fatalf("quarantine: q=%v peer=%d web=%d", Quarantined("alice", "1.1.1.1"), peer.Load(), web.Load())
	}
	if !gate(ctx, "alice", "1.1.1.1", true, 40000, "", nil) {
		t.Fatal("new peer connection must be refused")
	}
	for _, c := range []struct {
		isIP  bool
		port  int
		proto string
	}{{true, 443, ""}, {true, 53, ""}, {false, 40000, ""}, {true, 8443, "tls"}, {true, 3478, "quic"}} {
		if gate(ctx, "alice", "1.1.1.1", c.isIP, c.port, c.proto, nil) {
			t.Fatalf("must pass in quarantine: %+v", c)
		}
	}
	if gate(ctx, "alice", "9.9.9.9", true, 40000, "", nil) || gate(ctx, "bob", "1.1.1.1", true, 40000, "", nil) {
		t.Fatal("quarantine is per (user, source IP)")
	}
}

func TestQuarantine_HitsAndExempt(t *testing.T) {
	pushConfig(t, `{"enabled":true,"window_sec":20,"symmetry_ratio_min":0.8,"max_unique_ips_alert":60,"max_unique_ips_enforce":1000000,"action":"throttle","quarantine_enabled":true,"quarantine_min":30,"quarantine_hits":2,"quarantine_window_min":10}`)
	resetQuarantine()
	ReportSignature("carol", "4.4.4.4", "handshake", "5.5.5.5:1")
	if Quarantined("carol", "4.4.4.4") {
		t.Fatal("needs 2 hits")
	}
	ReportSignature("carol", "4.4.4.4", "udp_tracker", "5.5.5.6:1")
	if !Quarantined("carol", "4.4.4.4") {
		t.Fatal("2 hits must quarantine")
	}
	pushConfig(t, `{"enabled":true,"window_sec":20,"symmetry_ratio_min":0.8,"max_unique_ips_alert":60,"max_unique_ips_enforce":1000000,"action":"throttle","quarantine_enabled":true,"quarantine_hits":2,"exempt_users":["carol"]}`)
	if Quarantined("carol", "4.4.4.4") {
		t.Fatal("exempt must lift quarantine")
	}
}

func TestQuarantine_OffAndForgotten(t *testing.T) {
	pushConfig(t, `{"enabled":true,"window_sec":20,"symmetry_ratio_min":0.8,"max_unique_ips_alert":60,"max_unique_ips_enforce":1000000,"action":"throttle"}`)
	resetQuarantine()
	ReportSignature("dave", "6.6.6.6", "dht", "7.7.7.7:1")
	if Quarantined("dave", "6.6.6.6") || gate(context.Background(), "dave", "6.6.6.6", true, 40000, "", nil) {
		t.Fatal("quarantine off by default")
	}
	pushConfig(t, `{"enabled":true,"window_sec":20,"symmetry_ratio_min":0.8,"max_unique_ips_alert":60,"max_unique_ips_enforce":1000000,"action":"throttle","quarantine_enabled":true}`)
	ctx, cancel := context.WithCancel(context.Background())
	gate(ctx, "erin", "8.8.4.4", true, 40000, "", func() {})
	cancel()
	time.Sleep(50 * time.Millisecond)
	qMu.Lock()
	_, left := qStates[key("erin", "8.8.4.4")]
	qMu.Unlock()
	if left {
		t.Fatal("finished connection must be forgotten")
	}
}

type fakeConn struct{ closed atomic.Int32 }

func (c *fakeConn) Close() error { c.closed.Add(1); return nil }

func TestQuarantine_ClosesAttachedConn(t *testing.T) {
	pushConfig(t, `{"enabled":true,"window_sec":20,"symmetry_ratio_min":0.8,"max_unique_ips_alert":60,"max_unique_ips_enforce":1000000,"action":"throttle","quarantine_enabled":true}`)
	resetQuarantine()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, gctx := QuarantineGate(ctx, "frank", "1.2.3.4", true, 51413, "", nil)
	conn := &fakeConn{}
	AttachConn(gctx, conn)
	ReportSignature("frank", "1.2.3.4", "dht", "5.6.7.8:6881")
	if conn.closed.Load() != 1 {
		t.Fatal("dialed socket must be closed by quarantine")
	}
	late := &fakeConn{}
	AttachConn(gctx, late)
	if late.closed.Load() != 1 {
		t.Fatal("socket attached after quarantine must be closed at once")
	}
}
