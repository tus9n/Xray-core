package torrentguard

import (
	"sync/atomic"
	"testing"
)

func mkConn(destIP string, up, down int64) *ConnHandle {
	h := &ConnHandle{destIP: destIP}
	atomic.StoreInt64(&h.bytesUp, up)
	atomic.StoreInt64(&h.bytesDown, down)
	return h
}

func TestUniqueDestIPs(t *testing.T) {
	conns := []*ConnHandle{
		mkConn("1.1.1.1", 0, 0),
		mkConn("1.1.1.1", 0, 0),
		mkConn("2.2.2.2", 0, 0),
	}
	if got := uniqueDestIPs(conns); got != 2 {
		t.Fatalf("expected 2 unique IPs, got %d", got)
	}
}

func TestSymmetricFraction(t *testing.T) {
	conns := []*ConnHandle{
		mkConn("1.1.1.1", 1000, 900), // symmetric (0.9 >= 0.6)
		mkConn("2.2.2.2", 1000, 100), // not symmetric (0.1 < 0.6)
		mkConn("3.3.3.3", 0, 0),      // excluded: no traffic yet
		mkConn("4.4.4.4", 500, 500),  // symmetric
	}
	got := symmetricFraction(conns, 0.6)
	// 2 symmetric out of 3 with-traffic-in-both-directions (the 0/0 one is excluded from the denominator)
	want := 2.0 / 3.0
	if got != want {
		t.Fatalf("expected %v (2/3 with-traffic conns symmetric), got %v", want, got)
	}
}

func TestSymmetricFraction_BrowsingLikeAsymmetric(t *testing.T) {
	// Typical browsing/streaming: download >> upload on every connection.
	conns := []*ConnHandle{
		mkConn("1.1.1.1", 2000, 200000),
		mkConn("2.2.2.2", 1500, 180000),
		mkConn("3.3.3.3", 3000, 220000),
	}
	got := symmetricFraction(conns, 0.6)
	if got != 0 {
		t.Fatalf("expected 0 symmetric fraction for browsing-shaped traffic, got %v", got)
	}
}

func TestEvaluate_NoAlertBelowThreshold(t *testing.T) {
	s := &userState{}
	var conns []*ConnHandle
	for i := 0; i < 5; i++ {
		conns = append(conns, mkConn(string(rune('a'+i))+".ip", 1000, 900))
	}
	c := remoteConfig{SymmetryRatioMin: 0.6, MaxUniqueIPsAlert: 20, MaxUniqueIPsEnforce: 35}
	evaluate("user1", "10.0.0.1", s, conns, c)
	if s.enforced.Load() {
		t.Fatalf("should not be enforced with only 5 unique IPs")
	}
}

func TestEvaluate_EnforcesAboveThreshold(t *testing.T) {
	s := &userState{}
	var conns []*ConnHandle
	for i := 0; i < 40; i++ {
		conns = append(conns, mkConn(ipFor(i), 1000, 900))
	}
	c := remoteConfig{SymmetryRatioMin: 0.6, MaxUniqueIPsAlert: 20, MaxUniqueIPsEnforce: 35}
	evaluate("user1", "10.0.0.1", s, conns, c)
	if !s.enforced.Load() {
		t.Fatalf("expected enforcement above the enforce threshold with symmetric traffic")
	}
}

func TestEvaluate_NoEnforceWithoutSymmetry(t *testing.T) {
	s := &userState{}
	var conns []*ConnHandle
	for i := 0; i < 40; i++ {
		// Asymmetric — looks like normal downloading, not a swarm.
		conns = append(conns, mkConn(ipFor(i), 1000, 500000))
	}
	c := remoteConfig{SymmetryRatioMin: 0.6, MaxUniqueIPsAlert: 20, MaxUniqueIPsEnforce: 35}
	evaluate("user1", "10.0.0.1", s, conns, c)
	if s.enforced.Load() {
		t.Fatalf("should not enforce on many-IPs-but-asymmetric traffic (e.g. CDN-heavy browsing)")
	}
}

func ipFor(i int) string {
	return "10.1." + string(rune('0'+i/10)) + "." + string(rune('0'+i%10))
}
