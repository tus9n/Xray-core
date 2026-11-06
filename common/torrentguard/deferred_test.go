package torrentguard

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func pushConfig(t *testing.T, body string) {
	t.Helper()
	rec := httptest.NewRecorder()
	handlePush(rec, httptest.NewRequest(http.MethodPost, "/torrent-guard", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("push failed: %d", rec.Code)
	}
}

func resetState(t *testing.T) {
	t.Helper()
	regMu.Lock()
	reg = map[string]*userState{}
	regMu.Unlock()
}

type countCounter struct{ v int64 }

func (c *countCounter) Value() int64      { return c.v }
func (c *countCounter) Set(v int64) int64 { old := c.v; c.v = v; return old }
func (c *countCounter) Add(n int64) int64 { old := c.v; c.v += n; return old }

func mb(n int) buf.MultiBuffer {
	b := buf.New()
	b.Extend(int32(n))
	return buf.MultiBuffer{b}
}

func TestDeferred_NilSafe(t *testing.T) {
	var d *Deferred // no user
	if NewDeferred(context.Background(), "", "1.2.3.4") != nil {
		t.Fatal("expected nil Deferred without a username")
	}
	d.Activate("5.6.7.8")
	if d.ShouldDrop() {
		t.Fatal("nil Deferred must never drop")
	}
	w := buf.Discard
	if d.Writer(w, true) != w {
		t.Fatal("nil Deferred must return the writer unchanged")
	}
	c := &countCounter{}
	if d.UplinkCounter(c) != c {
		t.Fatal("nil Deferred must return the counter unchanged")
	}
	if ContextWithDeferred(context.Background(), nil) != context.Background() {
		t.Fatal("nil Deferred must not change the context")
	}
}

func TestDeferred_PassThroughUntilActivated(t *testing.T) {
	resetState(t)
	pushConfig(t, `{"enabled":true,"window_sec":20,"max_unique_ips_alert":5,"max_unique_ips_enforce":10,"action":"throttle"}`)
	d := NewDeferred(context.Background(), "u1", "10.0.0.1")
	w := d.Writer(buf.Discard, true)
	if err := w.WriteMultiBuffer(mb(100)); err != nil {
		t.Fatal(err)
	}
	if d.handle.Load() != nil {
		t.Fatal("handle must stay nil until Activate")
	}
	if atomic.LoadInt64(&d.preUp) != 100 {
		t.Fatal("bytes before Activate must be kept")
	}
	d.Activate("8.8.8.8")
	h := d.handle.Load()
	if h == nil {
		t.Fatal("Activate must register the connection when enabled")
	}
	if err := w.WriteMultiBuffer(mb(300)); err != nil {
		t.Fatal(err)
	}
	inner := &countCounter{}
	c := d.UplinkCounter(inner)
	c.Add(50)
	if got := atomic.LoadInt64(&h.bytesUp); got != 450 {
		t.Fatalf("expected 450 bytes up (100 before Activate + 300 via writer + 50 via counter), got %d", got)
	}
	if inner.v != 50 {
		t.Fatalf("inner counter must still receive the bytes, got %d", inner.v)
	}
	d.Writer(buf.Discard, false).WriteMultiBuffer(mb(70))
	if got := atomic.LoadInt64(&h.bytesDown); got != 70 {
		t.Fatalf("expected 70 bytes down, got %d", got)
	}
	// A second Activate must not register the same connection twice.
	d.Activate("9.9.9.9")
	if d.handle.Load() != h {
		t.Fatal("Activate must be idempotent")
	}
}

func TestDeferred_UplinkCounterWithoutStats(t *testing.T) {
	resetState(t)
	pushConfig(t, `{"enabled":true,"max_unique_ips_alert":5,"max_unique_ips_enforce":10}`)
	d := NewDeferred(context.Background(), "u2", "10.0.0.2")
	d.Activate("8.8.4.4")
	c := d.UplinkCounter(nil) // user stats disabled
	c.Add(42)
	if c.Value() != 0 || c.Set(5) != 0 {
		t.Fatal("counter without inner must report 0")
	}
	if got := atomic.LoadInt64(&d.handle.Load().bytesUp); got != 42 {
		t.Fatalf("expected 42 bytes up, got %d", got)
	}
}

func TestDeferred_ExemptAndDisabledNotTracked(t *testing.T) {
	resetState(t)
	pushConfig(t, `{"enabled":true,"max_unique_ips_alert":5,"max_unique_ips_enforce":10,"exempt_users":["bridge"]}`)
	d := NewDeferred(context.Background(), "bridge", "10.0.0.3")
	d.Activate("1.1.1.1")
	if d.handle.Load() != nil {
		t.Fatal("exempt user (bridge service account) must not be tracked")
	}
	pushConfig(t, `{"enabled":false,"max_unique_ips_alert":5,"max_unique_ips_enforce":10}`)
	d = NewDeferred(context.Background(), "u3", "10.0.0.3")
	d.Activate("1.1.1.1")
	if d.handle.Load() != nil {
		t.Fatal("disabled guard must not track")
	}
}

// A swarm-shaped user behind a bridge: many symmetric peers through the same
// (user, client IP) — crosses the enforce threshold, then new connections are
// refused with action=drop, exactly like freedom does.
func TestDeferred_EnforceAndDrop(t *testing.T) {
	resetState(t)
	pushConfig(t, `{"enabled":true,"window_sec":60,"symmetry_ratio_min":0.6,"max_unique_ips_alert":3,"max_unique_ips_enforce":5,"action":"drop"}`)
	var all []*Deferred
	for i := 0; i < 6; i++ {
		d := NewDeferred(context.Background(), "swarm", "10.0.0.9")
		if d.ShouldDrop() {
			break
		}
		d.Activate(ipFor(i))
		// symmetric traffic on every peer connection
		d.Writer(buf.Discard, true).WriteMultiBuffer(mb(1000))
		d.Writer(buf.Discard, false).WriteMultiBuffer(mb(900))
		all = append(all, d)
	}
	// one more open re-evaluates with traffic now present on earlier conns
	NewDeferred(context.Background(), "swarm", "10.0.0.9").Activate(ipFor(100))
	if !NewDeferred(context.Background(), "swarm", "10.0.0.9").ShouldDrop() {
		t.Fatal("expected swarm-shaped user to be enforced and dropped")
	}
	// another client IP of the same account is not punished
	if NewDeferred(context.Background(), "swarm", "10.0.0.10").ShouldDrop() {
		t.Fatal("enforcement must be per (user, client IP)")
	}
	_ = all
}
