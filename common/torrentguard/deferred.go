package torrentguard

import (
	"context"
	"sync/atomic"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/features/stats"
)

// Untracked is implemented by outbound proxies the dispatcher must not track:
// freedom tracks torrentguard itself (with the actually-dialed IP), and
// blackhole/dns/loopback never carry traffic to a remote peer. Everything
// else — first of all the VLESS/Trojan/... outbound a bridge entry node
// relays its clients through — is tracked by the dispatcher via Deferred.
type Untracked interface {
	TorrentGuardUntracked()
}

// Deferred tracks one dispatched connection whose outbound is not freedom.
//
// Without it a client of a bridge was invisible: on the entry node its
// traffic leaves through a proxy outbound (freedom never sees it), and on the
// exit node it arrives as the bridge's service account, which is exempt.
// The entry node is the only place where the real user and client IP meet
// the real destination, so the dispatcher counts it there.
//
// The link is built before routing picks the outbound, so the wrappers are
// installed first and stay pass-through until Activate registers the
// connection; for an untracked outbound Activate is never called.
type Deferred struct {
	handle atomic.Pointer[ConnHandle]
	// bytes moved before Activate (the sniffer reads the first chunk before
	// routing) — handed over to the handle on Activate
	preUp    int64
	preDown  int64
	ctx      context.Context
	username string
	sourceIP string
}

type deferredKey struct{}

// NewDeferred returns nil (every method is nil-safe) when there is no user to
// count the connection against.
func NewDeferred(ctx context.Context, username, sourceIP string) *Deferred {
	if username == "" {
		return nil
	}
	return &Deferred{ctx: ctx, username: username, sourceIP: sourceIP}
}

func ContextWithDeferred(ctx context.Context, d *Deferred) context.Context {
	if d == nil {
		return ctx
	}
	return context.WithValue(ctx, deferredKey{}, d)
}

func DeferredFromContext(ctx context.Context) *Deferred {
	d, _ := ctx.Value(deferredKey{}).(*Deferred)
	return d
}

// Activate registers the connection once the outbound is known; same
// counting, thresholds and alerts as freedom's RecordOpen.
func (d *Deferred) Activate(destIP string) {
	if d == nil || d.handle.Load() != nil {
		return
	}
	if h := RecordOpen(d.ctx, d.username, d.sourceIP, destIP); h != nil {
		d.handle.Store(h)
		d.flushPre(h)
	}
}

func (d *Deferred) flushPre(h *ConnHandle) {
	if n := atomic.SwapInt64(&d.preUp, 0); n > 0 {
		atomic.AddInt64(&h.bytesUp, n)
	}
	if n := atomic.SwapInt64(&d.preDown, 0); n > 0 {
		atomic.AddInt64(&h.bytesDown, n)
	}
}

// ShouldDrop mirrors freedom's drop-at-dial check for a new connection.
func (d *Deferred) ShouldDrop() bool {
	if d == nil {
		return false
	}
	return ShouldDrop(d.username, d.sourceIP)
}

func (d *Deferred) account(n int64, up bool) {
	if n <= 0 {
		return
	}
	h := d.handle.Load()
	if h == nil {
		if up {
			atomic.AddInt64(&d.preUp, n)
		} else {
			atomic.AddInt64(&d.preDown, n)
		}
		// Activate may have run in between — hand the bytes over now
		if h = d.handle.Load(); h != nil {
			d.flushPre(h)
		}
		return
	}
	if up {
		atomic.AddInt64(&h.bytesUp, n)
	} else {
		atomic.AddInt64(&h.bytesDown, n)
	}
	if !h.state.enforced.Load() {
		return
	}
	c := snapshot()
	if c.Action == "drop" {
		return // drop is enforced at dial time, see ShouldDrop
	}
	throttle(d.ctx, h, int(n), c.ThrottleMbps)
}

// Writer counts (and, once enforced, throttles) bytes written to w; up is
// the client->destination direction.
func (d *Deferred) Writer(w buf.Writer, up bool) buf.Writer {
	if d == nil {
		return w
	}
	return &deferredWriter{Writer: w, d: d, up: up}
}

type deferredWriter struct {
	buf.Writer
	d  *Deferred
	up bool
}

func (w *deferredWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.d.account(int64(mb.Len()), w.up)
	return w.Writer.WriteMultiBuffer(mb)
}

// UplinkCounter is for links whose client->destination side is a reader
// counted through a stats.Counter (dispatcher.WrapLink): it keeps feeding
// inner (nil when user stats are off) and counts the same bytes as upload.
// The reader's type is left untouched — the sniffer type-asserts it.
func (d *Deferred) UplinkCounter(inner stats.Counter) stats.Counter {
	if d == nil {
		return inner
	}
	return &uplinkCounter{inner: inner, d: d}
}

type uplinkCounter struct {
	inner stats.Counter
	d     *Deferred
}

func (c *uplinkCounter) Value() int64 {
	if c.inner == nil {
		return 0
	}
	return c.inner.Value()
}

func (c *uplinkCounter) Set(v int64) int64 {
	if c.inner == nil {
		return 0
	}
	return c.inner.Set(v)
}

func (c *uplinkCounter) Add(n int64) int64 {
	c.d.account(n, true)
	if c.inner == nil {
		return 0
	}
	return c.inner.Add(n)
}
