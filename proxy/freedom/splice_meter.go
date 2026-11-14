package freedom

import (
	"context"
	gonet "net"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/speedlimit"
	"github.com/xtls/xray-core/common/torrentguard"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/proxy"
)

// Marzban patch: metered splice of the download direction for users with a
// speed cap or torrentguard tracking (see proxy/splice_meter.go).

// Below this cap splice is not used: chunks would make throttling bursty.
const meteredSpliceMinBytesPerSec = 2_000_000 / 8

const (
	meteredSpliceMinChunk = 16 * 1024
	meteredSpliceMaxChunk = 256 * 1024
)

type spliceMeter struct {
	email    string
	username string
	tag      string
	tg       *torrentguard.ConnHandle
	stat     stats.Counter
}

// newSpliceMeter returns nil when the old buffered path must stay: a cap too
// low for chunked splicing, or nothing to meter.
func newSpliceMeter(email, tag string, tg *torrentguard.ConnHandle, output buf.Writer) *spliceMeter {
	r := speedlimit.RateBytesPerSec(email, tag, false)
	if r > 0 && r < meteredSpliceMinBytesPerSec {
		return nil
	}
	if r <= 0 && tg == nil {
		return nil // unlimited and untracked — upstream unmetered splice handles it
	}
	return &spliceMeter{email: email, username: speedlimit.Username(email), tag: tag, tg: tg, stat: userStatCounter(output)}
}

// Chunk ≈ 0.1 s of the current cap (re-read each step, so a changed limit
// applies at once), within the limiter burst (0.2 s).
func (m *spliceMeter) Chunk() int64 {
	r := speedlimit.RateBytesPerSec(m.email, m.tag, false)
	if r <= 0 {
		return meteredSpliceMaxChunk
	}
	c := int64(r * 0.1)
	if c < meteredSpliceMinChunk {
		c = meteredSpliceMinChunk
	}
	if c > meteredSpliceMaxChunk {
		c = meteredSpliceMaxChunk
	}
	return c
}

func (m *spliceMeter) Done(ctx context.Context, n int64) {
	if m.stat != nil {
		m.stat.Add(n)
	}
	m.tg.Account(ctx, n, false)
	_ = speedlimit.WaitN(ctx, m.username, m.tag, false, int(n))
}

// userStatCounter finds the dispatcher's per-user downlink counter in the
// link writer (possibly wrapped by torrentguard's deferred writer).
func userStatCounter(w buf.Writer) stats.Counter {
	for i := 0; i < 8 && w != nil; i++ {
		if s, ok := w.(*dispatcher.SizeStatWriter); ok {
			return s.Counter
		}
		u, ok := w.(interface{ Unwrap() buf.Writer })
		if !ok {
			return nil
		}
		w = u.Unwrap()
	}
	return nil
}

var _ proxy.SpliceMeter = (*spliceMeter)(nil)

// capReadBuffer: while the limiter makes a capped user wait, the site's data
// sits unread in the kernel receive queue, and with autotuning that queue
// grows to tcp_rmem max — each unread packet pins a whole NIC receive page
// (invisible kernel memory on small nodes). A receive buffer of ≈1 s of the
// cap lets TCP slow the site down instead; the cap itself is unchanged.
func capReadBuffer(conn gonet.Conn, bytesPerSec float64) {
	if bytesPerSec <= 0 {
		return
	}
	raw, _, _ := proxy.UnwrapRawConn(conn)
	tc, ok := raw.(*gonet.TCPConn)
	if !ok {
		return
	}
	n := int(bytesPerSec)
	if n < 256*1024 {
		n = 256 * 1024
	}
	if n > 4<<20 {
		n = 4 << 20
	}
	_ = tc.SetReadBuffer(n)
}
