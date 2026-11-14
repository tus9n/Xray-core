package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/net"
	"golang.org/x/time/rate"
)

type testMeter struct {
	chunk int64
	total atomic.Int64
	lim   *rate.Limiter
}

func (m *testMeter) Chunk() int64 { return m.chunk }
func (m *testMeter) Done(ctx context.Context, n int64) {
	m.total.Add(n)
	for n > 0 {
		take := n
		if b := int64(m.lim.Burst()); take > b {
			take = b
		}
		_ = m.lim.WaitN(ctx, int(take))
		n -= take
	}
}

// tcpPair returns both ends of a loopback TCP connection.
func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	ch := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	c1, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2 := <-ch
	return c1.(*net.TCPConn), c2.(*net.TCPConn)
}

func TestMeteredSpliceIntegrityAndRate(t *testing.T) {
	const size = 3 << 20 // 3 MiB
	const bps = 2 << 20  // 2 MiB/s cap
	data := make([]byte, size)
	_, _ = rand.Read(data)

	srcW, srcR := tcpPair(t) // remote server side → what xray reads from
	dstW, dstR := tcpPair(t) // xray → client side
	defer srcW.Close()
	defer srcR.Close()
	defer dstW.Close()
	defer dstR.Close()

	go func() { _, _ = srcW.Write(data); _ = srcW.Close() }()

	got := make(chan []byte, 1)
	go func() { b, _ := io.ReadAll(dstR); got <- b }()

	m := &testMeter{chunk: 200 * 1024, lim: rate.NewLimiter(rate.Limit(bps), bps/5)}
	m.lim.AllowN(time.Now(), bps/5) // start with an empty bucket
	var rc, wc atomic.Int64
	start := time.Now()
	if err := meteredSplice(context.Background(), m, dstW, srcR, counter{&rc}, counter{&wc}); err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	_ = dstW.CloseWrite()

	b := <-got
	if !bytes.Equal(b, data) {
		t.Fatalf("data mismatch: got %d bytes, want %d", len(b), size)
	}
	if m.total.Load() != size || rc.Load() != size || wc.Load() != size {
		t.Fatalf("accounting: meter=%d read=%d write=%d want %d", m.total.Load(), rc.Load(), wc.Load(), size)
	}
	// 3 MiB at 2 MiB/s ≈ 1.5 s (minus at most one chunk of slack)
	if elapsed < 1200*time.Millisecond {
		t.Fatalf("cap not enforced: %v", elapsed)
	}
}

type counter struct{ v *atomic.Int64 }

func (c counter) Add(n int64) int64 { return c.v.Add(n) }
