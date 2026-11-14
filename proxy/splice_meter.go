package proxy

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// Marzban patch: splice for users with a speed limit or torrent tracking.
//
// Upstream splice copies the whole stream in one kernel call, so nothing can
// meter it: our speed limiter and torrentguard therefore disabled splice for
// every such user, and with a default per-user limit that was everyone — the
// download direction always went through Go buffers (≈⅓ of xray CPU in
// profiles). A SpliceMeter keeps the kernel copy but splits it into chunks:
// after each chunk the bytes are accounted (user stats, torrentguard) and the
// shared per-user limiter is charged, so the aggregate cap across all of a
// user's connections behaves as before.
type SpliceMeter interface {
	// Chunk is the max bytes per kernel copy step (≥ 4 KiB).
	Chunk() int64
	// Done accounts n bytes just copied and blocks until the limiter admits
	// them (fail-open: never returns an error, never blocks forever).
	Done(ctx context.Context, n int64)
}

type spliceMeterKey struct{}

// WithSpliceMeter attaches m to ctx for CopyRawConnIfExist's splice step.
func WithSpliceMeter(ctx context.Context, m SpliceMeter) context.Context {
	if m == nil {
		return ctx
	}
	return context.WithValue(ctx, spliceMeterKey{}, m)
}

func spliceMeterFrom(ctx context.Context) SpliceMeter {
	m, _ := ctx.Value(spliceMeterKey{}).(SpliceMeter)
	return m
}

type byteCounter interface{ Add(int64) int64 }

// meteredSplice copies readerConn → tc in kernel chunks (splice on Linux:
// net.TCPConn.ReadFrom of an io.LimitedReader over a TCP conn). Data is
// forwarded as it arrives inside a chunk; accounting/limiting happen per chunk.
func meteredSplice(ctx context.Context, m SpliceMeter, tc *net.TCPConn, readerConn net.Conn, readCounter, writeCounter byteCounter) error {
	for {
		chunk := m.Chunk()
		if chunk < 4096 {
			chunk = 4096
		}
		w, err := tc.ReadFrom(&io.LimitedReader{R: readerConn, N: chunk})
		if w > 0 {
			if readCounter != nil {
				readCounter.Add(w)
			}
			if writeCounter != nil {
				writeCounter.Add(w)
			}
			m.Done(ctx, w)
		}
		if err != nil {
			if errors.Cause(err) == io.EOF {
				return nil
			}
			return err
		}
		if w < chunk { // LimitedReader stopped early: source reached EOF
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}
