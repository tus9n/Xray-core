package userkill

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestKillByUserAndEmail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var a, b, c atomic.Int32
	Track(ctx, "1.alice#VL3", func() { a.Add(1) })
	Track(ctx, "1.alice#VL10", func() { b.Add(1) })
	Track(ctx, "2.bob#VL3", func() { c.Add(1) })

	if n := Kill(nil, []string{"1.alice#VL10"}); n != 1 || b.Load() != 1 || a.Load() != 0 {
		t.Fatalf("email kill: n=%d a=%d b=%d", n, a.Load(), b.Load())
	}
	if n := Kill([]string{"alice"}, nil); n != 2 || a.Load() != 1 || b.Load() != 1 {
		t.Fatalf("user kill: n=%d a=%d b=%d (closer must run once)", n, a.Load(), b.Load())
	}
	if c.Load() != 0 {
		t.Fatal("bob must stay")
	}
	if !Blocked("1.alice#VL4") || Blocked("2.bob#VL3") {
		t.Fatal("blocked state wrong")
	}
}

func TestUntrackOnDone(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var a atomic.Int32
	Track(ctx, "3.carol#VL3", func() { a.Add(1) })
	cancel()
	time.Sleep(50 * time.Millisecond)
	if n := Kill([]string{"carol"}, nil); n != 0 || a.Load() != 0 {
		t.Fatalf("finished stream must be untracked: n=%d", n)
	}
}
