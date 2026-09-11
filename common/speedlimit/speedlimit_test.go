package speedlimit

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

func floatPtr(v float64) *float64 { return &v }
func stringPtr(v string) *string  { return &v }

func TestResolveLimitPlan(t *testing.T) {
	default20 := remoteConfig{}
	default20.Default.DownMbps = floatPtr(20)
	default20.Default.UpMbps = floatPtr(20)

	ordinaryUnlimited := default20
	ordinaryUnlimited.Users = map[string]userLimits{
		"alice": {DownMbps: floatPtr(0), UpMbps: floatPtr(0)},
	}

	unlimitedWithNodeCap := ordinaryUnlimited
	unlimitedWithNodeCap.Node = &nodeLimits{DownMbps: floatPtr(12)}

	overrideUnlimited := default20
	overrideUnlimited.UserInboundOverrides = map[string]map[string]userLimits{
		"alice": {"vless": {DownMbps: floatPtr(0)}},
	}

	totalWithInboundCap := default20
	totalWithInboundCap.DefaultScope = "total"
	totalWithInboundCap.Inbounds = map[string]inboundLimits{
		"vless": {DownMbps: floatPtr(8)},
	}

	perUserTotal := default20
	perUserTotal.Users = map[string]userLimits{
		"alice": {DownMbps: floatPtr(10), Scope: stringPtr("total")},
	}

	tests := []struct {
		name       string
		cfg        remoteConfig
		username   string
		tag        string
		up         bool
		wantTag    float64
		wantGlobal float64
	}{
		{name: "global default applies to ordinary user", cfg: default20, username: "alice", tag: "vless", wantTag: 2_500_000},
		{name: "ordinary explicit unlimited overrides default", cfg: ordinaryUnlimited, username: "alice", tag: "vless"},
		{name: "node cap still applies to unlimited user", cfg: unlimitedWithNodeCap, username: "alice", tag: "vless", wantTag: 1_500_000},
		{name: "per-inbound unlimited override suppresses default", cfg: overrideUnlimited, username: "alice", tag: "vless"},
		{name: "override only affects matching inbound", cfg: overrideUnlimited, username: "alice", tag: "trojan", wantTag: 2_500_000},
		{name: "total scope layers inbound and shared default", cfg: totalWithInboundCap, username: "alice", tag: "vless", wantTag: 1_000_000, wantGlobal: 2_500_000},
		{name: "per-user total scope uses shared user cap", cfg: perUserTotal, username: "alice", tag: "vless", wantGlobal: 1_250_000},
		{name: "direction is resolved independently", cfg: unlimitedWithNodeCap, username: "alice", tag: "vless", up: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := resolveLimitPlan(&test.cfg, test.username, test.tag, test.up)
			if got.tagBytesPerSec != test.wantTag || got.globalBytesPerSec != test.wantGlobal {
				t.Fatalf("resolveLimitPlan() = %+v, want tag=%v global=%v", got, test.wantTag, test.wantGlobal)
			}
		})
	}
}

func TestFastPathGuardInterruptedByConfigPush(t *testing.T) {
	resetSpeedlimitTestState(t)

	if guard := AllowFastPath("1.alice", "vless", false); guard != nil {
		t.Fatal("fast path must stay disabled before the first config push")
	}

	unlimited := remoteConfig{Users: map[string]userLimits{
		"alice": {DownMbps: floatPtr(0)},
	}}
	publishConfig(unlimited)
	guard := AllowFastPath("1.alice#vless", "vless", false)
	if guard == nil {
		t.Fatal("explicitly unlimited ordinary user should receive a fast-path guard")
	}

	var interrupted atomic.Int32
	stop, ok := guard.Activate(func() { interrupted.Add(1) })
	if !ok {
		t.Fatal("fresh guard activation failed")
	}

	limited := remoteConfig{Users: map[string]userLimits{
		"alice": {DownMbps: floatPtr(10)},
	}}
	publishConfig(limited)
	if got := interrupted.Load(); got != 1 {
		t.Fatalf("config push interrupted fast path %d times, want 1", got)
	}
	stop()
	publishConfig(limited)
	if got := interrupted.Load(); got != 1 {
		t.Fatalf("stopped guard interrupted again: got %d calls", got)
	}

	if _, ok := guard.Activate(func() {}); ok {
		t.Fatal("guard from stale config snapshot must not activate")
	}
	if guard := AllowFastPath("1.alice", "vless", false); guard != nil {
		t.Fatal("limited user must not receive a fast-path guard")
	}
}

func TestFastPathGuardStopPreventsInterrupt(t *testing.T) {
	resetSpeedlimitTestState(t)
	publishConfig(remoteConfig{})
	guard := AllowFastPath("1.alice", "vless", false)
	if guard == nil {
		t.Fatal("unlimited user should receive a fast-path guard")
	}

	var interrupted atomic.Int32
	stop, ok := guard.Activate(func() { interrupted.Add(1) })
	if !ok {
		t.Fatal("fresh guard activation failed")
	}
	stop()
	stop()
	publishConfig(remoteConfig{})
	if got := interrupted.Load(); got != 0 {
		t.Fatalf("stopped guard was interrupted %d times", got)
	}
}

func TestLimitedWriterConcurrentConfigUpdates(t *testing.T) {
	resetSpeedlimitTestState(t)
	publishConfig(remoteConfig{})
	writer := LimitWriter(context.Background(), buf.Discard, "1.alice", "vless", false)

	var writers sync.WaitGroup
	for range 8 {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for range 500 {
				b := buf.FromBytes([]byte{1})
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					t.Errorf("WriteMultiBuffer() failed: %v", err)
					return
				}
			}
		}()
	}

	for i := range 100 {
		next := remoteConfig{}
		if i%2 != 0 {
			next.Default.DownMbps = floatPtr(1_000_000)
		}
		publishConfig(next)
	}
	writers.Wait()
}

func resetSpeedlimitTestState(t *testing.T) {
	t.Helper()
	fastPathMu.Lock()
	currentConfig.Store(nil)
	fastPathWatchers = map[uint64]*fastPathWatcher{}
	fastPathNextID = 0
	fastPathMu.Unlock()
	regMu.Lock()
	reg = map[string]*entry{}
	regMu.Unlock()
	t.Cleanup(func() {
		fastPathMu.Lock()
		currentConfig.Store(nil)
		fastPathWatchers = map[uint64]*fastPathWatcher{}
		fastPathNextID = 0
		fastPathMu.Unlock()
		regMu.Lock()
		reg = map[string]*entry{}
		regMu.Unlock()
	})
}
