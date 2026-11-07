package clienthello

import (
	"strconv"
	"sync"
	"testing"
)

func drainMap() map[string]int64 {
	m := map[string]int64{}
	for _, e := range Drain() {
		m[e.Name] += e.Value
	}
	return m
}

func TestRecordAndDrain(t *testing.T) {
	Drain()
	Record("1.a", "VL3", "t13x", 512)
	Record("1.a", "VL3", "t13x", 512)
	Record("2.b", "VL8", "t13y", 1887)
	m := drainMap()
	if m["clienthello>>>1.a>>>VL3>>>t13x>>>512"] != 2 || m["clienthello>>>2.b>>>VL8>>>t13y>>>1887"] != 1 || len(m) != 2 {
		t.Fatalf("unexpected: %v", m)
	}
	if len(Drain()) != 0 {
		t.Fatal("drain must clear")
	}
}

func TestPerUserCapGoesToOther(t *testing.T) {
	Drain()
	for i := 0; i < maxKeysPerUser+10; i++ {
		Record("3.r", "VL3", "rand"+strconv.Itoa(i), 512)
	}
	m := drainMap()
	if len(m) != maxKeysPerUser+1 {
		t.Fatalf("want %d keys, got %d", maxKeysPerUser+1, len(m))
	}
	if m["clienthello>>>3.r>>>VL3>>>other>>>0"] != 10 {
		t.Fatalf("overflow must go to other: %v", m)
	}
	// после чтения лимит сбрасывается
	Record("3.r", "VL3", "new", 512)
	if m := drainMap(); m["clienthello>>>3.r>>>VL3>>>new>>>512"] != 1 {
		t.Fatalf("cap must reset after drain: %v", m)
	}
}

func TestEmptyIgnoredAndConcurrent(t *testing.T) {
	Drain()
	Record("", "VL3", "x", 1)
	Record("4.c", "VL3", "", 1)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				Record("5.d", "VL3", "fp", 512)
			}
		}()
	}
	wg.Wait()
	m := drainMap()
	if len(m) != 1 || m["clienthello>>>5.d>>>VL3>>>fp>>>512"] != 8000 {
		t.Fatalf("unexpected: %v", m)
	}
}
