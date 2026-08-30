package bittorrent

import (
	"testing"

	"github.com/xtls/xray-core/common"
)

func TestSniffUDPTracker(t *testing.T) {
	// protocol_id = 0x41727101980, action = 0 (connect), transaction_id arbitrary
	connect := []byte{0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80, 0, 0, 0, 0, 1, 2, 3, 4}
	if _, err := SniffUDPTracker(connect); err != nil {
		t.Fatalf("expected match, got %v", err)
	}

	notMatch := make([]byte, 16)
	if _, err := SniffUDPTracker(notMatch); err != errNotBittorrent {
		t.Fatalf("expected errNotBittorrent, got %v", err)
	}

	if _, err := SniffUDPTracker(make([]byte, 4)); err != common.ErrNoClue {
		t.Fatalf("expected ErrNoClue for short input, got %v", err)
	}
}

func TestSniffDHT(t *testing.T) {
	if _, err := SniffDHT([]byte("d1:ad2:id20:aaaaaaaaaaaaaaaaaaaae1:q4:ping1:t2:aa1:y1:qe")); err != nil {
		t.Fatalf("expected DHT query match, got %v", err)
	}
	if _, err := SniffDHT([]byte("not a dht packet")); err != errNotBittorrent {
		t.Fatalf("expected errNotBittorrent, got %v", err)
	}
	if _, err := SniffDHT([]byte("d1:")); err != common.ErrNoClue {
		t.Fatalf("expected ErrNoClue for short input, got %v", err)
	}
}

func TestSniffLSD(t *testing.T) {
	msg := "BT-SEARCH * HTTP/1.1\r\nHost: 239.192.152.143:6771\r\nInfohash: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n"
	if _, err := SniffLSD([]byte(msg)); err != nil {
		t.Fatalf("expected LSD match, got %v", err)
	}
	if _, err := SniffLSD([]byte("GET /some/long/enough/path HTTP/1.1\r\n\r\n")); err != errNotBittorrent {
		t.Fatalf("expected errNotBittorrent, got %v", err)
	}
}

func TestSniffHTTPTracker(t *testing.T) {
	announce := "GET /announce?info_hash=%00%01%02&peer_id=x&port=6881 HTTP/1.1\r\nHost: tracker.example\r\n\r\n"
	if _, err := SniffHTTPTracker([]byte(announce)); err != nil {
		t.Fatalf("expected tracker match, got %v", err)
	}

	scrape := "GET /scrape?info_hash=%00%01 HTTP/1.1\r\n\r\n"
	if _, err := SniffHTTPTracker([]byte(scrape)); err != nil {
		t.Fatalf("expected scrape match, got %v", err)
	}

	ordinary := "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
	if _, err := SniffHTTPTracker([]byte(ordinary)); err != errNotBittorrent {
		t.Fatalf("expected errNotBittorrent for ordinary GET, got %v", err)
	}

	post := "POST /announce?info_hash=x HTTP/1.1\r\n\r\n"
	if _, err := SniffHTTPTracker([]byte(post)); err != errNotBittorrent {
		t.Fatalf("expected errNotBittorrent for POST, got %v", err)
	}

	if _, err := SniffHTTPTracker([]byte("GET /announce?info")); err != common.ErrNoClue {
		t.Fatalf("expected ErrNoClue for incomplete request line, got %v", err)
	}
}
