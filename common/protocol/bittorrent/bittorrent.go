package bittorrent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"github.com/xtls/xray-core/common"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBittorrent = errors.New("not bittorrent header")

func SniffBittorrent(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	if b[0] == 19 && string(b[1:20]) == "BitTorrent protocol" {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, common.ErrNoClue
	}

	// type 4 (ST_SYN), version 1
	if b[0] != 0x41 {
		return nil, errNotBittorrent
	}

	// timestamp_difference is always 0 in new connections
	if binary.BigEndian.Uint32(b[8:12]) != 0 {
		return nil, errNotBittorrent
	}

	// Walk the extension chain. Selective ack (1) and extension bits (2)
	extension, offset := b[1], 20
	for extension != 0 {
		if len(b) < offset+2 {
			return nil, errNotBittorrent
		}
		length := int(b[offset+1])
		switch extension {
		case 1: // selective ack
			if length < 4 || length%4 != 0 {
				return nil, errNotBittorrent
			}
		case 2: // extension bits: fixed 8 bytes, sent in ST_SYN by µTorrent
			if length != 8 {
				return nil, errNotBittorrent
			}
		default:
			return nil, errNotBittorrent
		}
		if len(b) < offset+2+length {
			return nil, errNotBittorrent
		}
		extension = b[offset]
		offset += 2 + length
	}

	// extensions should consume all ST_SYN payload
	if len(b) != offset {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

// SniffUDPTracker matches a BEP-15 UDP tracker "connect" request: an 8-byte
// magic protocol_id, action=0 (connect), then a client-chosen transaction_id.
func SniffUDPTracker(b []byte) (*SniffHeader, error) {
	if len(b) < 16 {
		return nil, common.ErrNoClue
	}

	if binary.BigEndian.Uint64(b[0:8]) != 0x41727101980 {
		return nil, errNotBittorrent
	}
	if binary.BigEndian.Uint32(b[8:12]) != 0 {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

// SniffDHT matches a Mainline DHT (BEP-5) bencoded krpc message by its
// well-known top-level prefixes: query ("q"), response ("r"), BEP-42 "ip"
// key, or error ("e").
var dhtPrefixes = [][]byte{
	[]byte("d1:ad"),
	[]byte("d1:rd"),
	[]byte("d2:ip"),
	[]byte("d1:el"),
}

func SniffDHT(b []byte) (*SniffHeader, error) {
	if len(b) < 5 {
		return nil, common.ErrNoClue
	}

	for _, p := range dhtPrefixes {
		if bytes.HasPrefix(b, p) {
			return &SniffHeader{}, nil
		}
	}

	return nil, errNotBittorrent
}

// SniffLSD matches BEP-14 Local Service Discovery, sent as an HTTP-shaped
// multicast announcement rather than a real HTTP request.
var lsdPrefix = []byte("BT-SEARCH * HTTP/1.1\r\n")

func SniffLSD(b []byte) (*SniffHeader, error) {
	if len(b) < len(lsdPrefix) {
		return nil, common.ErrNoClue
	}

	if bytes.HasPrefix(b, lsdPrefix) {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

// SniffHTTPTracker matches a plain-HTTP BEP-3 tracker announce/scrape
// request (GET/HEAD with an "/announce" or "/scrape" path and an
// "info_hash=" query parameter). Placed ahead of the generic http.SniffHTTP
// in the sniffer list so trackers get tagged "bittorrent" instead of "http1"
// for routing purposes; falls through (non-ErrNoClue) for anything else so
// http.SniffHTTP still handles ordinary HTTP traffic.
const maxHTTPTrackerScan = 4096

func SniffHTTPTracker(b []byte) (*SniffHeader, error) {
	nl := bytes.IndexByte(b, '\n')
	if nl < 0 {
		if len(b) >= maxHTTPTrackerScan {
			return nil, errNotBittorrent
		}
		return nil, common.ErrNoClue
	}
	line := string(bytes.TrimRight(b[:nl], "\r"))

	var method string
	switch {
	case strings.HasPrefix(line, "GET "):
		method = "GET "
	case strings.HasPrefix(line, "HEAD "):
		method = "HEAD "
	default:
		return nil, errNotBittorrent
	}

	rest := strings.TrimPrefix(line, method)
	target, _, ok := strings.Cut(rest, " ")
	if !ok {
		return nil, errNotBittorrent
	}
	path, query, _ := strings.Cut(target, "?")
	if !strings.Contains(path, "/announce") && !strings.Contains(path, "/scrape") {
		return nil, errNotBittorrent
	}
	if !strings.Contains(query, "info_hash=") {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}
