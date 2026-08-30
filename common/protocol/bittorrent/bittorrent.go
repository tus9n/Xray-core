package bittorrent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
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

	buffer := buf.FromBytes(b)

	var typeAndVersion uint8

	if binary.Read(buffer, binary.BigEndian, &typeAndVersion) != nil {
		return nil, common.ErrNoClue
	} else if b[0]>>4&0xF > 4 || b[0]&0xF != 1 {
		return nil, errNotBittorrent
	}

	var extension uint8

	if binary.Read(buffer, binary.BigEndian, &extension) != nil {
		return nil, common.ErrNoClue
	} else if extension != 0 && extension != 1 {
		return nil, errNotBittorrent
	}

	for extension != 0 {
		if extension != 1 {
			return nil, errNotBittorrent
		}
		if binary.Read(buffer, binary.BigEndian, &extension) != nil {
			return nil, common.ErrNoClue
		}

		var length uint8
		if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
			return nil, common.ErrNoClue
		}
		if common.Error2(buffer.ReadBytes(int32(length))) != nil {
			return nil, common.ErrNoClue
		}
	}

	if common.Error2(buffer.ReadBytes(2)) != nil {
		return nil, common.ErrNoClue
	}

	var timestamp uint32
	if err := binary.Read(buffer, binary.BigEndian, &timestamp); err != nil {
		return nil, common.ErrNoClue
	}
	if math.Abs(float64(time.Now().UnixMicro()-int64(timestamp))) > float64(24*time.Hour) {
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
