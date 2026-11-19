package torrentguard

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// Signature reports (Marzban patch).
//
// The dispatcher's sniffers recognise plaintext BitTorrent: the peer
// handshake, uTP SYN, Mainline DHT krpc, UDP/HTTP tracker requests, LSD.
// Routing usually blackholes those connections, so on its own the block is
// invisible: the client quietly falls back to encrypted peers and nobody
// learns that the account runs a torrent client. Every match is counted here
// and logged for the panel as
//
//	TORRENTGUARD_SIGNATURE user=<username> src=<ip> hits=<n> peers=<n> kinds=dht:5,utp:2
//
// at most once per sigLogEvery for each (username, source IP): the first
// match is logged at once, later ones are summed up into the next line.
// hits — matches since the previous line, peers — distinct destinations
// among them.

const sigLogEvery = 30 * time.Second

type sigState struct {
	kinds   map[string]int
	peers   map[string]struct{}
	hits    int
	lastLog time.Time
}

var (
	sigMu     sync.Mutex
	sigStates = map[string]*sigState{}
	sigSwept  time.Time
)

// ReportSignature counts one sniffed BitTorrent signature of this user.
func ReportSignature(username, sourceIP, kind, dest string) {
	if username == "" || !Enabled() || isExempt(username) {
		return
	}
	if kind == "" {
		kind = "bittorrent"
	}
	now := time.Now()
	k := key(username, sourceIP)

	sigMu.Lock()
	if now.Sub(sigSwept) > 10*time.Minute {
		for sk, st := range sigStates {
			if now.Sub(st.lastLog) > 10*time.Minute && st.hits == 0 {
				delete(sigStates, sk)
			}
		}
		sigSwept = now
	}
	st := sigStates[k]
	if st == nil {
		st = &sigState{}
		sigStates[k] = st
	}
	if st.kinds == nil {
		st.kinds = map[string]int{}
		st.peers = map[string]struct{}{}
	}
	st.kinds[kind]++
	if dest != "" && len(st.peers) < 10000 {
		st.peers[dest] = struct{}{}
	}
	st.hits++
	if now.Sub(st.lastLog) < sigLogEvery {
		sigMu.Unlock()
		return
	}
	line := takeLine(username, sourceIP, st, now)
	sigMu.Unlock()
	logSignature(line)
}

// takeLine formats and resets the pending counts; called under sigMu.
func takeLine(username, sourceIP string, st *sigState, now time.Time) string {
	line := "TORRENTGUARD_SIGNATURE user=" + username + " src=" + sourceIP +
		" hits=" + strconv.Itoa(st.hits) + " peers=" + strconv.Itoa(len(st.peers)) +
		" kinds=" + formatKinds(st.kinds)
	st.kinds, st.peers, st.hits, st.lastLog = nil, nil, 0, now
	return line
}

func logSignature(line string) {
	errors.LogWarning(context.Background(), line)
}

// sigFlusher logs counts left pending when the matches stopped right after
// a line: without it they would wait for the next match forever.
func sigFlusher() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for now := range t.C {
		var lines []string
		sigMu.Lock()
		for k, st := range sigStates {
			if st.hits > 0 && now.Sub(st.lastLog) >= sigLogEvery {
				user, src, _ := strings.Cut(k, "\x00")
				lines = append(lines, takeLine(user, src, st, now))
			}
		}
		sigMu.Unlock()
		for _, l := range lines {
			logSignature(l)
		}
	}
}

func formatKinds(m map[string]int) string {
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(n)
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(m[n]))
	}
	return b.String()
}
