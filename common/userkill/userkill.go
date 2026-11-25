// Package userkill closes a user's already established connections on
// demand (Marzban patch).
//
// Removing a user from an inbound (HandlerService.AlterInbound →
// RemoveUserOperation) only stops NEW handshakes: every connection that is
// already authenticated keeps running until the client closes it. A long
// mux / XHTTP / Vision session can carry a blocked user's traffic for hours.
//
// The dispatcher registers every dispatched stream of an authenticated user
// here together with its closers (the client connection itself and the
// stream's pipe ends). The panel pushes {"users": [...], "emails": [...]}
// to the shared local listener (common/localpush) at /kill-users right after
// it removed those users from the inbounds; every tracked stream that
// matches is torn down at once.
//
// For a short time after a kill the same user is refused at dispatch
// (Blocked): it covers a mux connection that opens one more sub-stream
// between the RemoveUser and the kill, without leaving any lasting state.
//
// "pairs": [{"user": "...", "ip": "..."}] closes only the streams of that
// user that came from that client address (one device: the panel deleted or
// blocked it), the user's other devices keep running. The pair is refused
// at dispatch for "block_sec" seconds (default blockFor).
package userkill

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/localpush"
)

// blockFor is how long a killed user is refused at dispatch.
const blockFor = 10 * time.Second

type entry struct {
	email   string
	user    string
	src     string // client IP, normalized (see normIP); "" if unknown
	closers []func()
	once    sync.Once
}

func (e *entry) close() {
	e.once.Do(func() {
		for _, c := range e.closers {
			func() {
				defer func() { _ = recover() }()
				c()
			}()
		}
	})
}

var (
	mu      sync.Mutex
	byUser  = map[string]map[*entry]struct{}{}
	blocked = map[string]time.Time{} // username or full email -> until
	// username + "|" + client IP -> until
	blockedPairs = map[string]time.Time{}
)

// normIP brings an address to one textual form ("::ffff:1.2.3.4" and
// "1.2.3.4" are the same client). Not an IP — returned as is.
func normIP(s string) string {
	s = strings.TrimSpace(s)
	if ip := net.ParseIP(s); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return v4.String()
		}
		return ip.String()
	}
	return s
}

func pairKey(user, ip string) string { return user + "|" + ip }

// Username strips Marzban's "<id>." prefix and "#<inbound>" suffix from a
// client email ("6865.sub_13002#VL3" → "sub_13002"), same rule as
// speedlimit.Username.
func Username(email string) string {
	if idx := strings.IndexByte(email, '.'); idx >= 0 {
		email = email[idx+1:]
	}
	if idx := strings.IndexByte(email, '#'); idx >= 0 {
		email = email[:idx]
	}
	return email
}

// Track registers one dispatched stream of the user with this email. The
// entry is dropped when ctx (the stream's context) is done.
func Track(ctx context.Context, email string, closers ...func()) {
	TrackFrom(ctx, email, "", closers...)
}

// TrackFrom is Track with the client address, so the stream can also be
// killed by a (user, ip) pair.
func TrackFrom(ctx context.Context, email, src string, closers ...func()) {
	if email == "" || len(closers) == 0 {
		return
	}
	e := &entry{email: email, user: Username(email), src: normIP(src), closers: closers}
	mu.Lock()
	set := byUser[e.user]
	if set == nil {
		set = map[*entry]struct{}{}
		byUser[e.user] = set
	}
	set[e] = struct{}{}
	mu.Unlock()
	context.AfterFunc(ctx, func() {
		mu.Lock()
		if set := byUser[e.user]; set != nil {
			delete(set, e)
			if len(set) == 0 {
				delete(byUser, e.user)
			}
		}
		mu.Unlock()
	})
}

// Blocked reports whether this email's user was killed less than blockFor
// ago.
func Blocked(email string) bool {
	return BlockedFrom(email, "")
}

// BlockedFrom is Blocked that also honours a pair kill of this client address.
func BlockedFrom(email, src string) bool {
	if email == "" {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	if len(blocked) == 0 && len(blockedPairs) == 0 {
		return false
	}
	now := time.Now()
	if src != "" && len(blockedPairs) > 0 {
		k := pairKey(Username(email), normIP(src))
		if until, ok := blockedPairs[k]; ok {
			if now.Before(until) {
				return true
			}
			delete(blockedPairs, k)
		}
	}
	for _, k := range [2]string{Username(email), email} {
		if until, ok := blocked[k]; ok {
			if now.Before(until) {
				return true
			}
			delete(blocked, k)
		}
	}
	return false
}

// Kill closes every tracked stream of the given usernames (all inbounds) and
// of the given full emails (one inbound each). Returns how many streams were
// closed.
func Kill(users, emails []string) int {
	until := time.Now().Add(blockFor)
	var victims []*entry
	mu.Lock()
	for _, u := range users {
		if u == "" {
			continue
		}
		blocked[u] = until
		for e := range byUser[u] {
			victims = append(victims, e)
		}
	}
	for _, em := range emails {
		if em == "" {
			continue
		}
		blocked[em] = until
		for e := range byUser[Username(em)] {
			if e.email == em {
				victims = append(victims, e)
			}
		}
	}
	mu.Unlock()
	seen := make(map[*entry]struct{}, len(victims))
	for _, e := range victims {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		e.close()
	}
	return len(seen)
}

// Pair is one device of a user: its client address.
type Pair struct {
	User string `json:"user"` // username or full email
	IP   string `json:"ip"`
}

// KillPairs closes the tracked streams of each user that came from the given
// client IP and refuses that pair at dispatch for block (blockFor if <= 0).
// Returns how many streams were closed.
func KillPairs(pairs []Pair, block time.Duration) int {
	if block <= 0 {
		block = blockFor
	}
	until := time.Now().Add(block)
	var victims []*entry
	mu.Lock()
	for _, p := range pairs {
		u, ip := Username(p.User), normIP(p.IP)
		if u == "" || ip == "" {
			continue
		}
		blockedPairs[pairKey(u, ip)] = until
		for e := range byUser[u] {
			if e.src == ip {
				victims = append(victims, e)
			}
		}
	}
	mu.Unlock()
	seen := make(map[*entry]struct{}, len(victims))
	for _, e := range victims {
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		e.close()
	}
	return len(seen)
}

type killRequest struct {
	Users    []string `json:"users"`
	Emails   []string `json:"emails"`
	Pairs    []Pair   `json:"pairs"`
	BlockSec int      `json:"block_sec"`
}

func handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var req killRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n := 0
	if len(req.Users) > 0 || len(req.Emails) > 0 {
		n += Kill(req.Users, req.Emails)
	}
	if len(req.Pairs) > 0 {
		block := time.Duration(req.BlockSec) * time.Second
		if block > time.Hour {
			block = time.Hour
		}
		n += KillPairs(req.Pairs, block)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"killed": n})
}

func init() {
	localpush.Register("/kill-users", handleKill)
}
