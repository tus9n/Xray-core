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
package userkill

import (
	"context"
	"encoding/json"
	"io"
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
)

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
	if email == "" || len(closers) == 0 {
		return
	}
	e := &entry{email: email, user: Username(email), closers: closers}
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
	if email == "" {
		return false
	}
	mu.Lock()
	defer mu.Unlock()
	if len(blocked) == 0 {
		return false
	}
	now := time.Now()
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

type killRequest struct {
	Users  []string `json:"users"`
	Emails []string `json:"emails"`
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
	n := Kill(req.Users, req.Emails)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{"killed": n})
}

func init() {
	localpush.Register("/kill-users", handleKill)
}
