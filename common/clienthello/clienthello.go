// Package clienthello — [MARZBAN] агрегатор подключений по отпечатку ClientHello (JA4)
// на пользователя: каким uTLS-отпечатком реально подключаются клиенты REALITY.
//
// Отдельно от общего stats.Manager намеренно: там одна карта счётчиков под одной
// блокировкой, и каждый опрос трафика панелью перебирает её целиком — тысячи
// счётчиков отпечатков замедлили бы штатный сбор трафика, а регистрация на каждое
// подключение конкурировала бы за ту же блокировку. Здесь — шарды со своими
// блокировками, а чтение забирает накопленное и очищает (Drain): на ноде живёт
// только то, что накоплено с прошлого опроса.
//
// Ограничения памяти: не больше maxKeysPerUser разных ключей на пользователя между
// опросами (иначе отпечаток "randomized", у которого JA4 каждый раз новый, плодил
// бы ключи на каждое подключение) — сверх них подключение уходит в ключ OtherJA4; и
// не больше maxKeysPerShard ключей в шарде на случай, если панель долго не читает.
package clienthello

import (
	"hash/fnv"
	"strconv"
	"sync"
)

// Prefix — имя счётчиков в ответе StatsService.QueryStats:
// clienthello>>>{email}>>>{тег инбаунда}>>>{JA4}>>>{длина ClientHello}.
const Prefix = "clienthello>>>"

// OtherJA4 — подключения сверх лимита разных ключей пользователя.
const OtherJA4 = "other"

const (
	shardCount      = 16
	maxKeysPerUser  = 16
	maxKeysPerShard = 1 << 16
)

type key struct {
	email  string
	tag    string
	ja4    string
	length int
}

type shard struct {
	mu      sync.Mutex
	counts  map[key]int64
	perUser map[string]int
}

var shards [shardCount]shard

func init() {
	for i := range shards {
		shards[i].counts = make(map[key]int64)
		shards[i].perUser = make(map[string]int)
	}
}

func shardFor(email string) *shard {
	h := fnv.New32a()
	_, _ = h.Write([]byte(email))
	return &shards[h.Sum32()%shardCount]
}

// Record учитывает одно подключение пользователя email через инбаунд tag.
func Record(email, tag, ja4 string, length int) {
	if email == "" || ja4 == "" {
		return
	}
	s := shardFor(email)
	k := key{email: email, tag: tag, ja4: ja4, length: length}
	s.mu.Lock()
	if _, ok := s.counts[k]; !ok {
		if s.perUser[email] >= maxKeysPerUser || len(s.counts) >= maxKeysPerShard {
			k = key{email: email, tag: tag, ja4: OtherJA4}
			if _, ok := s.counts[k]; !ok && len(s.counts) >= maxKeysPerShard {
				s.mu.Unlock()
				return
			}
		} else {
			s.perUser[email]++
		}
	}
	s.counts[k]++
	s.mu.Unlock()
}

// Entry — накопленное значение одного ключа.
type Entry struct {
	Name  string
	Value int64
}

// Drain забирает всё накопленное с прошлого вызова и очищает агрегатор.
// Блокировка шарда держится только на подмену карт.
func Drain() []Entry {
	var out []Entry
	for i := range shards {
		s := &shards[i]
		s.mu.Lock()
		counts := s.counts
		if len(counts) == 0 {
			s.mu.Unlock()
			continue
		}
		s.counts = make(map[key]int64, len(counts))
		s.perUser = make(map[string]int)
		s.mu.Unlock()
		for k, v := range counts {
			out = append(out, Entry{
				Name:  Prefix + k.email + ">>>" + k.tag + ">>>" + k.ja4 + ">>>" + strconv.Itoa(k.length),
				Value: v,
			})
		}
	}
	return out
}
