package gate

import (
	"sync"
	"time"
)

// TokenBucket is a classic fixed-window-ish burst limiter per key.
type TokenBucket struct {
	mu     sync.Mutex
	burst  int
	window time.Duration
	tokens map[string]*bucketState
}

type bucketState struct {
	count    int
	windowAt time.Time
}

// NewRateLimiter builds a limiter with per-key buckets. burst<=0 disables.
func NewRateLimiter(burst int, window time.Duration) *TokenBucket {
	if burst <= 0 || window <= 0 {
		return &TokenBucket{burst: 0}
	}
	return &TokenBucket{burst: burst, window: window, tokens: make(map[string]*bucketState)}
}

// Allow reports whether a call for key may proceed, consuming a token.
func (b *TokenBucket) Allow(key string) bool {
	if b.burst == 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	st, ok := b.tokens[key]
	if !ok || now.Sub(st.windowAt) >= b.window {
		st = &bucketState{count: 0, windowAt: now}
		b.tokens[key] = st
	}
	if st.count >= b.burst {
		return false
	}
	st.count++
	return true
}
