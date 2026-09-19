package gate

import (
	"sync"
	"time"
)

// TokenBucket is a thread-safe continuous token-bucket rate limiter per key.
type TokenBucket struct {
	mu     sync.Mutex
	burst  float64
	rate   float64 // tokens per second
	tokens map[string]*bucketState
}

type bucketState struct {
	tokens     float64
	lastRefill time.Time
}

// NewRateLimiter builds a limiter with per-key token buckets. burst<=0 disables.
func NewRateLimiter(burst int, window time.Duration) *TokenBucket {
	if burst <= 0 || window <= 0 {
		return &TokenBucket{burst: 0}
	}
	rate := float64(burst) / window.Seconds()
	return &TokenBucket{
		burst:  float64(burst),
		rate:   rate,
		tokens: make(map[string]*bucketState),
	}
}

// Allow reports whether a call for key may proceed, consuming a token.
func (b *TokenBucket) Allow(key string) bool {
	if b.burst <= 0 {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	st, ok := b.tokens[key]
	if !ok {
		st = &bucketState{tokens: b.burst, lastRefill: now}
		b.tokens[key] = st
	} else {
		elapsed := now.Sub(st.lastRefill).Seconds()
		if elapsed > 0 {
			st.tokens += elapsed * b.rate
			if st.tokens > b.burst {
				st.tokens = b.burst
			}
			st.lastRefill = now
		}
	}

	if st.tokens >= 1.0 {
		st.tokens -= 1.0
		return true
	}
	return false
}

