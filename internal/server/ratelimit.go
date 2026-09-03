package server

import (
	"sync"
	"time"
)

// tokenBucket is a minimal refillable-bucket rate limiter. It exists so the
// edge can bound one tunnel's request rate without pulling in a dependency:
// the state is a token count and a timestamp, and Allow() is the whole API.
type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	capacity float64
	// refill is tokens gained per second.
	refill float64
	last   time.Time
}

// newTokenBucket builds a bucket admitting up to burst requests instantly,
// refilling at refillsPerSecond thereafter. Both values must be positive;
// callers gate on that before constructing the bucket.
func newTokenBucket(refillsPerSecond, burst int) *tokenBucket {
	if burst <= 0 {
		burst = refillsPerSecond
	}
	return &tokenBucket{
		tokens:   float64(burst),
		capacity: float64(burst),
		refill:   float64(refillsPerSecond),
		last:     time.Now(),
	}
}

// allow reports whether one request is admitted now, lazily refilling tokens
// for the time elapsed since the last call.
func (b *tokenBucket) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.refill
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
