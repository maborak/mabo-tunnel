package server

import (
	"testing"
	"time"
)

func TestTokenBucketAllowsBurstThenThrottles(t *testing.T) {
	b := newTokenBucket(10, 3)
	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("request %d within burst was rejected", i+1)
		}
	}
	if b.allow() {
		t.Error("request past the burst was admitted without any elapsed refill time")
	}
}

func TestTokenBucketRefillsOverTime(t *testing.T) {
	b := newTokenBucket(1000, 1)
	if !b.allow() {
		t.Fatal("first request should be admitted")
	}

	// Manually advance the clock instead of sleeping in tests.
	b.mu.Lock()
	b.last = b.last.Add(-200 * time.Millisecond)
	b.mu.Unlock()
	if !b.allow() {
		t.Error("bucket did not refill after simulated 200ms at 1000 rps")
	}
}

func TestNilBucketAllowsAll(t *testing.T) {
	var b *tokenBucket
	if !b.allow() {
		t.Error("nil bucket (rate limiting disabled) must admit every request")
	}
}
