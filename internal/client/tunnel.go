package client

import (
	"math/rand"
	"time"
)

// ReconnectPolicy defines how the client reconnects after disconnection.
type ReconnectPolicy struct {
	InitialDelay time.Duration
	MaxDelay     time.Duration
	Multiplier   float64
	MaxRetries   int     // 0 = unlimited
	Jitter       float64 // fraction of the delay to randomize, 0 = none
}

// DefaultReconnectPolicy returns sensible defaults for reconnection.
func DefaultReconnectPolicy() ReconnectPolicy {
	return ReconnectPolicy{
		InitialDelay: 1 * time.Second,
		MaxDelay:     60 * time.Second,
		Multiplier:   2.0,
		MaxRetries:   0,
		// Without jitter every client that was connected to a restarting
		// server reconnects on exactly the same schedule, and they arrive as
		// one burst each time.
		Jitter: 0.2,
	}
}

// NextDelay calculates the next retry delay with exponential backoff and
// optional jitter.
func (p ReconnectPolicy) NextDelay(attempt int) time.Duration {
	delay := p.InitialDelay
	for i := 0; i < attempt; i++ {
		delay = time.Duration(float64(delay) * p.Multiplier)
		if delay > p.MaxDelay {
			delay = p.MaxDelay
			break
		}
	}

	if p.Jitter > 0 {
		// Spread within ±Jitter of the computed delay.
		spread := float64(delay) * p.Jitter
		delay = time.Duration(float64(delay) - spread + rand.Float64()*2*spread)
		if delay < 0 {
			delay = 0
		}
		if delay > p.MaxDelay {
			delay = p.MaxDelay
		}
	}

	return delay
}
