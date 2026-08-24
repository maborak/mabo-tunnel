package auth

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// User represents an authenticated user.
//
// The token itself is deliberately not stored. The server only ever needs to
// verify a token a client presents, never to reproduce one, so keeping only its
// hash means a leaked user file — or a decompiled binary with the file embedded
// — yields no usable credential.
type User struct {
	Username string
	Plan     string // "free" or "pro"
}

// HashedPrefix marks a pre-hashed entry in the user file.
const HashedPrefix = "sha256:"

// UserStore manages users loaded from a flat file.
//
// Preferred line format is the hashed one:
//
//	sha256:<64 hex chars>:username:plan
//
// Plaintext lines (token:username:plan) are still accepted so existing
// deployments keep working, but they are hashed at load and reported by
// PlaintextEntries — a plaintext file is a credential list, and should be
// migrated with `mabo-tunnel-token migrate`.
type UserStore struct {
	mu    sync.RWMutex
	users map[[32]byte]*User
	path  string

	// plaintextEntries counts users loaded from unhashed lines.
	plaintextEntries int
}

// tokenKey hashes a token into its map key.
func tokenKey(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

// HashToken returns the storable hash of a token: "sha256:" + hex digest.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return HashedPrefix + hex.EncodeToString(sum[:])
}

// parseHashedToken decodes a "sha256:<hex>" field into a map key.
func parseHashedToken(field string) ([32]byte, error) {
	var key [32]byte
	raw, err := hex.DecodeString(strings.TrimPrefix(field, HashedPrefix))
	if err != nil {
		return key, fmt.Errorf("invalid token hash: %w", err)
	}
	if len(raw) != sha256.Size {
		return key, fmt.Errorf("invalid token hash: expected %d bytes, got %d", sha256.Size, len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

// RateLimiter tracks failed auth attempts per IP.
type RateLimiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	maxRate  int           // max attempts per window
	window   time.Duration // time window
	maxIPs   int           // hard cap on tracked IPs
	stopCh   chan struct{}
	stopOnce sync.Once
}

// maxTrackedIPs bounds the rate limiter's memory. Past this many distinct
// addresses the oldest entries are shed, so a spray of failed auths from many
// sources cannot grow the map without limit.
const maxTrackedIPs = 10000

// NewRateLimiter creates a rate limiter and starts a background sweep that
// evicts addresses whose attempts have all aged out of the window.
func NewRateLimiter(maxRate int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		attempts: make(map[string][]time.Time),
		maxRate:  maxRate,
		window:   window,
		maxIPs:   maxTrackedIPs,
		stopCh:   make(chan struct{}),
	}
	go rl.sweepLoop()
	return rl
}

// Stop halts the background sweep.
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() { close(rl.stopCh) })
}

func (rl *RateLimiter) sweepLoop() {
	// Sweep at the window cadence — often enough that expired entries do not
	// accumulate, rarely enough to be free.
	interval := rl.window
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			rl.sweep()
		case <-rl.stopCh:
			return
		}
	}
}

// sweep drops every address whose most recent attempt has aged out.
func (rl *RateLimiter) sweep() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	for ip, attempts := range rl.attempts {
		if len(attempts) == 0 || attempts[len(attempts)-1].Before(cutoff) {
			delete(rl.attempts, ip)
		}
	}
}

// Allow checks if an IP is allowed to attempt authentication.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Prune old attempts.
	attempts := rl.attempts[ip]
	valid := attempts[:0]
	for _, t := range attempts {
		if t.After(cutoff) {
			valid = append(valid, t)
		}
	}
	if len(valid) == 0 {
		delete(rl.attempts, ip)
	} else {
		rl.attempts[ip] = valid
	}

	return len(valid) < rl.maxRate
}

// Record records a failed auth attempt for an IP.
func (rl *RateLimiter) Record(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Shed the stalest entries if we are at the cap, so a distributed spray of
	// bad tokens cannot grow this map indefinitely.
	if len(rl.attempts) >= rl.maxIPs {
		if _, tracked := rl.attempts[ip]; !tracked {
			rl.evictOldestLocked()
		}
	}
	rl.attempts[ip] = append(rl.attempts[ip], time.Now())
}

// evictOldestLocked removes the entry with the oldest most-recent attempt.
// Must be called with rl.mu held.
func (rl *RateLimiter) evictOldestLocked() {
	var oldestIP string
	var oldest time.Time
	for ip, attempts := range rl.attempts {
		if len(attempts) == 0 {
			delete(rl.attempts, ip)
			return
		}
		newest := attempts[len(attempts)-1]
		if oldestIP == "" || newest.Before(oldest) {
			oldestIP, oldest = ip, newest
		}
	}
	if oldestIP != "" {
		delete(rl.attempts, oldestIP)
	}
}

// TrackedIPs returns how many addresses the limiter currently holds.
func (rl *RateLimiter) TrackedIPs() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.attempts)
}

// NewUserStore creates a UserStore and loads users from the given file path.
func NewUserStore(path string) (*UserStore, error) {
	store := &UserStore{
		users: make(map[[32]byte]*User),
		path:  path,
	}
	if err := store.Reload(); err != nil {
		return nil, err
	}
	return store, nil
}

// NewUserStoreFromData creates a UserStore from raw users data (same format as users.txt).
func NewUserStoreFromData(data string) (*UserStore, error) {
	store := &UserStore{
		users: make(map[[32]byte]*User),
		path:  "(embedded)",
	}
	if err := store.parse(data); err != nil {
		return nil, err
	}
	return store, nil
}

// Reload reads the users file and replaces the in-memory store.
func (s *UserStore) Reload() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return fmt.Errorf("open users file %s: %w", s.path, err)
	}
	return s.parse(string(data))
}

// parse parses users data and replaces the in-memory store. Accepts both the
// hashed form (sha256:<hex>:username:plan) and the legacy plaintext form
// (token:username:plan). Supports newline and pipe (|) as line separators, the
// latter used when data is baked in via ldflags.
func (s *UserStore) parse(data string) error {
	data = strings.ReplaceAll(data, "|", "\n")
	users := make(map[[32]byte]*User)
	plaintext := 0
	scanner := bufio.NewScanner(strings.NewReader(data))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		var key [32]byte
		var username, plan string

		if strings.HasPrefix(line, HashedPrefix) {
			// sha256:<hex>:username:plan
			rest := strings.TrimPrefix(line, HashedPrefix)
			parts := strings.SplitN(rest, ":", 3)
			if len(parts) != 3 {
				return fmt.Errorf("users data line %d: expected %s<hash>:username:plan, got %q", lineNum, HashedPrefix, line)
			}
			k, err := parseHashedToken(strings.TrimSpace(parts[0]))
			if err != nil {
				return fmt.Errorf("users data line %d: %w", lineNum, err)
			}
			key, username, plan = k, strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
		} else {
			// Legacy: token:username:plan. Hash it now; the plaintext is not retained.
			parts := strings.SplitN(line, ":", 3)
			if len(parts) != 3 {
				return fmt.Errorf("users data line %d: expected token:username:plan, got %q", lineNum, line)
			}
			token := strings.TrimSpace(parts[0])
			if token == "" {
				return fmt.Errorf("users data line %d: token must not be empty", lineNum)
			}
			key, username, plan = tokenKey(token), strings.TrimSpace(parts[1]), strings.TrimSpace(parts[2])
			plaintext++
		}

		if username == "" {
			return fmt.Errorf("users data line %d: username must not be empty", lineNum)
		}
		if plan != "free" && plan != "pro" {
			return fmt.Errorf("users data line %d: plan must be 'free' or 'pro', got %q", lineNum, plan)
		}

		users[key] = &User{Username: username, Plan: plan}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse users data: %w", err)
	}

	s.mu.Lock()
	s.users = users
	s.plaintextEntries = plaintext
	s.mu.Unlock()

	return nil
}

// PlaintextEntries returns how many users were loaded from unhashed lines.
// Non-zero means the user file still holds usable credentials and should be
// migrated.
func (s *UserStore) PlaintextEntries() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.plaintextEntries
}

// Authenticate validates a token by hashing it and looking up the hash. The
// token itself is never stored, so there is nothing to compare it against and
// nothing for an attacker to read out of the file or the binary.
func (s *UserStore) Authenticate(token string) (*User, bool) {
	if token == "" {
		return nil, false
	}

	key := tokenKey(token)

	s.mu.RLock()
	defer s.mu.RUnlock()

	user, ok := s.users[key]
	if !ok {
		return nil, false
	}
	return user, true
}

// Count returns the number of loaded users.
func (s *UserStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}
