package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func testStore(t *testing.T) *UserStore {
	t.Helper()
	data := HashToken("tok-pro") + ":alice:pro\n" +
		HashToken("tok-free") + ":bob:free\n# comment\n"
	store, err := NewUserStoreFromData(data)
	if err != nil {
		t.Fatalf("NewUserStoreFromData: %v", err)
	}
	return store
}

func TestAuthenticate(t *testing.T) {
	store := testStore(t)

	cases := []struct {
		token    string
		wantUser string
		wantOK   bool
	}{
		{"tok-pro", "alice", true},
		{"tok-free", "bob", true},
		{"tok-pro ", "", false}, // trailing space is a different token
		{"nope", "", false},
		{"", "", false},
	}

	for _, tc := range cases {
		user, ok := store.Authenticate(tc.token)
		if ok != tc.wantOK {
			t.Errorf("Authenticate(%q) ok = %v, want %v", tc.token, ok, tc.wantOK)
			continue
		}
		if ok && user.Username != tc.wantUser {
			t.Errorf("Authenticate(%q) user = %q, want %q", tc.token, user.Username, tc.wantUser)
		}
	}
}

func TestUserStoreCount(t *testing.T) {
	if got := testStore(t).Count(); got != 2 {
		t.Errorf("Count() = %d, want 2", got)
	}
}

func TestParseRejectsBadPlan(t *testing.T) {
	if _, err := NewUserStoreFromData(HashToken("tok") + ":alice:enterprise\n"); err == nil {
		t.Error("expected an error for an unknown plan")
	}
}

// The stored form must not contain the token, or a leaked user file (or a
// binary embedding one) is a list of working credentials.
func TestStoredFormDoesNotContainTheToken(t *testing.T) {
	const token = "super-secret-token-value"
	stored := HashToken(token)

	if strings.Contains(stored, token) {
		t.Fatalf("HashToken(%q) = %q — the token itself must not appear", token, stored)
	}
	if !strings.HasPrefix(stored, HashedPrefix) {
		t.Errorf("stored form %q missing %q prefix", stored, HashedPrefix)
	}

	store, err := NewUserStoreFromData(stored + ":alice:pro\n")
	if err != nil {
		t.Fatalf("NewUserStoreFromData: %v", err)
	}
	if _, ok := store.Authenticate(token); !ok {
		t.Error("the real token should authenticate against its hash")
	}
	if _, ok := store.Authenticate(stored); ok {
		t.Error("presenting the stored hash must not authenticate — it is not the token")
	}

	// Nothing reachable from the store should reveal the token.
	user, _ := store.Authenticate(token)
	if fmt.Sprintf("%+v", *user) != "{Username:alice Plan:pro}" {
		t.Errorf("User carries unexpected fields: %+v", *user)
	}
}

// Existing deployments must keep working, and must be told they are exposed.
func TestPlaintextEntriesStillLoadButAreReported(t *testing.T) {
	store, err := NewUserStoreFromData("plain-token:alice:pro\n" + HashToken("hashed-token") + ":bob:free\n")
	if err != nil {
		t.Fatalf("NewUserStoreFromData: %v", err)
	}

	if _, ok := store.Authenticate("plain-token"); !ok {
		t.Error("legacy plaintext entry should still authenticate")
	}
	if _, ok := store.Authenticate("hashed-token"); !ok {
		t.Error("hashed entry should authenticate")
	}
	if got := store.PlaintextEntries(); got != 1 {
		t.Errorf("PlaintextEntries() = %d, want 1", got)
	}
}

func TestFullyHashedFileReportsNoPlaintext(t *testing.T) {
	store, err := NewUserStoreFromData(HashToken("a") + ":alice:pro\n" + HashToken("b") + ":bob:free\n")
	if err != nil {
		t.Fatalf("NewUserStoreFromData: %v", err)
	}
	if got := store.PlaintextEntries(); got != 0 {
		t.Errorf("PlaintextEntries() = %d, want 0", got)
	}
}

func TestParseRejectsMalformedHash(t *testing.T) {
	cases := []string{
		"sha256:nothex:alice:pro\n",
		"sha256:abcd:alice:pro\n", // right charset, wrong length
		"sha256::alice:pro\n",
	}
	for _, in := range cases {
		if _, err := NewUserStoreFromData(in); err == nil {
			t.Errorf("expected an error for %q", in)
		}
	}
}

// Lookup must not get slower as the user list grows — the old implementation
// compared against every entry.
func BenchmarkAuthenticate(b *testing.B) {
	data := ""
	for i := 0; i < 10000; i++ {
		data += fmt.Sprintf("%s:user%d:pro\n", HashToken(fmt.Sprintf("token-%d", i)), i)
	}
	store, err := NewUserStoreFromData(data)
	if err != nil {
		b.Fatalf("NewUserStoreFromData: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		store.Authenticate("token-9999")
	}
}

func TestRateLimiterBlocksAfterMax(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	defer rl.Stop()

	const ip = "203.0.113.1"
	for i := 0; i < 3; i++ {
		if !rl.Allow(ip) {
			t.Fatalf("attempt %d blocked before the limit", i+1)
		}
		rl.Record(ip)
	}
	if rl.Allow(ip) {
		t.Error("expected the address to be blocked after 3 failures")
	}
}

func TestRateLimiterRecoversAfterWindow(t *testing.T) {
	rl := NewRateLimiter(2, 100*time.Millisecond)
	defer rl.Stop()

	const ip = "203.0.113.2"
	rl.Record(ip)
	rl.Record(ip)
	if rl.Allow(ip) {
		t.Fatal("expected the address to be blocked")
	}

	time.Sleep(150 * time.Millisecond)
	if !rl.Allow(ip) {
		t.Error("expected the address to be allowed once the window passed")
	}
}

// Entries have to be released, or a spray of failed auths from many addresses
// grows the map for the life of the process.
func TestRateLimiterDropsExpiredEntries(t *testing.T) {
	rl := NewRateLimiter(5, 50*time.Millisecond)
	defer rl.Stop()

	for i := 0; i < 100; i++ {
		rl.Record(fmt.Sprintf("198.51.100.%d", i))
	}
	if got := rl.TrackedIPs(); got != 100 {
		t.Fatalf("TrackedIPs() = %d, want 100", got)
	}

	// The background sweep runs at the window cadence.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if rl.TrackedIPs() == 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Errorf("TrackedIPs() = %d after the window expired, want 0", rl.TrackedIPs())
}

func TestRateLimiterCapsTrackedAddresses(t *testing.T) {
	rl := NewRateLimiter(5, time.Hour) // long window: nothing expires on its own
	defer rl.Stop()
	rl.maxIPs = 10

	for i := 0; i < 50; i++ {
		rl.Record(fmt.Sprintf("192.0.2.%d", i))
	}

	if got := rl.TrackedIPs(); got > 10 {
		t.Errorf("TrackedIPs() = %d, want at most 10", got)
	}
}
