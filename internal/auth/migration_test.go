package auth

import "testing"

// A client keeps using the token it always had; only the server-side storage
// changes. This is the property the migration depends on.
func TestMigratedFileAcceptsTheOriginalToken(t *testing.T) {
	const originalToken = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"

	before, err := NewUserStoreFromData(originalToken + ":wilmer:pro\n")
	if err != nil {
		t.Fatalf("plaintext load: %v", err)
	}
	after, err := NewUserStoreFromData(HashToken(originalToken) + ":wilmer:pro\n")
	if err != nil {
		t.Fatalf("hashed load: %v", err)
	}

	for name, store := range map[string]*UserStore{"plaintext": before, "hashed": after} {
		user, ok := store.Authenticate(originalToken)
		if !ok {
			t.Fatalf("%s store rejected the original token", name)
		}
		if user.Username != "wilmer" || user.Plan != "pro" {
			t.Errorf("%s store returned %+v", name, *user)
		}
	}
	if _, ok := after.Authenticate("wrong-token"); ok {
		t.Error("hashed store accepted a wrong token")
	}
}
