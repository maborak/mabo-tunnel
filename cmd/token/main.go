// mabo-tunnel-token generates tunnel tokens and migrates a plaintext user file to
// the hashed format.
//
// The server stores only SHA-256(token), so a token is printed exactly once, at
// generation. There is no way to recover it afterwards — that is the point.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/maborak/mabo-tunnel/internal/auth"
)

const usage = `mabo-tunnel-token — manage Mabo Tunnel tokens

Usage:
  mabo-tunnel-token generate <username> [plan]      Generate a token and print its users.txt line
  mabo-tunnel-token hash <token>                    Print the stored hash for an existing token
  mabo-tunnel-token migrate <users-file>            Rewrite a plaintext user file in hashed form

Plan is "free" or "pro" (default: free).

The server keeps only the hash, so a generated token is shown once. Record it
when it is printed; it cannot be recovered from the user file or the binary.

Examples:
  mabo-tunnel-token generate alice pro >> data/users.txt
  mabo-tunnel-token migrate data/users.txt
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "generate":
		cmdGenerate(os.Args[2:])
	case "hash":
		cmdHash(os.Args[2:])
	case "migrate":
		cmdMigrate(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func cmdGenerate(args []string) {
	if len(args) < 1 {
		fatal("generate: username is required")
	}
	username := args[0]
	plan := "free"
	if len(args) > 1 {
		plan = args[1]
	}
	if plan != "free" && plan != "pro" {
		fatal("generate: plan must be 'free' or 'pro', got %q", plan)
	}
	if strings.ContainsAny(username, ": \t") {
		fatal("generate: username must not contain ':' or whitespace")
	}

	token, err := generateToken()
	if err != nil {
		fatal("generate: %v", err)
	}

	// The line goes to stdout so it can be appended to the user file; the token
	// goes to stderr so it is visible even when stdout is redirected.
	fmt.Fprintf(os.Stderr, "Token for %s (shown once, store it now):\n\n  %s\n\n", username, token)
	fmt.Printf("%s:%s:%s\n", auth.HashToken(token), username, plan)
}

func cmdHash(args []string) {
	if len(args) < 1 {
		fatal("hash: token is required")
	}
	fmt.Println(auth.HashToken(args[0]))
}

func cmdMigrate(args []string) {
	if len(args) < 1 {
		fatal("migrate: path to the user file is required")
	}
	path := args[0]

	f, err := os.Open(path)
	if err != nil {
		fatal("migrate: %v", err)
	}

	var out strings.Builder
	scanner := bufio.NewScanner(f)
	converted, alreadyHashed := 0, 0
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		if line == "" || strings.HasPrefix(line, "#") {
			out.WriteString(raw + "\n")
			continue
		}
		if strings.HasPrefix(line, auth.HashedPrefix) {
			out.WriteString(raw + "\n")
			alreadyHashed++
			continue
		}

		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			f.Close()
			fatal("migrate: line %d: expected token:username:plan, got %q", lineNum, line)
		}
		token := strings.TrimSpace(parts[0])
		username := strings.TrimSpace(parts[1])
		plan := strings.TrimSpace(parts[2])

		out.WriteString(fmt.Sprintf("%s:%s:%s\n", auth.HashToken(token), username, plan))
		converted++
	}
	if err := scanner.Err(); err != nil {
		f.Close()
		fatal("migrate: %v", err)
	}
	f.Close()

	if converted == 0 {
		fmt.Fprintf(os.Stderr, "Nothing to do: %d entries already hashed.\n", alreadyHashed)
		return
	}

	// Keep a copy of the original. It holds live tokens, so it is written
	// owner-only and should be destroyed once the migration is confirmed.
	backup := path + ".plaintext.bak"
	original, err := os.ReadFile(path)
	if err != nil {
		fatal("migrate: %v", err)
	}
	if err := os.WriteFile(backup, original, 0o600); err != nil {
		fatal("migrate: writing backup: %v", err)
	}
	if err := os.WriteFile(path, []byte(out.String()), 0o600); err != nil {
		fatal("migrate: writing %s: %v", path, err)
	}

	fmt.Fprintf(os.Stderr, "Hashed %d entries in %s (%d already hashed).\n", converted, path, alreadyHashed)
	fmt.Fprintf(os.Stderr, "Original saved to %s — it contains live tokens.\n", backup)
	fmt.Fprintf(os.Stderr, "Restart the server, confirm clients still connect, then shred the backup:\n")
	fmt.Fprintf(os.Stderr, "  rm -P %s\n", backup)
}

// generateToken returns 32 bytes of randomness as 64 hex characters.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
