// Package secrets provides AES-GCM encryption/decryption for embedded secrets.
// At build time, a tool encrypts secrets and generates Go source with the ciphertext.
// At runtime, the generated code decrypts them.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

// Encrypt encrypts plaintext with AES-256-GCM using the given 32-byte key.
// Returns nonce + ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts AES-256-GCM ciphertext (nonce prepended) with the given 32-byte key.
func Decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm: %w", err)
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce := ciphertext[:gcm.NonceSize()]
	return gcm.Open(nil, nonce, ciphertext[gcm.NonceSize():], nil)
}

// SplitKey splits a 32-byte key into two parts using XOR with a random mask.
// key = part1 XOR part2
func SplitKey(key []byte) (part1, part2 []byte, err error) {
	part1 = make([]byte, len(key))
	part2 = make([]byte, len(key))
	if _, err := rand.Read(part1); err != nil {
		return nil, nil, err
	}
	for i := range key {
		part2[i] = key[i] ^ part1[i]
	}
	return part1, part2, nil
}

// JoinKey reconstructs a key from two XOR'd parts.
func JoinKey(part1, part2 []byte) []byte {
	key := make([]byte, len(part1))
	for i := range part1 {
		key[i] = part1[i] ^ part2[i]
	}
	return key
}
