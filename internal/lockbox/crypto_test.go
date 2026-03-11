// internal/lockbox/crypto_test.go
package lockbox

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"testing"
)

// encryptForTest mirrors Lockbox's Rust encrypt to create test vectors.
// Uses stdlib AES-256-GCM with the given seed as key.
func encryptForTest(seed, nonce, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func TestDecrypt_RoundTrip(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	nonce := make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 50)
	}
	plaintext := []byte("super-secret-password")

	cipherdata, err := encryptForTest(seed, nonce, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	ct := Ciphertext{
		Nonce: IntBytes(nonce),
		Data:  IntBytes(cipherdata),
	}
	got, err := Decrypt(seed, ct)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecrypt_WrongSeed(t *testing.T) {
	seed := make([]byte, 32)
	nonce := make([]byte, 12)
	plaintext := []byte("secret")

	cipherdata, _ := encryptForTest(seed, nonce, plaintext)
	ct := Ciphertext{Nonce: IntBytes(nonce), Data: IntBytes(cipherdata)}

	wrongSeed := make([]byte, 32)
	wrongSeed[0] = 0xFF
	_, err := Decrypt(wrongSeed, ct)
	if err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestDecrypt_BadSeedLen(t *testing.T) {
	_, err := Decrypt([]byte("short"), Ciphertext{Nonce: make([]byte, 12), Data: []byte{}})
	if err == nil {
		t.Fatal("expected error for short seed")
	}
}
