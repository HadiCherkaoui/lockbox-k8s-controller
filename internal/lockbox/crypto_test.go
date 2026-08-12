// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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
func encryptForTest(seed, nonce, plaintext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func testKeyMaterial() (seed, nonce []byte) {
	seed = make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	nonce = make([]byte, 12)
	for i := range nonce {
		nonce[i] = byte(i + 50)
	}
	return seed, nonce
}

func TestDecrypt_RoundTrip(t *testing.T) {
	seed, nonce := testKeyMaterial()
	plaintext := []byte("super-secret-password")

	cipherdata, err := encryptForTest(seed, nonce, plaintext, nil)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	ct := Ciphertext{Nonce: IntBytes(nonce), Data: IntBytes(cipherdata)}
	got, err := Decrypt(seed, ct, nil)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecrypt_RoundTripWithAAD(t *testing.T) {
	seed, nonce := testKeyMaterial()
	plaintext := []byte("super-secret-password")
	aad := AADFor("prod", "db-credentials", "password")

	cipherdata, err := encryptForTest(seed, nonce, plaintext, aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	ct := Ciphertext{Nonce: IntBytes(nonce), Data: IntBytes(cipherdata)}
	got, err := Decrypt(seed, ct, aad)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("mismatch: got %q, want %q", got, plaintext)
	}
}

func TestDecrypt_AADMismatchFails(t *testing.T) {
	seed, nonce := testKeyMaterial()
	sealed := AADFor("prod", "db-credentials", "password")

	cipherdata, err := encryptForTest(seed, nonce, []byte("prod-password"), sealed)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct := Ciphertext{Nonce: IntBytes(nonce), Data: IntBytes(cipherdata)}

	// Each of these is the same blob presented under a different identity.
	for name, aad := range map[string][]byte{
		"other namespace": AADFor("attacker", "db-credentials", "password"),
		"other name":      AADFor("prod", "loot", "password"),
		"other field":     AADFor("prod", "db-credentials", "tls.key"),
		"no binding":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Decrypt(seed, ct, aad); err == nil {
				t.Fatalf("expected authentication failure for %s", name)
			}
		})
	}
}

// TestDecrypt_AADDoesNotBindFreshness documents a deliberate gap rather than a
// guarantee: the same coordinates always produce the same AAD, so a blob
// captured from an earlier revision of a secret still authenticates when the
// server replays it as current. AAD binds location, not freshness — see the
// note on AADFor. Anything relying on rollback protection needs a separate
// mechanism, and this test exists so that assumption is never made silently.
func TestDecrypt_AADDoesNotBindFreshness(t *testing.T) {
	seed, nonce := testKeyMaterial()
	aad := AADFor("prod", "db-credentials", "password")

	cipherdata, err := encryptForTest(seed, nonce, []byte("revoked-password"), aad)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	ct := Ciphertext{Nonce: IntBytes(nonce), Data: IntBytes(cipherdata)}

	if _, err := Decrypt(seed, ct, AADFor("prod", "db-credentials", "password")); err != nil {
		t.Fatalf("AAD is not expected to prevent replay at the same coordinates: %v", err)
	}
}

func TestAADFor_IsUnambiguous(t *testing.T) {
	// Length prefixing must stop one component bleeding into the next: a
	// namespace of "ab" with name "c" must not collide with "a" and "bc".
	if bytes.Equal(AADFor("ab", "c", "f"), AADFor("a", "bc", "f")) {
		t.Fatal("AAD components are ambiguous — a value can be shifted between fields")
	}
	if !bytes.Equal(AADFor("ns", "name", "field"), AADFor("ns", "name", "field")) {
		t.Fatal("AAD is not deterministic")
	}
}

func TestDecrypt_WrongSeed(t *testing.T) {
	seed := make([]byte, 32)
	nonce := make([]byte, 12)

	cipherdata, _ := encryptForTest(seed, nonce, []byte("secret"), nil)
	ct := Ciphertext{Nonce: IntBytes(nonce), Data: IntBytes(cipherdata)}

	wrongSeed := make([]byte, 32)
	wrongSeed[0] = 0xFF
	if _, err := Decrypt(wrongSeed, ct, nil); err == nil {
		t.Fatal("expected error with wrong seed")
	}
}

func TestDecrypt_BadSeedLen(t *testing.T) {
	if _, err := Decrypt([]byte("short"), Ciphertext{Nonce: make([]byte, 12), Data: []byte{}}, nil); err == nil {
		t.Fatal("expected error for short seed")
	}
}

func TestDecrypt_BadNonceLenDoesNotPanic(t *testing.T) {
	// crypto/cipher panics rather than erroring on a wrong-length nonce, so a
	// malformed server response would otherwise crash-loop the controller.
	seed := make([]byte, 32)
	for _, n := range []int{0, 1, 11, 13, 32} {
		ct := Ciphertext{Nonce: make([]byte, n), Data: []byte{1, 2, 3}}
		if _, err := Decrypt(seed, ct, nil); err == nil {
			t.Fatalf("expected error for %d-byte nonce", n)
		}
	}
}
