// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal/lockbox/crypto.go
package lockbox

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

// Decrypt decrypts a Lockbox Ciphertext using AES-256-GCM.
//
// Key derivation matches Rust's SymmetricKey::from_ed25519:
//
//	sym_key = signing_key.to_bytes()  // the raw 32-byte Ed25519 seed
//
// In Go, use ed25519.PrivateKey.Seed() to obtain the same 32 bytes.
func Decrypt(seed []byte, ct Ciphertext) ([]byte, error) {
	if len(seed) != 32 {
		return nil, fmt.Errorf("decrypt: seed must be 32 bytes, got %d", len(seed))
	}
	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, fmt.Errorf("decrypt: create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("decrypt: create GCM: %w", err)
	}
	plaintext, err := gcm.Open(nil, ct.Nonce, ct.Data, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
