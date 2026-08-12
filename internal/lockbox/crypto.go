// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal/lockbox/crypto.go
package lockbox

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
)

// aadDomain is the domain-separation prefix for AAD construction. Bump the
// suffix if the AAD layout ever changes, so an old server and a new client
// fail authentication instead of silently disagreeing.
const aadDomain = "lockbox-aad-v2"

// AADFor builds the additional authenticated data binding a ciphertext to the
// identity it claims: destination namespace, secret name, and field key.
//
// Each component is length-prefixed so no value can be shifted into an
// adjacent field by embedding a separator — ("ab", "c") and ("a", "bc") must
// not produce the same AAD.
//
// The Lockbox server must seal with the byte-identical construction.
//
// updated_at is deliberately NOT bound. The sealer cannot see it — the client
// encrypts before the request, and the server assigns the timestamp when it
// stores the row — and a partial update re-stamps it while leaving untouched
// fields' ciphertext as-is, which would leave those fields undecryptable.
//
// The consequence is explicit: this binds *location*, not *freshness*. It stops
// a blob being relocated to another namespace, name or field, but it does not
// stop an old blob for the same coordinates being replayed as current. Rollback
// protection needs a mechanism that does not ride on a field the sealer cannot
// see — a per-secret monotonic version the controller tracks, or a signature
// over the whole delta response.
func AADFor(namespace, name, field string) []byte {
	var b []byte
	for _, p := range []string{aadDomain, namespace, name, field} {
		b = binary.BigEndian.AppendUint32(b, uint32(len(p)))
		b = append(b, p...)
	}
	return b
}

// Decrypt decrypts a Lockbox Ciphertext using AES-256-GCM.
//
// Key derivation matches Rust's SymmetricKey::from_ed25519:
//
//	sym_key = signing_key.to_bytes()  // the raw 32-byte Ed25519 seed
//
// In Go, use ed25519.PrivateKey.Seed() to obtain the same 32 bytes.
//
// aad binds the ciphertext to its destination; pass nil to accept a blob that
// carries no such binding. A nil aad leaves the ciphertext relocatable: it
// will decrypt under any namespace, name or field the server claims for it.
// Callers should pass the result of AADFor once the server seals with it.
func Decrypt(seed []byte, ct Ciphertext, aad []byte) ([]byte, error) {
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
	// gcm.Open panics on a wrong-length nonce rather than returning an error,
	// so a malformed server response would crash the process without this.
	if len(ct.Nonce) != gcm.NonceSize() {
		return nil, fmt.Errorf("decrypt: nonce must be %d bytes, got %d", gcm.NonceSize(), len(ct.Nonce))
	}
	plaintext, err := gcm.Open(nil, ct.Nonce, ct.Data, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	return plaintext, nil
}
