// internal/lockbox/types.go
package lockbox

import (
	"encoding/json"
	"fmt"
)

// IntBytes is a []byte that marshals to/from a JSON array of integers.
// Rust's serde serializes [u8; N] and Vec<u8> as integer arrays by default,
// not base64, so standard Go []byte encoding is incompatible.
type IntBytes []byte

func (b IntBytes) MarshalJSON() ([]byte, error) {
	nums := make([]int, len(b))
	for i, v := range b {
		nums[i] = int(v)
	}
	return json.Marshal(nums)
}

func (b *IntBytes) UnmarshalJSON(data []byte) error {
	var nums []int
	if err := json.Unmarshal(data, &nums); err != nil {
		return fmt.Errorf("IntBytes: expected integer array: %w", err)
	}
	*b = make([]byte, len(nums))
	for i, n := range nums {
		if n < 0 || n > 255 {
			return fmt.Errorf("IntBytes: value %d out of byte range at index %d", n, i)
		}
		(*b)[i] = byte(n)
	}
	return nil
}

// Ciphertext is an AES-256-GCM encrypted value from Lockbox.
type Ciphertext struct {
	Nonce IntBytes `json:"nonce"`
	Data  IntBytes `json:"data"`
}

// SecretWithMetadata is the delta sync event payload for one secret.
type SecretWithMetadata struct {
	Namespace string                `json:"namespace"`
	Name      string                `json:"name"`
	Data      map[string]Ciphertext `json:"data"`
	CreatedAt int64                 `json:"created_at"`
	UpdatedAt int64                 `json:"updated_at"`
	DeletedAt *int64                `json:"deleted_at"`
}

// DeltaSyncResponse is the response from GET /secrets/sync.
type DeltaSyncResponse struct {
	Secrets    []SecretWithMetadata `json:"secrets"`
	ServerTime int64                `json:"server_time"`
}

// Auth request/response types

type ChallengeRequest struct {
	PublicKey IntBytes `json:"public_key"`
}

type ChallengeResponse struct {
	Challenge IntBytes `json:"challenge"`
}

type AuthRequest struct {
	PublicKey IntBytes `json:"public_key"`
	Challenge IntBytes `json:"challenge"`
	Signature IntBytes `json:"signature"`
}

type AuthResponse struct {
	Success bool   `json:"success"`
	Token   string `json:"token"`
}

type RegisterKeyRequest struct {
	PublicKey IntBytes `json:"public_key"`
	Label     string   `json:"label"`
}
