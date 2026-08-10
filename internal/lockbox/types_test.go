// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal/lockbox/types_test.go
package lockbox

import (
	"encoding/json"
	"testing"
)

func TestIntBytes_RoundTrip(t *testing.T) {
	original := IntBytes{0, 1, 127, 128, 255}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(b) != "[0,1,127,128,255]" {
		t.Fatalf("expected integer array, got %s", b)
	}
	var decoded IntBytes
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(decoded) != string(original) {
		t.Fatalf("round-trip mismatch: %v != %v", decoded, original)
	}
}

func TestCiphertext_Unmarshal(t *testing.T) {
	raw := `{"nonce":[1,2,3,4,5,6,7,8,9,10,11,12],"data":[99,100,101]}`
	var ct Ciphertext
	if err := json.Unmarshal([]byte(raw), &ct); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(ct.Nonce) != 12 || ct.Nonce[0] != 1 || ct.Nonce[11] != 12 {
		t.Fatalf("nonce wrong: %v", ct.Nonce)
	}
	if len(ct.Data) != 3 || ct.Data[0] != 99 {
		t.Fatalf("data wrong: %v", ct.Data)
	}
}

func TestSecretWithMetadata_Unmarshal(t *testing.T) {
	raw := `{
		"namespace": "prod",
		"name": "db-pass",
		"data": {"password": {"nonce":[1,2,3,4,5,6,7,8,9,10,11,12],"data":[42]}},
		"created_at": 1000,
		"updated_at": 2000,
		"deleted_at": null
	}`
	var s SecretWithMetadata
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.Namespace != "prod" || s.Name != "db-pass" {
		t.Fatalf("fields: %+v", s)
	}
	if s.DeletedAt != nil {
		t.Fatal("expected nil deleted_at")
	}
	ct, ok := s.Data["password"]
	if !ok || ct.Data[0] != 42 {
		t.Fatalf("data field: %+v", s.Data)
	}
}

func TestIntBytes_OutOfRange(t *testing.T) {
	err := json.Unmarshal([]byte("[256]"), new(IntBytes))
	if err == nil {
		t.Fatal("expected error for value 256")
	}
	err = json.Unmarshal([]byte("[-1]"), new(IntBytes))
	if err == nil {
		t.Fatal("expected error for value -1")
	}
}

func TestIntBytes_NullJSON(t *testing.T) {
	var b IntBytes
	if err := json.Unmarshal([]byte("null"), &b); err != nil {
		t.Fatalf("unmarshal null: %v", err)
	}
	if b != nil {
		t.Fatalf("expected nil, got %v", b)
	}
}

func TestSecretWithMetadata_SecretType_Opaque(t *testing.T) {
	// The common case: server sends "Opaque" as the secret_type.
	raw := `{
		"namespace": "prod",
		"name": "db-pass",
		"data": {},
		"created_at": 1,
		"updated_at": 2,
		"deleted_at": null,
		"secret_type": "Opaque"
	}`
	var s SecretWithMetadata
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.SecretType != "Opaque" {
		t.Fatalf("expected Opaque, got %q", s.SecretType)
	}
}

func TestSecretWithMetadata_SecretType_NonOpaque(t *testing.T) {
	// Non-standard type must pass through unchanged.
	raw := `{
		"namespace": "prod",
		"name": "reg",
		"data": {},
		"created_at": 1,
		"updated_at": 2,
		"deleted_at": null,
		"secret_type": "kubernetes.io/dockerconfigjson"
	}`
	var s SecretWithMetadata
	if err := json.Unmarshal([]byte(raw), &s); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if s.SecretType != "kubernetes.io/dockerconfigjson" {
		t.Fatalf("expected dockerconfigjson, got %q", s.SecretType)
	}
}
