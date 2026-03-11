// internal/lockbox/client_test.go
package lockbox

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_DeltaSync_Success(t *testing.T) {
	ts := int64(9999)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth/challenge":
			_ = json.NewEncoder(w).Encode(ChallengeResponse{Challenge: make(IntBytes, 32)})
		case "/auth/verify":
			_ = json.NewEncoder(w).Encode(AuthResponse{Success: true, Token: "tok"})
		case "/secrets/sync":
			if r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(DeltaSyncResponse{
				Secrets: []SecretWithMetadata{
					{Namespace: "ns1", Name: "s1"},
				},
				ServerTime: ts,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	seed := make([]byte, 32)
	privKey := ed25519.NewKeyFromSeed(seed)
	a := &Auth{endpoint: srv.URL, privKey: privKey, http: &http.Client{}}
	c := NewClient(srv.URL, a)

	secrets, serverTime, err := c.DeltaSync(context.Background(), 0)
	if err != nil {
		t.Fatalf("DeltaSync: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Name != "s1" {
		t.Fatalf("unexpected secrets: %v", secrets)
	}
	if serverTime != ts {
		t.Fatalf("serverTime: got %d, want %d", serverTime, ts)
	}
}

func TestClient_DeltaSync_AuthError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusUnauthorized)
	}))
	defer srv.Close()

	seed := make([]byte, 32)
	a := &Auth{endpoint: srv.URL, privKey: ed25519.NewKeyFromSeed(seed), http: &http.Client{}}
	c := NewClient(srv.URL, a)

	_, _, err := c.DeltaSync(context.Background(), 0)
	if err == nil {
		t.Fatal("expected error")
	}
}
