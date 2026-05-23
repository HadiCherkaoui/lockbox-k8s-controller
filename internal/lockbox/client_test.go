// internal/lockbox/client_test.go
package lockbox

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient_DeltaSync_Success(t *testing.T) {
	ts := int64(9999)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case authChallengePath:
			_ = json.NewEncoder(w).Encode(ChallengeResponse{Challenge: make(IntBytes, 32)})
		case authVerifyPath:
			_ = json.NewEncoder(w).Encode(AuthResponse{Success: true, Token: "tok"})
		case secretsSyncPath:
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

func TestClient_DeltaSync_Paginates(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case authChallengePath:
			_ = json.NewEncoder(w).Encode(ChallengeResponse{Challenge: make(IntBytes, 32)})
		case authVerifyPath:
			_ = json.NewEncoder(w).Encode(AuthResponse{Success: true, Token: "tok"})
		case secretsSyncPath:
			calls++
			since := r.URL.Query().Get("since")
			if calls == 1 {
				// Page 1 must be requested with the original cursor.
				if since != "0" {
					http.Error(w, "page 1 since="+since, http.StatusBadRequest)
					return
				}
				// First page is full (pageLimit=1000) — caller must loop.
				secs := make([]SecretWithMetadata, pageLimit)
				for i := range secs {
					secs[i] = SecretWithMetadata{Namespace: "ns", Name: fmt.Sprintf("s%d", i)}
				}
				_ = json.NewEncoder(w).Encode(DeltaSyncResponse{Secrets: secs, ServerTime: 100})
				return
			}
			// Page 2 must advance the cursor to the server_time from page 1
			// — guards against a regression like `cursor = since` that
			// would re-request the same page forever.
			if since != "100" {
				http.Error(w, "page 2 since="+since+" (want 100)", http.StatusBadRequest)
				return
			}
			// Second page short — pagination terminates here.
			_ = json.NewEncoder(w).Encode(DeltaSyncResponse{
				Secrets:    []SecretWithMetadata{{Namespace: "ns", Name: "tail"}},
				ServerTime: 200,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := &Auth{endpoint: srv.URL, privKey: ed25519.NewKeyFromSeed(make([]byte, 32)), http: &http.Client{}}
	c := NewClient(srv.URL, a)
	secrets, serverTime, err := c.DeltaSync(context.Background(), 0)
	if err != nil {
		t.Fatalf("DeltaSync: %v", err)
	}
	if len(secrets) != pageLimit+1 {
		t.Fatalf("expected %d secrets across both pages, got %d", pageLimit+1, len(secrets))
	}
	if serverTime != 200 {
		t.Fatalf("serverTime should reflect last page: got %d", serverTime)
	}
	if calls != 2 {
		t.Fatalf("expected 2 /secrets/sync calls, got %d", calls)
	}
}

func TestClient_DeltaSync_RefreshesOn401(t *testing.T) {
	// First /secrets/sync request gets a 401 (simulating a JWT that expired
	// mid-pagination); after a fresh token is fetched the retry succeeds.
	tokens := []string{"old-token", "new-token"}
	tokenIdx := 0
	syncCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case authChallengePath:
			_ = json.NewEncoder(w).Encode(ChallengeResponse{Challenge: make(IntBytes, 32)})
		case authVerifyPath:
			tok := tokens[tokenIdx]
			tokenIdx++
			_ = json.NewEncoder(w).Encode(AuthResponse{Success: true, Token: tok})
		case secretsSyncPath:
			syncCalls++
			if syncCalls == 1 {
				http.Error(w, "expired", http.StatusUnauthorized)
				return
			}
			// The retry must carry the refreshed bearer.
			if got := r.Header.Get("Authorization"); got != "Bearer new-token" {
				http.Error(w, "wrong token: "+got, http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(DeltaSyncResponse{
				Secrets:    []SecretWithMetadata{{Namespace: "ns", Name: "s1"}},
				ServerTime: 10,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := &Auth{endpoint: srv.URL, privKey: ed25519.NewKeyFromSeed(make([]byte, 32)), http: &http.Client{}}
	c := NewClient(srv.URL, a)
	secrets, serverTime, err := c.DeltaSync(context.Background(), 0)
	if err != nil {
		t.Fatalf("DeltaSync: %v", err)
	}
	if len(secrets) != 1 || secrets[0].Name != "s1" {
		t.Fatalf("unexpected secrets: %v", secrets)
	}
	if serverTime != 10 {
		t.Fatalf("serverTime: got %d", serverTime)
	}
	if syncCalls != 2 {
		t.Fatalf("expected 2 sync calls (401 + retry), got %d", syncCalls)
	}
	if tokenIdx != 2 {
		t.Fatalf("expected 2 token fetches, got %d", tokenIdx)
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
