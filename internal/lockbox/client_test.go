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

const deltaSyncErrFmt = "DeltaSync: %v"

// writeJSON encodes v as JSON and ignores the encode error — test handlers
// don't care about partial writes and ignoring errcheck-style errors keeps
// the call sites readable.
func writeJSON(w http.ResponseWriter, v any) {
	_ = json.NewEncoder(w).Encode(v)
}

// handleAuthMock answers /auth/challenge and /auth/verify with a hard-coded
// 32-byte zero challenge and the supplied token. Returns true if the request
// path matched (and the response is fully written), false otherwise — the
// caller's handler chains its own /secrets/sync logic when false.
func handleAuthMock(w http.ResponseWriter, r *http.Request, token string) bool {
	switch r.URL.Path {
	case authChallengePath:
		writeJSON(w, ChallengeResponse{Challenge: make(IntBytes, 32)})
		return true
	case authVerifyPath:
		writeJSON(w, AuthResponse{Success: true, Token: token})
		return true
	}
	return false
}

func TestClient_DeltaSync_Success(t *testing.T) {
	ts := int64(9999)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setJSONHeader(w)
		if handleAuthMock(w, r, "tok") {
			return
		}
		if r.URL.Path == secretsSyncPath {
			if r.Header.Get("Authorization") != "Bearer tok" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			writeJSON(w, DeltaSyncResponse{
				Secrets:    []SecretWithMetadata{{Namespace: "ns1", Name: "s1"}},
				ServerTime: ts,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	seed := make([]byte, 32)
	privKey := ed25519.NewKeyFromSeed(seed)
	a := &Auth{endpoint: srv.URL, privKey: privKey, http: &http.Client{}}
	c := NewClient(srv.URL, a)

	secrets, serverTime, err := c.DeltaSync(context.Background(), 0)
	if err != nil {
		t.Fatalf(deltaSyncErrFmt, err)
	}
	if len(secrets) != 1 || secrets[0].Name != "s1" {
		t.Fatalf("unexpected secrets: %v", secrets)
	}
	if serverTime != ts {
		t.Fatalf("serverTime: got %d, want %d", serverTime, ts)
	}
}

// paginateSyncPage emits one mocked page of /secrets/sync, asserting that the
// `since` query param advances correctly between calls. Lifting it out of the
// httptest handler keeps the test's cognitive complexity manageable.
func paginateSyncPage(w http.ResponseWriter, since string, callNum int) {
	if callNum == 1 {
		if since != "0" {
			http.Error(w, "page 1 since="+since, http.StatusBadRequest)
			return
		}
		// Full page (pageLimit) forces the caller to loop.
		secs := make([]SecretWithMetadata, pageLimit)
		for i := range secs {
			secs[i] = SecretWithMetadata{Namespace: "ns", Name: fmt.Sprintf("s%d", i)}
		}
		writeJSON(w, DeltaSyncResponse{Secrets: secs, ServerTime: 100})
		return
	}
	// Page 2 MUST advance the cursor to the previous server_time — a
	// regression like `cursor = since` would re-request the same page forever.
	if since != "100" {
		http.Error(w, "page 2 since="+since+" (want 100)", http.StatusBadRequest)
		return
	}
	writeJSON(w, DeltaSyncResponse{
		Secrets:    []SecretWithMetadata{{Namespace: "ns", Name: "tail"}},
		ServerTime: 200,
	})
}

func TestClient_DeltaSync_Paginates(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setJSONHeader(w)
		if handleAuthMock(w, r, "tok") {
			return
		}
		if r.URL.Path == secretsSyncPath {
			calls++
			paginateSyncPage(w, r.URL.Query().Get("since"), calls)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a := &Auth{endpoint: srv.URL, privKey: ed25519.NewKeyFromSeed(make([]byte, 32)), http: &http.Client{}}
	c := NewClient(srv.URL, a)
	secrets, serverTime, err := c.DeltaSync(context.Background(), 0)
	if err != nil {
		t.Fatalf(deltaSyncErrFmt, err)
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
		setJSONHeader(w)
		// Inline auth mock — handleAuthMock takes a static token; this test
		// needs a fresh one per /auth/verify so the retry actually carries
		// a different Bearer.
		if r.URL.Path == authChallengePath {
			writeJSON(w, ChallengeResponse{Challenge: make(IntBytes, 32)})
			return
		}
		if r.URL.Path == authVerifyPath {
			writeJSON(w, AuthResponse{Success: true, Token: tokens[tokenIdx]})
			tokenIdx++
			return
		}
		if r.URL.Path == secretsSyncPath {
			syncCalls++
			if syncCalls == 1 {
				http.Error(w, "expired", http.StatusUnauthorized)
				return
			}
			if got := r.Header.Get("Authorization"); got != "Bearer new-token" {
				http.Error(w, "wrong token: "+got, http.StatusForbidden)
				return
			}
			writeJSON(w, DeltaSyncResponse{
				Secrets:    []SecretWithMetadata{{Namespace: "ns", Name: "s1"}},
				ServerTime: 10,
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	a := &Auth{endpoint: srv.URL, privKey: ed25519.NewKeyFromSeed(make([]byte, 32)), http: &http.Client{}}
	c := NewClient(srv.URL, a)
	secrets, serverTime, err := c.DeltaSync(context.Background(), 0)
	if err != nil {
		t.Fatalf(deltaSyncErrFmt, err)
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
