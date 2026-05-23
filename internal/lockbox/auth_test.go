// internal/lockbox/auth_test.go
package lockbox

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

const (
	authChallengePath = "/auth/challenge"
	authVerifyPath    = "/auth/verify"
	secretsSyncPath   = "/secrets/sync"
)

func TestAuth_LoadOrRegister_ExistingSecret(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	seed := privKey.Seed()

	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: credentialsSecretName, Namespace: "test-ns"},
		Data:       map[string][]byte{credentialsSeedKey: seed},
	}
	fakeClient := fake.NewClientBuilder().WithObjects(existing).Build()

	a := NewAuth("http://unused", "unused-key")
	if err := a.LoadOrRegister(context.Background(), fakeClient, "test-ns"); err != nil {
		t.Fatalf("LoadOrRegister: %v", err)
	}
	if string(a.Seed()) != string(seed) {
		t.Fatal("seed mismatch")
	}
}

func TestAuth_LoadOrRegister_NewKeypair(t *testing.T) {
	registerCalled := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/auth/register" {
			registerCalled = true
			if r.Header.Get("X-API-KEY") != "test-key" {
				http.Error(w, "bad key", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true})
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	fakeClient := fake.NewClientBuilder().Build()
	a := NewAuth(srv.URL, "test-key")
	if err := a.LoadOrRegister(context.Background(), fakeClient, "test-ns"); err != nil {
		t.Fatalf("LoadOrRegister: %v", err)
	}
	if !registerCalled {
		t.Fatal("expected register to be called")
	}
	if len(a.Seed()) != 32 {
		t.Fatal("expected 32-byte seed")
	}

	// Verify K8s Secret was created
	var stored corev1.Secret
	if err := fakeClient.Get(context.Background(),
		types.NamespacedName{Namespace: "test-ns", Name: "lockbox-credentials"},
		&stored); err != nil {
		t.Fatalf("credentials not stored: %v", err)
	}
	if len(stored.Data[credentialsSeedKey]) != 32 {
		t.Fatal("stored seed wrong length")
	}
}

func TestAuth_LoadOrRegister_InvalidSeedLength(t *testing.T) {
	existing := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: credentialsSecretName, Namespace: "test-ns"},
		Data:       map[string][]byte{credentialsSeedKey: []byte("too-short")},
	}
	fakeClient := fake.NewClientBuilder().WithObjects(existing).Build()

	a := NewAuth("http://unused", "unused-key")
	err := a.LoadOrRegister(context.Background(), fakeClient, "test-ns")
	if err == nil {
		t.Fatal("expected error for invalid seed length")
	}
}

func TestAuth_LoadOrRegister_RegisterFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	fakeClient := fake.NewClientBuilder().Build()
	a := NewAuth(srv.URL, "wrong-key")
	err := a.LoadOrRegister(context.Background(), fakeClient, "test-ns")
	if err == nil {
		t.Fatal("expected error when register fails")
	}
}

func TestAuth_GetToken_ChallengeFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	seed := make([]byte, 32)
	a := &Auth{endpoint: srv.URL, privKey: ed25519.NewKeyFromSeed(seed), http: &http.Client{}}
	_, err := a.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error when challenge fails")
	}
}

func TestAuth_GetToken_VerifyFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == authChallengePath {
			_ = json.NewEncoder(w).Encode(ChallengeResponse{Challenge: make(IntBytes, 32)})
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer srv.Close()

	seed := make([]byte, 32)
	a := &Auth{endpoint: srv.URL, privKey: ed25519.NewKeyFromSeed(seed), http: &http.Client{}}
	_, err := a.GetToken(context.Background())
	if err == nil {
		t.Fatal("expected error when verify fails")
	}
}

func TestAuth_GetToken(t *testing.T) {
	_, privKey, _ := ed25519.GenerateKey(rand.Reader)
	challenge := make([]byte, 32)
	_, _ = rand.Read(challenge)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case authChallengePath:
			_ = json.NewEncoder(w).Encode(ChallengeResponse{Challenge: IntBytes(challenge)})
		case authVerifyPath:
			var req AuthRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			pubKey := ed25519.PublicKey(req.PublicKey)
			if !ed25519.Verify(pubKey, req.Challenge, req.Signature) {
				http.Error(w, "bad sig", http.StatusUnauthorized)
				return
			}
			_ = json.NewEncoder(w).Encode(AuthResponse{Success: true, Token: "test-jwt"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	a := &Auth{
		endpoint: srv.URL,
		privKey:  privKey,
		http:     &http.Client{},
	}
	token, err := a.GetToken(context.Background())
	if err != nil {
		t.Fatalf("GetToken: %v", err)
	}
	if token != "test-jwt" {
		t.Fatalf("expected test-jwt, got %q", token)
	}
}
