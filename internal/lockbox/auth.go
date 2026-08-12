// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal/lockbox/auth.go
package lockbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	credentialsSecretName = "lockbox-credentials"
	// credentialsSeedKey is the Secret data key storing the raw 32-byte
	// Ed25519 seed — same name on read (LoadOrRegister) and write (the
	// initial registration path).
	credentialsSeedKey = "seed"
	// httpTimeout caps every Lockbox HTTP call. A hung endpoint must not stall
	// the polling syncer (which would block leader-election lease renewal).
	httpTimeout = 30 * time.Second
)

// Auth manages the Ed25519 keypair and JWT acquisition for Lockbox.
type Auth struct {
	endpoint string
	apiKey   string
	privKey  ed25519.PrivateKey
	http     *http.Client
}

// NewAuth creates an Auth. Call LoadOrRegister before using GetToken.
func NewAuth(endpoint, apiKey string) *Auth {
	return &Auth{
		endpoint: endpoint,
		apiKey:   apiKey,
		http:     newHTTPClient(),
	}
}

// newHTTPClient builds the HTTP client used for every Lockbox call.
//
// Redirects are refused outright: the protocol has no legitimate use for them,
// and Go replays non-standard headers across hosts on redirect. X-API-KEY is
// not in net/http's sensitive-header set, so a 3xx would hand the bootstrap
// credential to the redirect target. Authorization is stripped only when the
// hostname changes — never on an https->http downgrade to the same host.
func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: httpTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Seed returns the 32-byte Ed25519 seed used as the AES-256-GCM decryption key.
func (a *Auth) Seed() []byte {
	return a.privKey.Seed()
}

// LoadOrRegister loads the keypair from the lockbox-credentials K8s Secret, or
// generates a new keypair, registers it with Lockbox, and stores it.
func (a *Auth) LoadOrRegister(ctx context.Context, k8sClient client.Client, namespace string) error {
	var secret corev1.Secret
	err := k8sClient.Get(ctx, types.NamespacedName{Namespace: namespace, Name: credentialsSecretName}, &secret)
	if err == nil {
		seed := secret.Data[credentialsSeedKey]
		if len(seed) != 32 {
			return fmt.Errorf("invalid seed length in %s/%s: %d", namespace, credentialsSecretName, len(seed))
		}
		a.privKey = ed25519.NewKeyFromSeed(seed)
		return nil
	}
	if !errors.IsNotFound(err) {
		return fmt.Errorf("get credentials secret: %w", err)
	}

	// Generate new keypair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}
	a.privKey = privKey

	if err := a.register(ctx, pubKey); err != nil {
		return fmt.Errorf("register with lockbox: %w", err)
	}

	cred := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      credentialsSecretName,
			Namespace: namespace,
		},
		Data: map[string][]byte{
			credentialsSeedKey: privKey.Seed(),
		},
	}
	if err := k8sClient.Create(ctx, cred); err != nil {
		return fmt.Errorf("store credentials: %w", err)
	}
	return nil
}

// GetToken performs challenge-response auth and returns a fresh JWT (valid ~60s).
// Call once at the start of each sync cycle.
func (a *Auth) GetToken(ctx context.Context) (string, error) {
	pubKey := a.privKey.Public().(ed25519.PublicKey)

	challengeResp, err := a.getChallenge(ctx, pubKey)
	if err != nil {
		return "", fmt.Errorf("challenge: %w", err)
	}

	sig := ed25519.Sign(a.privKey, challengeResp.Challenge)

	body, err := json.Marshal(AuthRequest{
		PublicKey: IntBytes(pubKey),
		Challenge: challengeResp.Challenge,
		Signature: IntBytes(sig),
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/auth/verify", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("verify request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("verify: status %d: %s", resp.StatusCode, b)
	}
	var ar AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&ar); err != nil {
		return "", fmt.Errorf("decode verify response: %w", err)
	}
	if !ar.Success {
		return "", fmt.Errorf("auth: server returned success=false")
	}
	return ar.Token, nil
}

func (a *Auth) getChallenge(ctx context.Context, pubKey ed25519.PublicKey) (*ChallengeResponse, error) {
	body, err := json.Marshal(ChallengeRequest{PublicKey: IntBytes(pubKey)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/auth/challenge", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("challenge request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("challenge: status %d: %s", resp.StatusCode, b)
	}
	var cr ChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	return &cr, nil
}

func (a *Auth) register(ctx context.Context, pubKey ed25519.PublicKey) error {
	body, err := json.Marshal(RegisterKeyRequest{
		PublicKey: IntBytes(pubKey),
		Label:     "lockbox-k8s-controller",
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint+"/auth/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-KEY", a.apiKey)
	resp, err := a.http.Do(req)
	if err != nil {
		return fmt.Errorf("register request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("register: status %d: %s", resp.StatusCode, b)
	}
	return nil
}
