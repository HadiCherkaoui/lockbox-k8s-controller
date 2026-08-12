// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal/sync/syncer_test.go
package sync

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"gitlab.cherkaoui.ch/HadiCherkaoui/lockbox-k8s-controller/internal/lockbox"
)

type mockLockboxClient struct {
	calls      atomic.Int32
	returnErr  bool
	secrets    []lockbox.SecretWithMetadata
	serverTime int64
}

func (m *mockLockboxClient) DeltaSync(_ context.Context, _ int64) ([]lockbox.SecretWithMetadata, int64, error) {
	m.calls.Add(1)
	if m.returnErr {
		return nil, 0, fmt.Errorf("mock error")
	}
	return m.secrets, m.serverTime, nil
}

// newSyncer builds a Syncer carrying the shipped default policy.
func newSyncer(mc LockboxClientIface, c client.Client) *Syncer {
	return &Syncer{
		LockboxClient: mc,
		K8sClient:     c,
		Seed:          make([]byte, 32),
		Interval:      time.Hour,
		Policy:        testPolicy(),
	}
}

// newSyncEvent builds a SecretWithMetadata with a single AAD-bound field in the
// default test namespace.
func newSyncEvent(t *testing.T, name string, nonce byte, plaintext string) lockbox.SecretWithMetadata {
	t.Helper()
	return upsertEvent(t, testNamespace, name, "val", plaintext, nonce)
}

func TestSyncer_Start_Cancels(t *testing.T) {
	mc := &mockLockboxClient{serverTime: 42}
	s := newSyncer(mc, fake.NewClientBuilder().Build())
	s.Interval = 50 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if mc.calls.Load() < 2 {
		t.Fatalf("expected >= 2 calls, got %d", mc.calls.Load())
	}
}

func TestSyncer_LastSync_Updated(t *testing.T) {
	s := newSyncer(&mockLockboxClient{serverTime: 999}, fake.NewClientBuilder().Build())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.lastSync != 999 {
		t.Fatalf("lastSync not updated: %d", s.lastSync)
	}
}

func TestSyncer_ErrorDoesNotPanic(t *testing.T) {
	s := newSyncer(&mockLockboxClient{returnErr: true}, fake.NewClientBuilder().Build())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func TestSyncer_LastSync_NotAdvancedOnReconcileFailure(t *testing.T) {
	// Empty ciphertext fails inside gcm.Open (needs at least the 16-byte tag),
	// so reconcileSecret returns an error and the syncer must hold the cursor.
	bad := lockbox.SecretWithMetadata{
		Namespace: testNamespace, Name: "bad", SecretType: "Opaque",
		Data: map[string]lockbox.Ciphertext{
			"x": {Nonce: make(lockbox.IntBytes, 12), Data: lockbox.IntBytes{}},
		},
	}
	s := newSyncer(&mockLockboxClient{serverTime: 999, secrets: []lockbox.SecretWithMetadata{bad}},
		fake.NewClientBuilder().Build())

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if s.lastSync != 0 {
		t.Fatalf("lastSync must stay at 0 on partial failure, got %d", s.lastSync)
	}
}

func TestSyncer_PoisonEvent_SkippedAfterMaxAttempts(t *testing.T) {
	bad := lockbox.SecretWithMetadata{
		Namespace: testNamespace, Name: "bad", UpdatedAt: 42, SecretType: "Opaque",
		Data: map[string]lockbox.Ciphertext{
			"x": {Nonce: make(lockbox.IntBytes, 12), Data: lockbox.IntBytes{}},
		},
	}
	s := newSyncer(&mockLockboxClient{serverTime: 999, secrets: []lockbox.SecretWithMetadata{bad}},
		fake.NewClientBuilder().Build())

	for i := range maxReconcileAttempts {
		s.syncOnce(t.Context(), testLogger())
		if s.lastSync != 0 {
			t.Fatalf("lastSync advanced before maxAttempts at iteration %d: %d", i, s.lastSync)
		}
	}
	s.syncOnce(t.Context(), testLogger())
	if s.lastSync != 999 {
		t.Fatalf("lastSync should advance after maxAttempts (poison skip), got %d", s.lastSync)
	}
}

// TestSyncer_SkippedDelete_EvictsSelfHealCache is the regression test for the
// revocation bypass: a delete that permanently fails to apply (an admission
// policy denying DELETE on Secrets is enough — no attacker required) used to be
// skipped while its cache entry survived. The cursor then advanced past the
// tombstone, which is never re-delivered, so self-heal re-created the revoked
// secret every tick, forever.
func TestSyncer_SkippedDelete_EvictsSelfHealCache(t *testing.T) {
	fc := fake.NewClientBuilder().WithInterceptorFuncs(interceptor.Funcs{
		Delete: func(_ context.Context, _ client.WithWatch, _ client.Object, _ ...client.DeleteOption) error {
			return fmt.Errorf("denied by admission webhook")
		},
	}).Build()

	created := newSyncEvent(t, "revoke-me", 20, "old-password")
	mc := &mockLockboxClient{serverTime: 10, secrets: []lockbox.SecretWithMetadata{created}}
	s := newSyncer(mc, fc)

	// Tick 1: create and populate the self-heal cache.
	s.syncOnce(t.Context(), testLogger())
	if _, ok := s.knownSecrets[testNamespace+"/revoke-me"]; !ok {
		t.Fatal("precondition: secret should be in the self-heal cache after creation")
	}

	// Now revoke it upstream. Every delete attempt is denied.
	ts := int64(99)
	del := lockbox.SecretWithMetadata{
		Namespace: testNamespace, Name: "revoke-me", UpdatedAt: 50, DeletedAt: &ts,
	}
	mc.secrets = []lockbox.SecretWithMetadata{del}
	mc.serverTime = 20

	for range maxReconcileAttempts + 1 {
		s.syncOnce(t.Context(), testLogger())
	}

	if _, ok := s.knownSecrets[testNamespace+"/revoke-me"]; ok {
		t.Fatal("skipped DELETE left a stale cache entry — self-heal would resurrect the revoked secret every tick")
	}
}

func TestSyncer_TransientFailure_ClearedOnSuccess(t *testing.T) {
	good := newSyncEvent(t, "x", 21, "value")
	// failedAttempts is keyed by updated_at, so match the seeded entry below.
	good.UpdatedAt = 1

	s := newSyncer(&mockLockboxClient{serverTime: 7, secrets: []lockbox.SecretWithMetadata{good}},
		fake.NewClientBuilder().Build())
	s.failedAttempts = map[string]int{"default/x@1": 5}

	s.syncOnce(t.Context(), testLogger())
	if got := s.failedAttempts["default/x@1"]; got != 0 {
		t.Fatalf("failedAttempts not cleared on success: %d", got)
	}
	if s.lastSync != 7 {
		t.Fatalf("lastSync did not advance after success: %d", s.lastSync)
	}
}

type mockAuth struct {
	loadCalled bool
	seed       []byte
}

func (m *mockAuth) LoadOrRegister(_ context.Context, _ client.Client, _ string) error {
	m.loadCalled = true
	m.seed = make([]byte, 32)
	return nil
}

func (m *mockAuth) Seed() []byte { return m.seed }

type mockAuthFailing struct{}

func (m *mockAuthFailing) LoadOrRegister(_ context.Context, _ client.Client, _ string) error {
	return fmt.Errorf("auth init failed")
}

func (m *mockAuthFailing) Seed() []byte { return nil }

func TestSyncer_AuthInitialized_InStart(t *testing.T) {
	ma := &mockAuth{}
	s := newSyncer(&mockLockboxClient{serverTime: 1}, fake.NewClientBuilder().Build())
	s.Auth = ma
	s.Namespace = "test-ns"

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if !ma.loadCalled {
		t.Fatal("expected LoadOrRegister to be called")
	}
	if len(s.Seed) != 32 {
		t.Fatalf("expected seed to be set, got len=%d", len(s.Seed))
	}
}

func TestSyncer_AuthInitFails(t *testing.T) {
	s := newSyncer(&mockLockboxClient{}, fake.NewClientBuilder().Build())
	s.Auth = &mockAuthFailing{}
	s.Namespace = "test-ns"

	if err := s.Start(context.Background()); err == nil {
		t.Fatal("expected error when auth init fails")
	}
}

// TestSyncer_SelfHeal_RecreatesMissingSecret verifies that a managed Secret
// that is externally deleted (Flux prune, kubectl delete, etc.) gets recreated
// by the next syncOnce call — without a controller restart.
func TestSyncer_SelfHeal_RecreatesMissingSecret(t *testing.T) {
	event := newSyncEvent(t, "heal-me", 22, "secretval")
	mc := &mockLockboxClient{serverTime: 10, secrets: []lockbox.SecretWithMetadata{event}}
	fc := fake.NewClientBuilder().Build()
	s := newSyncer(mc, fc)

	s.syncOnce(t.Context(), testLogger())

	var created corev1.Secret
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: "heal-me"}, &created); err != nil {
		t.Fatalf("secret not created after first tick: %v", err)
	}

	if err := fc.Delete(t.Context(), &created); err != nil {
		t.Fatalf("delete: %v", err)
	}

	mc.secrets = nil
	mc.serverTime = 20
	s.syncOnce(t.Context(), testLogger())

	var healed corev1.Secret
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: "heal-me"}, &healed); err != nil {
		t.Fatalf("self-heal: secret not recreated after deletion: %v", err)
	}
	if healed.Annotations[managedAnnotation] != managedAnnotationValue {
		t.Fatal("self-heal: recreated secret is missing managed annotation")
	}
}

// TestSyncer_SelfHeal_DoesNotRecreateDeletedUpstream verifies that a secret
// explicitly deleted upstream is not resurrected.
func TestSyncer_SelfHeal_DoesNotRecreateDeletedUpstream(t *testing.T) {
	event := newSyncEvent(t, "going-away", 23, "value")
	mc := &mockLockboxClient{serverTime: 10, secrets: []lockbox.SecretWithMetadata{event}}
	fc := fake.NewClientBuilder().Build()
	s := newSyncer(mc, fc)

	s.syncOnce(t.Context(), testLogger())

	ts := int64(99)
	mc.secrets = []lockbox.SecretWithMetadata{{
		Namespace: testNamespace, Name: "going-away", DeletedAt: &ts,
	}}
	mc.serverTime = 20
	s.syncOnce(t.Context(), testLogger())

	var got corev1.Secret
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: "going-away"}, &got); err == nil {
		t.Fatal("upstream-deleted secret must not be recreated by self-heal")
	}
}

// TestSyncer_SelfHeal_DoesNotCacheAdoptedSecrets verifies that an adopted
// Secret is never replayed from cache. Its data belongs to whoever created it,
// so a replay would overwrite data the controller never possessed.
func TestSyncer_SelfHeal_DoesNotCacheAdoptedSecrets(t *testing.T) {
	preexisting := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        "adopt-me",
			Namespace:   testNamespace,
			Annotations: map[string]string{adoptAnnotation: adoptAnnotationValue},
		},
		Data: map[string][]byte{"owned-by-someone-else": []byte("do-not-touch")},
	}
	fc := fake.NewClientBuilder().WithObjects(preexisting).Build()

	event := newSyncEvent(t, "adopt-me", 24, "server-side-value")
	s := newSyncer(&mockLockboxClient{serverTime: 10, secrets: []lockbox.SecretWithMetadata{event}}, fc)

	s.syncOnce(t.Context(), testLogger())

	if _, ok := s.knownSecrets[testNamespace+"/adopt-me"]; ok {
		t.Fatal("adopted secret was cached — a later self-heal would overwrite data the controller never had")
	}

	var got corev1.Secret
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: "adopt-me"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.Data["owned-by-someone-else"]) != "do-not-touch" {
		t.Fatal("adoption overwrote the pre-existing data")
	}
}
