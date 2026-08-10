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
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

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

func TestSyncer_Start_Cancels(t *testing.T) {
	mc := &mockLockboxClient{serverTime: 42}
	fc := fake.NewClientBuilder().Build()

	s := &Syncer{
		LockboxClient: mc,
		K8sClient:     fc,
		Seed:          make([]byte, 32),
		Interval:      50 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Should have fired at least twice (initial + 1 tick) within 200ms at 50ms interval
	if mc.calls.Load() < 2 {
		t.Fatalf("expected >= 2 calls, got %d", mc.calls.Load())
	}
}

func TestSyncer_LastSync_Updated(t *testing.T) {
	mc := &mockLockboxClient{serverTime: 999}
	fc := fake.NewClientBuilder().Build()

	s := &Syncer{
		LockboxClient: mc,
		K8sClient:     fc,
		Seed:          make([]byte, 32),
		Interval:      time.Hour, // don't tick during test
	}
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
	mc := &mockLockboxClient{returnErr: true}
	fc := fake.NewClientBuilder().Build()

	s := &Syncer{
		LockboxClient: mc,
		K8sClient:     fc,
		Seed:          make([]byte, 32),
		Interval:      time.Hour,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Should not panic even when DeltaSync returns an error
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
}

func TestSyncer_LastSync_NotAdvancedOnReconcileFailure(t *testing.T) {
	// Empty ciphertext fails inside gcm.Open (needs at least the 16-byte tag),
	// so reconcileSecret returns an error and the syncer must hold the cursor.
	bad := lockbox.SecretWithMetadata{
		Namespace: testNamespace, Name: "bad",
		Data: map[string]lockbox.Ciphertext{
			"x": {Nonce: make(lockbox.IntBytes, 12), Data: lockbox.IntBytes{}},
		},
	}
	mc := &mockLockboxClient{serverTime: 999, secrets: []lockbox.SecretWithMetadata{bad}}
	fc := fake.NewClientBuilder().Build()
	s := &Syncer{
		LockboxClient: mc,
		K8sClient:     fc,
		Seed:          make([]byte, 32),
		Interval:      time.Hour,
	}
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
	// A permanently-failing event (empty ciphertext → gcm.Open error) must
	// not freeze the cursor forever; after maxReconcileAttempts retries it
	// is skipped and lastSync advances.
	bad := lockbox.SecretWithMetadata{
		Namespace: testNamespace, Name: "bad", UpdatedAt: 42,
		Data: map[string]lockbox.Ciphertext{
			"x": {Nonce: make(lockbox.IntBytes, 12), Data: lockbox.IntBytes{}},
		},
	}
	mc := &mockLockboxClient{serverTime: 999, secrets: []lockbox.SecretWithMetadata{bad}}
	fc := fake.NewClientBuilder().Build()
	s := &Syncer{
		LockboxClient: mc,
		K8sClient:     fc,
		Seed:          make([]byte, 32),
		Interval:      time.Hour,
	}
	// Direct invocation avoids racing the ticker.
	for i := range maxReconcileAttempts {
		s.syncOnce(t.Context(), zap.New().WithName("test"))
		if s.lastSync != 0 {
			t.Fatalf("lastSync advanced before maxAttempts at iteration %d: %d", i, s.lastSync)
		}
	}
	// One more tick — at this point the event has hit the threshold and is skipped.
	s.syncOnce(t.Context(), zap.New().WithName("test"))
	if s.lastSync != 999 {
		t.Fatalf("lastSync should advance after maxAttempts (poison skip), got %d", s.lastSync)
	}
}

func TestSyncer_TransientFailure_ClearedOnSuccess(t *testing.T) {
	// A reconcile that initially fails (recorded in failedAttempts) but then
	// succeeds on a retry must clear its counter so a later transient failure
	// gets a full maxReconcileAttempts budget.
	s := &Syncer{
		LockboxClient: &mockLockboxClient{},
		K8sClient:     fake.NewClientBuilder().Build(),
		Seed:          make([]byte, 32),
		failedAttempts: map[string]int{
			"default/x@1": 5,
		},
	}
	good := lockbox.SecretWithMetadata{
		Namespace: testNamespace, Name: "x", UpdatedAt: 1, SecretType: "Opaque",
		Data: map[string]lockbox.Ciphertext{},
	}
	s.LockboxClient = &mockLockboxClient{serverTime: 7, secrets: []lockbox.SecretWithMetadata{good}}
	s.syncOnce(t.Context(), zap.New().WithName("test"))
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

func (m *mockAuth) Seed() []byte {
	return m.seed
}

type mockAuthFailing struct{}

func (m *mockAuthFailing) LoadOrRegister(_ context.Context, _ client.Client, _ string) error {
	return fmt.Errorf("auth init failed")
}

func (m *mockAuthFailing) Seed() []byte { return nil }

func TestSyncer_AuthInitialized_InStart(t *testing.T) {
	mc := &mockLockboxClient{serverTime: 1}
	fc := fake.NewClientBuilder().Build()
	ma := &mockAuth{}

	s := &Syncer{
		LockboxClient: mc,
		K8sClient:     fc,
		Auth:          ma,
		Namespace:     "test-ns",
		Interval:      time.Hour,
	}
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
	fc := fake.NewClientBuilder().Build()
	ma := &mockAuthFailing{}

	s := &Syncer{
		LockboxClient: &mockLockboxClient{},
		K8sClient:     fc,
		Auth:          ma,
		Namespace:     "test-ns",
		Interval:      time.Hour,
	}
	err := s.Start(context.Background())
	if err == nil {
		t.Fatal("expected error when auth init fails")
	}
}

// TestSyncer_SelfHeal_RecreatesMissingSecret verifies that a managed Secret
// that is externally deleted (Flux prune, kubectl delete, etc.) gets recreated
// by the next syncOnce call — without a controller restart.
func TestSyncer_SelfHeal_RecreatesMissingSecret(t *testing.T) {
	// Seed an event with a valid (all-zero) ciphertext.
	nonce := make([]byte, 12)
	event := newSyncEvent(t, testNamespace, "heal-me", nonce, "secretval")

	// First tick: reconcile from the delta (creates the secret and populates the cache).
	mc := &mockLockboxClient{serverTime: 10, secrets: []lockbox.SecretWithMetadata{event}}
	fc := fake.NewClientBuilder().Build()
	s := &Syncer{
		LockboxClient: mc,
		K8sClient:     fc,
		Seed:          make([]byte, 32),
		Interval:      time.Hour,
	}
	s.syncOnce(t.Context(), zap.New().WithName("test"))

	// Verify the secret was created.
	var created corev1.Secret
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: "heal-me"}, &created); err != nil {
		t.Fatalf("secret not created after first tick: %v", err)
	}

	// Simulate external deletion.
	if err := fc.Delete(t.Context(), &created); err != nil {
		t.Fatalf("delete: %v", err)
	}

	// Second tick: delta is empty (cursor advanced), but self-heal must recreate.
	mc.secrets = nil
	mc.serverTime = 20
	s.syncOnce(t.Context(), zap.New().WithName("test"))

	var healed corev1.Secret
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: "heal-me"}, &healed); err != nil {
		t.Fatalf("self-heal: secret not recreated after deletion: %v", err)
	}
	if healed.Annotations[managedAnnotation] != managedAnnotationValue {
		t.Fatal("self-heal: recreated secret is missing managed annotation")
	}
}

// TestSyncer_SelfHeal_DoesNotRecreateDeletedUpstream verifies that a secret
// that was explicitly deleted upstream (DeletedAt != nil) is NOT recreated by
// the self-heal path — it should be evicted from the cache.
func TestSyncer_SelfHeal_DoesNotRecreateDeletedUpstream(t *testing.T) {
	nonce := make([]byte, 12)
	event := newSyncEvent(t, testNamespace, "going-away", nonce, "value")

	mc := &mockLockboxClient{serverTime: 10, secrets: []lockbox.SecretWithMetadata{event}}
	fc := fake.NewClientBuilder().Build()
	s := &Syncer{
		LockboxClient: mc,
		K8sClient:     fc,
		Seed:          make([]byte, 32),
		Interval:      time.Hour,
	}
	// First tick: create + populate cache.
	s.syncOnce(t.Context(), zap.New().WithName("test"))

	// Second tick: send a delete event. This deletes the k8s Secret AND evicts
	// the cache entry, so the self-heal loop must not try to recreate it.
	ts := int64(99)
	del := lockbox.SecretWithMetadata{
		Namespace: testNamespace,
		Name:      "going-away",
		DeletedAt: &ts,
	}
	mc.secrets = []lockbox.SecretWithMetadata{del}
	mc.serverTime = 20
	s.syncOnce(t.Context(), zap.New().WithName("test"))

	// The secret must not exist.
	var got corev1.Secret
	if err := fc.Get(t.Context(), types.NamespacedName{Namespace: testNamespace, Name: "going-away"}, &got); err == nil {
		t.Fatal("upstream-deleted secret must not be recreated by self-heal")
	}
}

// newSyncEvent is a test helper that builds a SecretWithMetadata with a single
// encrypted field using the all-zero testSeed. encryptField is defined in
// reconcile_test.go and is available throughout the sync package test binary.
func newSyncEvent(t *testing.T, ns, name string, nonce []byte, plaintext string) lockbox.SecretWithMetadata {
	t.Helper()
	return lockbox.SecretWithMetadata{
		Namespace:  ns,
		Name:       name,
		SecretType: "Opaque",
		UpdatedAt:  1,
		Data:       map[string]lockbox.Ciphertext{"val": encryptField(t, nonce, []byte(plaintext))},
	}
}
