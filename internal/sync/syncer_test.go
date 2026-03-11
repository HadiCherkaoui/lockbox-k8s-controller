// internal/sync/syncer_test.go
package sync

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"gitlab.cherkaoui.ch/HadiCherkaoui/lockbox-k8s-controller/internal/lockbox"
)

type mockLockboxClient struct {
	calls      int32
	returnErr  bool
	secrets    []lockbox.SecretWithMetadata
	serverTime int64
}

func (m *mockLockboxClient) DeltaSync(_ context.Context, _ int64) ([]lockbox.SecretWithMetadata, int64, error) {
	atomic.AddInt32(&m.calls, 1)
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
	if atomic.LoadInt32(&mc.calls) < 2 {
		t.Fatalf("expected >= 2 calls, got %d", atomic.LoadInt32(&mc.calls))
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
