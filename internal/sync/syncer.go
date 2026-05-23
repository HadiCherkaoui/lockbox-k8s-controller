// internal/sync/syncer.go
package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab.cherkaoui.ch/HadiCherkaoui/lockbox-k8s-controller/internal/lockbox"
)

// maxReconcileAttempts is the number of consecutive ticks a single Lockbox
// event may fail to reconcile before the syncer logs a warning and skips it,
// allowing the cursor to advance past the poison. Past this threshold the
// event is silently dropped from the current sync stream — the operator is
// expected to repair the upstream event in Lockbox (it will reappear with a
// fresh updated_at and get a clean retry).
const maxReconcileAttempts = 10

// LockboxClientIface is the subset of lockbox.Client used by Syncer (allows testing with mocks).
type LockboxClientIface interface {
	DeltaSync(ctx context.Context, since int64) ([]lockbox.SecretWithMetadata, int64, error)
}

// AuthIface is the subset of lockbox.Auth used by Syncer for initialization.
type AuthIface interface {
	LoadOrRegister(ctx context.Context, k8sClient client.Client, namespace string) error
	Seed() []byte
}

// Syncer polls Lockbox and syncs secrets to Kubernetes. Implements manager.Runnable.
type Syncer struct {
	LockboxClient LockboxClientIface
	K8sClient     client.Client
	Seed          []byte
	Interval      time.Duration
	// Auth and Namespace are used to initialize the keypair on first start.
	// If Auth is nil, Seed must be pre-populated.
	Auth      AuthIface
	Namespace string
	lastSync  int64
	// failedAttempts counts consecutive reconcile failures per
	// "namespace/name@updated_at" key. Successful reconciles clear the entry;
	// reaching maxReconcileAttempts skips the event so a single corrupt event
	// can't freeze the cursor indefinitely.
	failedAttempts map[string]int
}

// Start implements manager.Runnable. Blocks until ctx is cancelled.
func (s *Syncer) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("lockbox-syncer")

	if s.Auth != nil {
		if err := s.Auth.LoadOrRegister(ctx, s.K8sClient, s.Namespace); err != nil {
			return fmt.Errorf("initialize lockbox auth: %w", err)
		}
		s.Seed = s.Auth.Seed()
		logger.Info("lockbox auth initialized", "namespace", s.Namespace)
	}

	s.syncOnce(ctx, logger)

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.syncOnce(ctx, logger)
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *Syncer) syncOnce(ctx context.Context, logger logr.Logger) {
	secrets, serverTime, err := s.LockboxClient.DeltaSync(ctx, s.lastSync)
	if err != nil {
		logger.Error(err, "delta sync failed")
		return
	}
	if s.failedAttempts == nil {
		s.failedAttempts = map[string]int{}
	}
	failed, skipped := 0, 0
	for _, secret := range secrets {
		key := fmt.Sprintf("%s/%s@%d", secret.Namespace, secret.Name, secret.UpdatedAt)
		if s.failedAttempts[key] >= maxReconcileAttempts {
			// Poison event: dropped from this sync stream so the cursor can
			// advance. Operator must fix the upstream event in Lockbox.
			logger.Error(nil, "skipping permanently-failing event after max attempts",
				"name", secret.Name, "namespace", secret.Namespace,
				"updatedAt", secret.UpdatedAt, "attempts", s.failedAttempts[key])
			delete(s.failedAttempts, key)
			skipped++
			continue
		}
		if err := reconcileSecret(ctx, logger, s.K8sClient, s.Seed, secret); err != nil {
			s.failedAttempts[key]++
			failed++
			logger.Error(err, "reconcile failed",
				"name", secret.Name, "namespace", secret.Namespace,
				"attempt", s.failedAttempts[key], "max", maxReconcileAttempts)
			continue
		}
		delete(s.failedAttempts, key)
	}
	// Advance the cursor only when every remaining event reconciled. Events
	// that hit maxReconcileAttempts are treated as resolved (skipped), so a
	// permanently-corrupt event no longer blocks an otherwise healthy stream.
	if failed == 0 {
		s.lastSync = serverTime
		logger.Info("sync complete", "count", len(secrets), "skipped", skipped, "nextSince", serverTime)
	} else {
		logger.Info("sync partial — cursor held for retry",
			"count", len(secrets), "failed", failed, "skipped", skipped, "since", s.lastSync)
	}
}
