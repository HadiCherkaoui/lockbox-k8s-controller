// internal/sync/syncer.go
package sync

import (
	"context"
	"time"

	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"gitlab.cherkaoui.ch/HadiCherkaoui/lockbox-k8s-controller/internal/lockbox"
)

// LockboxClientIface is the subset of lockbox.Client used by Syncer (allows testing with mocks).
type LockboxClientIface interface {
	DeltaSync(ctx context.Context, since int64) ([]lockbox.SecretWithMetadata, int64, error)
}

// Syncer polls Lockbox and syncs secrets to Kubernetes. Implements manager.Runnable.
type Syncer struct {
	LockboxClient LockboxClientIface
	K8sClient     client.Client
	Seed          []byte
	Interval      time.Duration
	lastSync      int64
}

// Start implements manager.Runnable. Blocks until ctx is cancelled.
func (s *Syncer) Start(ctx context.Context) error {
	logger := log.FromContext(ctx).WithName("lockbox-syncer")

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
	for _, secret := range secrets {
		if err := reconcileSecret(ctx, logger, s.K8sClient, s.Seed, secret); err != nil {
			logger.Error(err, "reconcile failed",
				"name", secret.Name, "namespace", secret.Namespace)
		}
	}
	s.lastSync = serverTime
	logger.Info("sync complete", "count", len(secrets), "nextSince", serverTime)
}
