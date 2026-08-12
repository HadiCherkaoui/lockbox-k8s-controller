// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal/sync/syncer.go
package sync

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
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
	// Policy carries the operator-set limits (namespace allowlist, AAD
	// enforcement) applied to every event before it is acted on.
	Policy Policy
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
	// knownSecrets is the self-heal cache: maps "namespace/name" to the last
	// successfully reconciled SecretWithMetadata for every live (non-deleted)
	// lockbox secret. On each tick, after the delta is processed, healDeletedSecrets
	// lists all managed k8s Secrets and recreates any that are absent from the
	// cluster but present here.
	//
	// Design choice — Option B (periodic full-state sync):
	// The controller ships no CRDs and runs as a manager.Runnable, not a
	// controller-runtime Reconciler. Registering a Watch on core/v1.Secret
	// (Option A) would require a separate controller wired into cmd/main.go
	// and a point-query lockbox API that does not exist yet. Option B is
	// simpler: one extra List call per tick (cheap for <=20 secrets) and
	// guarantees self-heal within at most one syncInterval regardless of the
	// deletion mechanism (Flux prune, kubectl delete, etc.).
	knownSecrets map[string]lockbox.SecretWithMetadata
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
	if s.knownSecrets == nil {
		s.knownSecrets = map[string]lockbox.SecretWithMetadata{}
	}
	failed, skipped := 0, 0
	for _, secret := range secrets {
		key := fmt.Sprintf("%s/%s@%d", secret.Namespace, secret.Name, secret.UpdatedAt)
		cacheKey := secret.Namespace + "/" + secret.Name
		if s.failedAttempts[key] >= maxReconcileAttempts {
			// Poison event: dropped from this sync stream so the cursor can
			// advance. Operator must fix the upstream event in Lockbox.
			//
			// Evict the cache entry first. A tombstone is never re-delivered,
			// so skipping a delete without evicting would leave self-heal
			// re-creating a secret that was revoked upstream — every tick,
			// forever, surviving both upstream deletion and kubectl delete.
			if secret.DeletedAt != nil {
				delete(s.knownSecrets, cacheKey)
				logger.Error(nil, "skipping permanently-failing DELETE after max attempts — "+
					"self-heal disabled for this secret; it may still exist in-cluster and needs manual removal",
					"name", secret.Name, "namespace", secret.Namespace,
					"updatedAt", secret.UpdatedAt, "attempts", s.failedAttempts[key])
			} else {
				logger.Error(nil, "skipping permanently-failing event after max attempts",
					"name", secret.Name, "namespace", secret.Namespace,
					"updatedAt", secret.UpdatedAt, "attempts", s.failedAttempts[key])
			}
			delete(s.failedAttempts, key)
			skipped++
			continue
		}
		result, err := reconcileSecret(ctx, logger, s.K8sClient, s.Seed, s.Policy, secret)
		if err != nil {
			s.failedAttempts[key]++
			failed++
			logger.Error(err, "reconcile failed",
				"name", secret.Name, "namespace", secret.Namespace,
				"attempt", s.failedAttempts[key], "max", maxReconcileAttempts)
			continue
		}
		delete(s.failedAttempts, key)
		// Update the self-heal cache: track secrets this controller owns the
		// data for, evict deleted ones. Adopted Secrets are deliberately not
		// cached — their data belongs to whoever created them, and replaying a
		// stored event over one would overwrite data we never possessed.
		switch {
		case result == outcomeDeleted:
			delete(s.knownSecrets, cacheKey)
		case result.cacheable():
			s.knownSecrets[cacheKey] = secret
		default:
			delete(s.knownSecrets, cacheKey)
		}
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

	// Self-heal: recreate any managed Secrets that were externally deleted.
	// This runs even on a partial sync so a single corrupt event doesn't also
	// block self-healing of unrelated Secrets.
	s.healDeletedSecrets(ctx, logger)
}

// healDeletedSecrets lists all managed k8s Secrets and recreates any that are
// absent from the cluster but still present in knownSecrets. This catches
// deletions by Flux prune, kubectl delete, or any other external actor.
func (s *Syncer) healDeletedSecrets(ctx context.Context, logger logr.Logger) {
	if len(s.knownSecrets) == 0 {
		return
	}

	var secretList corev1.SecretList
	if err := s.K8sClient.List(ctx, &secretList, client.MatchingLabels{
		managedLabel: managedLabelValue,
	}); err != nil {
		logger.Error(err, "self-heal: failed to list managed secrets")
		return
	}

	// Build a set of live secrets.
	live := make(map[string]struct{}, len(secretList.Items))
	for i := range secretList.Items {
		live[secretList.Items[i].Namespace+"/"+secretList.Items[i].Name] = struct{}{}
	}

	healed := 0
	for cacheKey, meta := range s.knownSecrets {
		if _, exists := live[cacheKey]; exists {
			continue
		}
		// Secret is missing from the cluster — recreate it.
		logger.Info("self-heal: recreating externally-deleted managed secret",
			"namespace", meta.Namespace, "name", meta.Name)
		if _, err := reconcileSecret(ctx, logger, s.K8sClient, s.Seed, s.Policy, meta); err != nil {
			logger.Error(err, "self-heal: failed to recreate secret",
				"namespace", meta.Namespace, "name", meta.Name)
			continue
		}
		healed++
	}
	if healed > 0 {
		logger.Info("self-heal: recreated missing managed secrets", "count", healed)
	}
}
