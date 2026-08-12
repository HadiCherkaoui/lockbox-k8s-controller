// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal/sync/reconcile.go
package sync

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"gitlab.cherkaoui.ch/HadiCherkaoui/lockbox-k8s-controller/internal/lockbox"
)

const (
	// managedAnnotation is the controller's internal source-of-truth: writes
	// and deletes are gated on this so we never clobber a Secret that wasn't
	// created by the syncer or explicitly offered for adoption.
	managedAnnotation      = "lockbox.io/managed"
	managedAnnotationValue = "true"
	// adoptAnnotation is the operator's opt-in for taking over a pre-existing
	// Secret. It must be applied in-cluster, out of band: the signal has to
	// originate somewhere the Lockbox server cannot reach, otherwise the
	// ownership gate authorizes nothing against an actor who picks the name.
	adoptAnnotation      = "lockbox.io/adopt"
	adoptAnnotationValue = "true"
	// managedLabel surfaces the same "we manage this" signal as a label, so
	// operators can run `kubectl get secrets -l app.kubernetes.io/managed-by=lockbox-k8s-controller`
	// to enumerate managed objects. Mirrors the convention used by
	// cert-manager, external-secrets, etc.
	managedLabel      = "app.kubernetes.io/managed-by"
	managedLabelValue = "lockbox-k8s-controller"
)

// DefaultDeniedNamespaces are refused unless the operator overrides the list.
//
// The controller is deliberately open by default: any namespace you create
// works with no configuration change. What it will not do is write into the
// namespaces where a Secret is consumed by privileged cluster machinery, since
// there a write is not a leak but a cluster takeover — an upstream event that
// replaces a Secret backing a system component executes as that component.
// Nothing legitimate needs syncing into these.
var DefaultDeniedNamespaces = []string{
	"kube-system",
	"kube-public",
	"kube-node-lease",
}

// Policy is the set of operator-controlled limits applied to every event
// before it is acted on. It is built once at startup from the environment,
// which is trusted input, and is never influenced by the Lockbox payload.
type Policy struct {
	// AllowedNamespaces, when non-empty, is a strict allowlist: only these
	// namespaces may be written to. Empty (the default) means every namespace
	// is permitted except those in DeniedNamespaces, so new namespaces need no
	// configuration change.
	AllowedNamespaces map[string]struct{}
	// DeniedNamespaces are always refused. Defaults to DefaultDeniedNamespaces.
	DeniedNamespaces map[string]struct{}
	// ControllerNamespace is where this controller and its credentials Secret
	// live.
	ControllerNamespace string
	// RequireAAD rejects any ciphertext that does not authenticate against the
	// AAD binding it to its destination, which is what stops a blob from being
	// relocated to another namespace, field or timestamp. On by default; it
	// requires a Lockbox server that seals with the identical construction, so
	// LOCKBOX_REQUIRE_AAD=false exists to fall back to an older server.
	RequireAAD bool
}

// permits reports whether the policy allows writing to ns. Deny always wins.
func (p Policy) permits(ns string) bool {
	if _, denied := p.DeniedNamespaces[ns]; denied {
		return false
	}
	if len(p.AllowedNamespaces) == 0 {
		return true
	}
	_, ok := p.AllowedNamespaces[ns]
	return ok
}

// outcome describes what a reconcile did, so the caller can decide whether the
// event is safe to hold in the self-heal cache.
type outcome int

const (
	outcomeNoop outcome = iota
	outcomeCreated
	outcomeUpdated
	outcomeAdopted
	outcomeDeleted
)

// cacheable reports whether an event that produced this outcome may be stored
// in the self-heal cache. Adopted Secrets carry data the controller never
// possessed, so replaying a cached event over them would destroy it.
func (o outcome) cacheable() bool {
	return o == outcomeCreated || o == outcomeUpdated
}

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// reconcileSecret syncs one Lockbox secret event to a K8s Secret.
func reconcileSecret(
	ctx context.Context,
	log logr.Logger,
	k8sClient client.Client,
	seed []byte,
	pol Policy,
	s lockbox.SecretWithMetadata,
) (outcome, error) {
	// Enforce the destination limits before any decryption, so plaintext for a
	// rejected event never exists in this process.
	if !pol.permits(s.Namespace) {
		return outcomeNoop, fmt.Errorf(
			"refusing event for %s/%s: namespace %q is not writable by this controller "+
				"(see LOCKBOX_DENIED_NAMESPACES / LOCKBOX_ALLOWED_NAMESPACES)",
			s.Namespace, s.Name, s.Namespace)
	}
	if s.Namespace == pol.ControllerNamespace {
		// The whole namespace, not just lockbox-credentials by name. The adopt
		// opt-in only guards Secrets that currently exist: if one is pruned and
		// recreated (Flux reconcile, chart upgrade), an event naming it lands in
		// the CREATE branch during that gap and the controller writes
		// server-supplied data into a Secret nothing here should ever author.
		// The controller's own namespace holds its seed and its bootstrap
		// credentials; nothing in it is a legitimate sync target.
		return outcomeNoop, fmt.Errorf(
			"refusing event for %s/%s: the controller's own namespace is never a sync target",
			s.Namespace, s.Name)
	}

	nsName := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}

	if s.DeletedAt != nil {
		return handleDelete(ctx, log, k8sClient, nsName)
	}
	return handleUpsert(ctx, log, k8sClient, seed, pol, s, nsName)
}

func handleDelete(
	ctx context.Context,
	log logr.Logger,
	k8sClient client.Client,
	nsName types.NamespacedName,
) (outcome, error) {
	var existing corev1.Secret
	if err := k8sClient.Get(ctx, nsName, &existing); err != nil {
		if errors.IsNotFound(err) {
			return outcomeDeleted, nil
		}
		return outcomeNoop, fmt.Errorf("get secret for delete: %w", err)
	}
	if existing.Annotations[managedAnnotation] != managedAnnotationValue {
		log.Info("skipping delete of unmanaged secret",
			"namespace", nsName.Namespace, "name", nsName.Name)
		// Still a resolved event: the upstream secret is gone and there is
		// nothing of ours to remove. Reporting it as deleted evicts any stale
		// cache entry rather than leaving one to be resurrected.
		return outcomeDeleted, nil
	}
	if err := k8sClient.Delete(ctx, &existing); err != nil {
		return outcomeNoop, fmt.Errorf("delete secret: %w", err)
	}
	return outcomeDeleted, nil
}

func handleUpsert(
	ctx context.Context,
	log logr.Logger,
	k8sClient client.Client,
	seed []byte,
	pol Policy,
	s lockbox.SecretWithMetadata,
	nsName types.NamespacedName,
) (outcome, error) {
	// Validate the payload before any I/O. The server must always send a
	// non-empty type and at least one field; either being absent is a protocol
	// error, not a default. Returning an error here causes the syncer to log at
	// Error level and hold the cursor for a retry, which keeps the failure
	// visible — and stops an empty payload from emptying a live Secret.
	if s.SecretType == "" {
		return outcomeNoop, fmt.Errorf("secret_type is empty for %s/%s: server-side protocol error — expected a non-empty type (e.g. \"Opaque\")", s.Namespace, s.Name)
	}
	if len(s.Data) == 0 {
		return outcomeNoop, fmt.Errorf("data is empty for %s/%s: server-side protocol error — an upsert must carry at least one field", s.Namespace, s.Name)
	}

	data, err := decryptAll(seed, pol, s)
	if err != nil {
		return outcomeNoop, fmt.Errorf("decrypt %s/%s: %w", s.Namespace, s.Name, err)
	}

	var existing corev1.Secret
	if err := k8sClient.Get(ctx, nsName, &existing); err != nil {
		if !errors.IsNotFound(err) {
			return outcomeNoop, fmt.Errorf("get secret: %w", err)
		}
		// CREATE. Use the type the server sent directly — the server defaults
		// to "Opaque" for ordinary secrets. k8s Secret type is immutable; we
		// only set it on creation and leave pre-existing Secrets' types
		// untouched (UPDATE path below).
		if err := k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        s.Name,
				Namespace:   s.Namespace,
				Annotations: map[string]string{managedAnnotation: managedAnnotationValue},
				Labels:      map[string]string{managedLabel: managedLabelValue},
			},
			Type: corev1.SecretType(s.SecretType),
			Data: data,
		}); err != nil {
			return outcomeNoop, fmt.Errorf("create secret: %w", err)
		}
		return outcomeCreated, nil
	}

	if existing.Annotations[managedAnnotation] == managedAnnotationValue {
		// UPDATE — also backfill the label on Secrets created before the
		// label was added; harmless when already set.
		//
		// Data is replaced wholesale, not merged: Lockbox is the source of
		// truth for the entire Secret, so a field removed upstream must
		// disappear here too. The empty-payload guard above is what stops a
		// replace from being usable as a wipe.
		ensureManagedLabel(&existing)
		existing.Data = data
		if err := k8sClient.Update(ctx, &existing); err != nil {
			return outcomeNoop, fmt.Errorf("update secret: %w", err)
		}
		return outcomeUpdated, nil
	}

	// ADOPT — only when the operator has offered this Secret in-cluster.
	// Without the opt-in the controller refuses rather than annexing it,
	// so an upstream event cannot confer the ownership it is gated on.
	if existing.Annotations[adoptAnnotation] != adoptAnnotationValue {
		return outcomeNoop, fmt.Errorf(
			"refusing to adopt unmanaged secret %s/%s: apply the %s=%s annotation to offer it for adoption",
			s.Namespace, s.Name, adoptAnnotation, adoptAnnotationValue)
	}
	log.Info("adopting unmanaged secret", "namespace", nsName.Namespace, "name", nsName.Name)
	existing.Annotations[managedAnnotation] = managedAnnotationValue
	ensureManagedLabel(&existing)
	if err := k8sClient.Update(ctx, &existing); err != nil {
		return outcomeNoop, fmt.Errorf("adopt secret: %w", err)
	}
	return outcomeAdopted, nil
}

func ensureManagedLabel(s *corev1.Secret) {
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	s.Labels[managedLabel] = managedLabelValue
}

func decryptAll(seed []byte, pol Policy, s lockbox.SecretWithMetadata) (map[string][]byte, error) {
	result := make(map[string][]byte, len(s.Data))
	for k, ct := range s.Data {
		var aad []byte
		if pol.RequireAAD {
			aad = lockbox.AADFor(s.Namespace, s.Name, k)
		}
		plaintext, err := lockbox.Decrypt(seed, ct, aad)
		if err != nil {
			if pol.RequireAAD {
				// The overwhelmingly likely cause is a secret written before the
				// server began sealing with AAD, not an attack. There is
				// deliberately no unbound fallback — accepting a blob whose
				// binding fails is exactly what the binding exists to prevent,
				// and an attacker would simply strip it. Migrate instead.
				return nil, fmt.Errorf("field %q: %w — if this secret predates AAD sealing, "+
					"migrate it with `lbx reseal`, or set LOCKBOX_REQUIRE_AAD=false to sync "+
					"unbound secrets while you do", k, err)
			}
			return nil, fmt.Errorf("field %q: %w", k, err)
		}
		result[k] = plaintext
	}
	return result, nil
}
