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
	// created or adopted by the syncer.
	managedAnnotation      = "lockbox.io/managed"
	managedAnnotationValue = "true"
	// managedLabel surfaces the same "we manage this" signal as a label, so
	// operators can run `kubectl get secrets -l app.kubernetes.io/managed-by=lockbox-k8s-controller`
	// to enumerate managed objects. Mirrors the convention used by
	// cert-manager, external-secrets, etc.
	managedLabel      = "app.kubernetes.io/managed-by"
	managedLabelValue = "lockbox-k8s-controller"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

// reconcileSecret syncs one Lockbox secret event to a K8s Secret.
func reconcileSecret(
	ctx context.Context,
	log logr.Logger,
	k8sClient client.Client,
	seed []byte,
	s lockbox.SecretWithMetadata,
) error {
	nsName := types.NamespacedName{Namespace: s.Namespace, Name: s.Name}

	if s.DeletedAt != nil {
		return handleDelete(ctx, log, k8sClient, nsName)
	}
	return handleUpsert(ctx, log, k8sClient, seed, s, nsName)
}

func handleDelete(ctx context.Context, log logr.Logger, k8sClient client.Client, nsName types.NamespacedName) error {
	var existing corev1.Secret
	if err := k8sClient.Get(ctx, nsName, &existing); err != nil {
		if errors.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("get secret for delete: %w", err)
	}
	if existing.Annotations[managedAnnotation] != managedAnnotationValue {
		log.Info("skipping delete of unmanaged secret",
			"namespace", nsName.Namespace, "name", nsName.Name)
		return nil
	}
	return k8sClient.Delete(ctx, &existing)
}

func handleUpsert(
	ctx context.Context,
	log logr.Logger,
	k8sClient client.Client,
	seed []byte,
	s lockbox.SecretWithMetadata,
	nsName types.NamespacedName,
) error {
	data, err := decryptAll(seed, s.Data)
	if err != nil {
		return fmt.Errorf("decrypt %s/%s: %w", s.Namespace, s.Name, err)
	}

	var existing corev1.Secret
	if err := k8sClient.Get(ctx, nsName, &existing); err != nil {
		if !errors.IsNotFound(err) {
			return fmt.Errorf("get secret: %w", err)
		}
		// CREATE
		return k8sClient.Create(ctx, &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:        s.Name,
				Namespace:   s.Namespace,
				Annotations: map[string]string{managedAnnotation: managedAnnotationValue},
				Labels:      map[string]string{managedLabel: managedLabelValue},
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		})
	}

	if existing.Annotations[managedAnnotation] == managedAnnotationValue {
		// UPDATE — also backfill the label on Secrets created before the
		// label was added; harmless when already set.
		ensureManagedLabel(&existing)
		existing.Data = data
		return k8sClient.Update(ctx, &existing)
	}

	// ADOPT — mark managed, leave data untouched
	log.Info("adopting unmanaged secret", "namespace", nsName.Namespace, "name", nsName.Name)
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations[managedAnnotation] = managedAnnotationValue
	ensureManagedLabel(&existing)
	return k8sClient.Update(ctx, &existing)
}

func ensureManagedLabel(s *corev1.Secret) {
	if s.Labels == nil {
		s.Labels = map[string]string{}
	}
	s.Labels[managedLabel] = managedLabelValue
}

func decryptAll(seed []byte, fields map[string]lockbox.Ciphertext) (map[string][]byte, error) {
	result := make(map[string][]byte, len(fields))
	for k, ct := range fields {
		plaintext, err := lockbox.Decrypt(seed, ct)
		if err != nil {
			return nil, fmt.Errorf("field %q: %w", k, err)
		}
		result[k] = plaintext
	}
	return result, nil
}
