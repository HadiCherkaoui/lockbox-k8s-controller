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

const managedAnnotation = "lockbox.io/managed"

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
	if existing.Annotations[managedAnnotation] != "true" {
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
				Annotations: map[string]string{managedAnnotation: "true"},
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		})
	}

	if existing.Annotations[managedAnnotation] == "true" {
		// UPDATE
		existing.Data = data
		return k8sClient.Update(ctx, &existing)
	}

	// ADOPT — mark managed, leave data untouched
	log.Info("adopting unmanaged secret", "namespace", nsName.Namespace, "name", nsName.Name)
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations[managedAnnotation] = "true"
	return k8sClient.Update(ctx, &existing)
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
