// internal/sync/reconcile_test.go
package sync

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	"gitlab.cherkaoui.ch/HadiCherkaoui/lockbox-k8s-controller/internal/lockbox"
)

const testNamespace = "default"

var testSeed = make([]byte, 32)

func encryptField(t *testing.T, nonce []byte, plaintext []byte) lockbox.Ciphertext {
	t.Helper()
	block, err := aes.NewCipher(testSeed)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	return lockbox.Ciphertext{Nonce: lockbox.IntBytes(nonce), Data: lockbox.IntBytes(ct)}
}

func newSecret(managed bool) *corev1.Secret {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: testNamespace},
		Data:       map[string][]byte{"existing-key": []byte("existing-val")},
	}
	if managed {
		s.Annotations = map[string]string{managedAnnotation: managedAnnotationValue}
	}
	return s
}

func TestReconcile_Create(t *testing.T) {
	fc := fake.NewClientBuilder().Build()
	nonce := make([]byte, 12)
	event := lockbox.SecretWithMetadata{
		Namespace: testNamespace,
		Name:      "my-secret",
		Data:      map[string]lockbox.Ciphertext{"password": encryptField(t, nonce, []byte("hunter2"))},
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "my-secret"}, &got); err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if got.Annotations[managedAnnotation] != managedAnnotationValue {
		t.Fatal("missing managed annotation")
	}
	if got.Labels[managedLabel] != managedLabelValue {
		t.Fatalf("missing managed-by label, got labels=%v", got.Labels)
	}
	if string(got.Data["password"]) != "hunter2" {
		t.Fatalf("data mismatch: %q", got.Data["password"])
	}
}

func TestReconcile_Update(t *testing.T) {
	existing := newSecret(true)
	fc := fake.NewClientBuilder().WithObjects(existing).Build()

	nonce := make([]byte, 12)
	nonce[0] = 1
	event := lockbox.SecretWithMetadata{
		Namespace: testNamespace,
		Name:      "my-secret",
		Data:      map[string]lockbox.Ciphertext{"password": encryptField(t, nonce, []byte("new-pass"))},
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "my-secret"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.Data["password"]) != "new-pass" {
		t.Fatalf("data not updated: %q", got.Data["password"])
	}
}

func TestReconcile_Adopt(t *testing.T) {
	existing := newSecret(false)
	fc := fake.NewClientBuilder().WithObjects(existing).Build()

	event := lockbox.SecretWithMetadata{
		Namespace: testNamespace,
		Name:      "my-secret",
		Data:      map[string]lockbox.Ciphertext{},
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "my-secret"}, &got); err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Annotations[managedAnnotation] != managedAnnotationValue {
		t.Fatal("adoption: annotation not added")
	}
	if got.Labels[managedLabel] != managedLabelValue {
		t.Fatalf("adoption: managed-by label not added, got labels=%v", got.Labels)
	}
	if string(got.Data["existing-key"]) != "existing-val" {
		t.Fatal("adoption: data was overwritten")
	}
}

func TestReconcile_Delete_Managed(t *testing.T) {
	existing := newSecret(true)
	fc := fake.NewClientBuilder().WithObjects(existing).Build()

	ts := int64(1234)
	event := lockbox.SecretWithMetadata{
		Namespace: testNamespace,
		Name:      "my-secret",
		DeletedAt: &ts,
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "my-secret"}, &got)
	if err == nil {
		t.Fatal("expected secret to be deleted")
	}
}

func TestReconcile_Delete_Unmanaged(t *testing.T) {
	existing := newSecret(false)
	fc := fake.NewClientBuilder().WithObjects(existing).Build()

	ts := int64(1234)
	event := lockbox.SecretWithMetadata{
		Namespace: testNamespace,
		Name:      "my-secret",
		DeletedAt: &ts,
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	// Secret must still exist
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "my-secret"}, &got); err != nil {
		t.Fatal("unmanaged secret was deleted — must not happen")
	}
}

func TestReconcile_Delete_NotFound(t *testing.T) {
	// Secret doesn't exist — delete event should be a no-op
	fc := fake.NewClientBuilder().Build()

	ts := int64(1234)
	event := lockbox.SecretWithMetadata{
		Namespace: testNamespace,
		Name:      "nonexistent",
		DeletedAt: &ts,
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	// No panic, no error — success
}
