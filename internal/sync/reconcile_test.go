// SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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

const (
	testNamespace  = "default"
	testSecretName = "my-secret"
)

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
		ObjectMeta: metav1.ObjectMeta{Name: testSecretName, Namespace: testNamespace},
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
		Namespace:  testNamespace,
		Name:       testSecretName,
		SecretType: "Opaque",
		Data:       map[string]lockbox.Ciphertext{"password": encryptField(t, nonce, []byte("hunter2"))},
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &got); err != nil {
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
	if got.Type != corev1.SecretTypeOpaque {
		t.Fatalf("expected Opaque type, got %q", got.Type)
	}
}

func TestReconcile_Update(t *testing.T) {
	existing := newSecret(true)
	fc := fake.NewClientBuilder().WithObjects(existing).Build()

	nonce := make([]byte, 12)
	nonce[0] = 1
	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       testSecretName,
		SecretType: "Opaque",
		Data:       map[string]lockbox.Ciphertext{"password": encryptField(t, nonce, []byte("new-pass"))},
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &got); err != nil {
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
		Namespace:  testNamespace,
		Name:       testSecretName,
		SecretType: "Opaque",
		Data:       map[string]lockbox.Ciphertext{},
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &got); err != nil {
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
		Name:      testSecretName,
		DeletedAt: &ts,
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &got)
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
		Name:      testSecretName,
		DeletedAt: &ts,
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	// Secret must still exist
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &got); err != nil {
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

func TestReconcile_Create_OpaqueType(t *testing.T) {
	// server_type="Opaque" is the common case — must create a Opaque Secret.
	fc := fake.NewClientBuilder().Build()
	nonce := make([]byte, 12)
	nonce[0] = 5
	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       "opaque-secret",
		SecretType: "Opaque",
		Data: map[string]lockbox.Ciphertext{
			"key": encryptField(t, nonce, []byte("value")),
		},
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "opaque-secret"}, &got); err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if got.Type != corev1.SecretTypeOpaque {
		t.Fatalf("expected Opaque type, got %q", got.Type)
	}
}

func TestReconcile_Create_WithNonOpaqueSecretType(t *testing.T) {
	// When the server sends a non-Opaque secret_type, the created k8s Secret
	// must use exactly that type.
	fc := fake.NewClientBuilder().Build()
	nonce := make([]byte, 12)
	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       "typed-secret",
		SecretType: "kubernetes.io/dockerconfigjson",
		Data: map[string]lockbox.Ciphertext{
			".dockerconfigjson": encryptField(t, nonce, []byte(`{"auths":{}}`)),
		},
	}
	logger := zap.New().WithName("test")
	if err := reconcileSecret(context.Background(), logger, fc, testSeed, event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var got corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "typed-secret"}, &got); err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if got.Type != "kubernetes.io/dockerconfigjson" {
		t.Fatalf("expected dockerconfigjson type, got %q", got.Type)
	}
}

func TestReconcile_EmptySecretType_IsProtocolError(t *testing.T) {
	// An empty secret_type must be treated as a protocol error: reconcileSecret
	// must return a non-nil error so the syncer logs at Error level and holds
	// the cursor, making the server-side bug visible.
	fc := fake.NewClientBuilder().Build()
	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       "bad-secret",
		SecretType: "", // empty — malformed server response
		Data:       map[string]lockbox.Ciphertext{},
	}
	logger := zap.New().WithName("test")
	err := reconcileSecret(context.Background(), logger, fc, testSeed, event)
	if err == nil {
		t.Fatal("expected error for empty secret_type, got nil")
	}
	// Confirm no Secret was created.
	var got corev1.Secret
	if getErr := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "bad-secret"}, &got); getErr == nil {
		t.Fatal("secret must not be created when secret_type is empty")
	}
}
