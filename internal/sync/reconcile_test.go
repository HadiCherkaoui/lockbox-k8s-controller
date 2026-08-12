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

	"github.com/go-logr/logr"
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
	testControlNS  = "lockbox-system"
	// preexistingKey/preexistingVal is data the controller did not create, used
	// to assert that adoption and self-heal leave it alone.
	preexistingKey = "existing-key"
	preexistingVal = "existing-val"
)

var testSeed = make([]byte, 32)

// testPolicy mirrors the shipped defaults: every namespace writable except the
// system set, AAD required.
func testPolicy() Policy {
	denied := make(map[string]struct{}, len(DefaultDeniedNamespaces))
	for _, ns := range DefaultDeniedNamespaces {
		denied[ns] = struct{}{}
	}
	return Policy{
		DeniedNamespaces:    denied,
		ControllerNamespace: testControlNS,
		RequireAAD:          true,
	}
}

// sealField encrypts plaintext the way a correct Lockbox server would: bound to
// the coordinates the event claims for it. Tests forge a relocation by sealing
// under one identity and serving the blob under another.
func sealField(t *testing.T, nonce, plaintext []byte, ns, name, field string) lockbox.Ciphertext {
	t.Helper()
	block, err := aes.NewCipher(testSeed)
	if err != nil {
		t.Fatalf("aes: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, lockbox.AADFor(ns, name, field))
	return lockbox.Ciphertext{Nonce: lockbox.IntBytes(nonce), Data: lockbox.IntBytes(ct)}
}

func nonceOf(b byte) []byte {
	n := make([]byte, 12)
	n[0] = b
	return n
}

// upsertEvent builds a well-formed single-field event with matching AAD.
func upsertEvent(t *testing.T, ns, name, field, value string, nonce byte) lockbox.SecretWithMetadata {
	t.Helper()
	return lockbox.SecretWithMetadata{
		Namespace:  ns,
		Name:       name,
		SecretType: "Opaque",
		UpdatedAt:  1000,
		Data: map[string]lockbox.Ciphertext{
			field: sealField(t, nonceOf(nonce), []byte(value), ns, name, field),
		},
	}
}

func newSecret(annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        testSecretName,
			Namespace:   testNamespace,
			Annotations: annotations,
		},
		Data: map[string][]byte{preexistingKey: []byte(preexistingVal)},
	}
}

func managedAnnotations() map[string]string {
	return map[string]string{managedAnnotation: managedAnnotationValue}
}

func testLogger() logr.Logger { return zap.New().WithName("test") }

func TestReconcile_Create(t *testing.T) {
	fc := fake.NewClientBuilder().Build()
	event := upsertEvent(t, testNamespace, testSecretName, "password", "hunter2", 0)

	got, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event)
	if err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	if got != outcomeCreated {
		t.Fatalf("expected outcomeCreated, got %v", got)
	}
	var secret corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &secret); err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if secret.Annotations[managedAnnotation] != managedAnnotationValue {
		t.Fatal("missing managed annotation")
	}
	if secret.Labels[managedLabel] != managedLabelValue {
		t.Fatalf("missing managed-by label, got labels=%v", secret.Labels)
	}
	if string(secret.Data["password"]) != "hunter2" {
		t.Fatalf("data mismatch: %q", secret.Data["password"])
	}
	if secret.Type != corev1.SecretTypeOpaque {
		t.Fatalf("expected Opaque type, got %q", secret.Type)
	}
}

func TestReconcile_Update(t *testing.T) {
	fc := fake.NewClientBuilder().WithObjects(newSecret(managedAnnotations())).Build()
	event := upsertEvent(t, testNamespace, testSecretName, "password", "new-pass", 1)

	got, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event)
	if err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	if got != outcomeUpdated {
		t.Fatalf("expected outcomeUpdated, got %v", got)
	}
	var secret corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &secret); err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(secret.Data["password"]) != "new-pass" {
		t.Fatalf("data not updated: %q", secret.Data["password"])
	}
}

func TestReconcile_Adopt_RequiresOperatorOptIn(t *testing.T) {
	// An unmanaged Secret must NOT be annexed just because an event names it.
	// Without this the ownership gate authorizes nothing: the server picks the
	// name, the controller stamps the annotation, and the next event may then
	// rewrite or delete the object.
	fc := fake.NewClientBuilder().WithObjects(newSecret(nil)).Build()
	event := upsertEvent(t, testNamespace, testSecretName, "password", "hunter2", 2)

	got, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event)
	if err == nil {
		t.Fatal("expected refusal to adopt an unmanaged secret without the opt-in annotation")
	}
	if got != outcomeNoop {
		t.Fatalf("expected outcomeNoop, got %v", got)
	}
	var secret corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &secret); err != nil {
		t.Fatalf("get: %v", err)
	}
	if _, ok := secret.Annotations[managedAnnotation]; ok {
		t.Fatal("secret was annexed despite having no adopt opt-in")
	}
	if string(secret.Data[preexistingKey]) != preexistingVal {
		t.Fatal("pre-existing data was modified")
	}
}

func TestReconcile_Adopt_WithOptIn(t *testing.T) {
	fc := fake.NewClientBuilder().WithObjects(
		newSecret(map[string]string{adoptAnnotation: adoptAnnotationValue}),
	).Build()
	event := upsertEvent(t, testNamespace, testSecretName, "password", "hunter2", 3)

	got, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event)
	if err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	if got != outcomeAdopted {
		t.Fatalf("expected outcomeAdopted, got %v", got)
	}
	var secret corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &secret); err != nil {
		t.Fatalf("get: %v", err)
	}
	if secret.Annotations[managedAnnotation] != managedAnnotationValue {
		t.Fatal("adoption: annotation not added")
	}
	if secret.Labels[managedLabel] != managedLabelValue {
		t.Fatalf("adoption: managed-by label not added, got labels=%v", secret.Labels)
	}
	if string(secret.Data[preexistingKey]) != preexistingVal {
		t.Fatal("adoption: data was overwritten")
	}
}

func TestReconcile_AdoptedOutcomeIsNotCacheable(t *testing.T) {
	// Self-heal replays cached events. An adopted Secret's data belongs to
	// whoever created it, so caching the event would let a later replay
	// overwrite data the controller never possessed.
	if outcomeAdopted.cacheable() {
		t.Fatal("adopted secrets must not be cached for self-heal")
	}
	if !outcomeCreated.cacheable() || !outcomeUpdated.cacheable() {
		t.Fatal("created and updated secrets must be cacheable")
	}
}

func TestReconcile_DeniedNamespace(t *testing.T) {
	fc := fake.NewClientBuilder().Build()
	event := upsertEvent(t, "kube-system", "boom", "password", "hunter2", 4)

	got, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event)
	if err == nil {
		t.Fatal("expected refusal for a denied namespace")
	}
	if got != outcomeNoop {
		t.Fatalf("expected outcomeNoop, got %v", got)
	}
	var secret corev1.Secret
	if getErr := fc.Get(context.Background(), types.NamespacedName{Namespace: "kube-system", Name: "boom"}, &secret); getErr == nil {
		t.Fatal("secret must not be created in a denied namespace")
	}
}

func TestReconcile_ArbitraryNamespaceIsAllowedByDefault(t *testing.T) {
	// The default policy is open: a namespace created after the controller
	// started must work with no configuration change.
	fc := fake.NewClientBuilder().Build()
	event := upsertEvent(t, "a-brand-new-namespace", "app-secret", "token", "abc123", 5)

	got, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event)
	if err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	if got != outcomeCreated {
		t.Fatalf("expected outcomeCreated, got %v", got)
	}
}

func TestReconcile_StrictAllowlistWhenSet(t *testing.T) {
	pol := testPolicy()
	pol.AllowedNamespaces = map[string]struct{}{"only-this": {}}

	fc := fake.NewClientBuilder().Build()
	event := upsertEvent(t, "somewhere-else", "app-secret", "token", "abc123", 6)

	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, pol, event); err == nil {
		t.Fatal("expected refusal when a strict allowlist is set and the namespace is absent from it")
	}
}

func TestReconcile_RefusesOwnNamespace(t *testing.T) {
	// Overwriting the seed destroys the only key that decrypts everything in
	// Lockbox, and the controller then fails its length check on next restart.
	// The whole namespace is refused, not just lockbox-credentials by name: the
	// adopt opt-in only guards Secrets that exist, so a Secret pruned and
	// recreated by Flux leaves a window where an event naming it takes the
	// CREATE path. lockbox-auth carries API_KEY and JWT_SECRET.
	for _, name := range []string{"lockbox-credentials", "lockbox-auth", "lockbox-config", "anything-else"} {
		t.Run(name, func(t *testing.T) {
			fc := fake.NewClientBuilder().Build()
			event := upsertEvent(t, testControlNS, name, "seed", "not-a-real-seed", 7)

			got, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event)
			if err == nil {
				t.Fatalf("expected refusal for %s in the controller's own namespace", name)
			}
			if got != outcomeNoop {
				t.Fatalf("expected outcomeNoop, got %v", got)
			}
			var secret corev1.Secret
			if getErr := fc.Get(context.Background(),
				types.NamespacedName{Namespace: testControlNS, Name: name}, &secret); getErr == nil {
				t.Fatal("secret must not be created in the controller's own namespace")
			}
		})
	}
}

func TestReconcile_RelocatedCiphertextIsRejected(t *testing.T) {
	// A blob sealed for prod/db-credentials, re-served under another namespace
	// and name. Byte-identical ciphertext, nonce and tag — only the claimed
	// coordinates differ. AAD is what makes this fail.
	stolen := sealField(t, nonceOf(9), []byte("prod-db-password"), "prod", "db-credentials", "password")

	event := lockbox.SecretWithMetadata{
		Namespace:  "attacker-tenant",
		Name:       "loot",
		SecretType: "Opaque",
		UpdatedAt:  1000,
		Data:       map[string]lockbox.Ciphertext{"password": stolen},
	}

	fc := fake.NewClientBuilder().Build()
	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event); err == nil {
		t.Fatal("expected relocated ciphertext to fail authentication")
	}
	var secret corev1.Secret
	if getErr := fc.Get(context.Background(), types.NamespacedName{Namespace: "attacker-tenant", Name: "loot"}, &secret); getErr == nil {
		t.Fatal("plaintext must not land when the ciphertext is not bound to this destination")
	}
}

func TestReconcile_FieldKeySwapIsRejected(t *testing.T) {
	// Same secret, but the blob sealed for "password" re-served as "tls.key".
	swapped := sealField(t, nonceOf(10), []byte("hunter2"), testNamespace, testSecretName, "password")

	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       testSecretName,
		SecretType: "Opaque",
		UpdatedAt:  1000,
		Data:       map[string]lockbox.Ciphertext{"tls.key": swapped},
	}

	fc := fake.NewClientBuilder().Build()
	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event); err == nil {
		t.Fatal("expected field-key swap to fail authentication")
	}
}

// TestReconcile_TimestampIsNotBound records that a rewritten updated_at does
// NOT invalidate a ciphertext. updated_at cannot be part of the AAD: the sealer
// never sees it (the server assigns it on write), and a partial update
// re-stamps it while leaving untouched fields sealed under the old value, which
// would make those fields permanently undecryptable. Rollback protection
// therefore is not provided here and needs its own mechanism.
func TestReconcile_TimestampIsNotBound(t *testing.T) {
	replayed := sealField(t, nonceOf(11), []byte("old-password"), testNamespace, testSecretName, "password")

	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       testSecretName,
		SecretType: "Opaque",
		UpdatedAt:  9999, // not the timestamp it was sealed under
		Data:       map[string]lockbox.Ciphertext{"password": replayed},
	}

	fc := fake.NewClientBuilder().Build()
	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event); err != nil {
		t.Fatalf("updated_at must not participate in the AAD: %v", err)
	}
}

func TestReconcile_AADDisabledAcceptsUnboundCiphertext(t *testing.T) {
	// The compatibility path for a server that does not yet seal with AAD.
	pol := testPolicy()
	pol.RequireAAD = false

	block, _ := aes.NewCipher(testSeed)
	gcm, _ := cipher.NewGCM(block)
	raw := gcm.Seal(nil, nonceOf(12), []byte("hunter2"), nil)

	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       testSecretName,
		SecretType: "Opaque",
		UpdatedAt:  1000,
		Data: map[string]lockbox.Ciphertext{
			"password": {Nonce: lockbox.IntBytes(nonceOf(12)), Data: lockbox.IntBytes(raw)},
		},
	}

	fc := fake.NewClientBuilder().Build()
	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, pol, event); err != nil {
		t.Fatalf("with RequireAAD=false an unbound ciphertext must decrypt: %v", err)
	}
}

func TestReconcile_Delete_Managed(t *testing.T) {
	fc := fake.NewClientBuilder().WithObjects(newSecret(managedAnnotations())).Build()

	ts := int64(1234)
	event := lockbox.SecretWithMetadata{Namespace: testNamespace, Name: testSecretName, DeletedAt: &ts}

	got, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event)
	if err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	if got != outcomeDeleted {
		t.Fatalf("expected outcomeDeleted, got %v", got)
	}
	var secret corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &secret); err == nil {
		t.Fatal("expected secret to be deleted")
	}
}

func TestReconcile_Delete_Unmanaged(t *testing.T) {
	fc := fake.NewClientBuilder().WithObjects(newSecret(nil)).Build()

	ts := int64(1234)
	event := lockbox.SecretWithMetadata{Namespace: testNamespace, Name: testSecretName, DeletedAt: &ts}

	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var secret corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &secret); err != nil {
		t.Fatal("unmanaged secret was deleted — must not happen")
	}
}

func TestReconcile_Delete_NotFound(t *testing.T) {
	fc := fake.NewClientBuilder().Build()

	ts := int64(1234)
	event := lockbox.SecretWithMetadata{Namespace: testNamespace, Name: "nonexistent", DeletedAt: &ts}

	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
}

func TestReconcile_Create_WithNonOpaqueSecretType(t *testing.T) {
	fc := fake.NewClientBuilder().Build()
	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       "typed-secret",
		SecretType: "kubernetes.io/dockerconfigjson",
		UpdatedAt:  1000,
		Data: map[string]lockbox.Ciphertext{
			".dockerconfigjson": sealField(t, nonceOf(13), []byte(`{"auths":{}}`),
				testNamespace, "typed-secret", ".dockerconfigjson"),
		},
	}

	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event); err != nil {
		t.Fatalf("reconcileSecret: %v", err)
	}
	var secret corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "typed-secret"}, &secret); err != nil {
		t.Fatalf("secret not created: %v", err)
	}
	if secret.Type != "kubernetes.io/dockerconfigjson" {
		t.Fatalf("expected dockerconfigjson type, got %q", secret.Type)
	}
}

func TestReconcile_EmptySecretType_IsProtocolError(t *testing.T) {
	fc := fake.NewClientBuilder().Build()
	event := upsertEvent(t, testNamespace, "bad-secret", "password", "hunter2", 14)
	event.SecretType = ""

	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event); err == nil {
		t.Fatal("expected error for empty secret_type, got nil")
	}
	var secret corev1.Secret
	if getErr := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: "bad-secret"}, &secret); getErr == nil {
		t.Fatal("secret must not be created when secret_type is empty")
	}
}

func TestReconcile_EmptyData_IsProtocolError(t *testing.T) {
	// An upsert carrying no fields would otherwise replace a live Secret's data
	// with an empty map — a wipe driven entirely by the payload.
	fc := fake.NewClientBuilder().WithObjects(newSecret(managedAnnotations())).Build()
	event := lockbox.SecretWithMetadata{
		Namespace:  testNamespace,
		Name:       testSecretName,
		SecretType: "Opaque",
		UpdatedAt:  1000,
		Data:       map[string]lockbox.Ciphertext{},
	}

	if _, err := reconcileSecret(context.Background(), testLogger(), fc, testSeed, testPolicy(), event); err == nil {
		t.Fatal("expected error for an upsert with no fields, got nil")
	}
	var secret corev1.Secret
	if err := fc.Get(context.Background(), types.NamespacedName{Namespace: testNamespace, Name: testSecretName}, &secret); err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(secret.Data[preexistingKey]) != preexistingVal {
		t.Fatal("live secret data was wiped by an empty payload")
	}
}
