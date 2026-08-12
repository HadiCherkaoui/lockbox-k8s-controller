<!--
SPDX-FileCopyrightText: Hadi Cherkaoui <contact@hide.cherkaoui.ch>

SPDX-License-Identifier: AGPL-3.0-or-later
-->

# lockbox-k8s-controller

A Kubernetes controller that syncs encrypted secrets from a
[Lockbox](https://gitlab.cherkaoui.ch/HadiCherkaoui) server into native
`core/v1.Secret` objects in your cluster.

## Description

The controller polls the Lockbox HTTP API on a fixed interval (default 60s),
authenticates with an Ed25519 keypair via challenge-response, fetches the
delta of secret changes since its last cursor, and decrypts each event with
AES-256-GCM (key derived from the Ed25519 seed). For every event it reconciles
the matching Kubernetes Secret in the namespace dictated by Lockbox:

- **CREATE** — Secret didn't exist; create it with `lockbox.io/managed=true` and
  the `secret_type` the server sent (e.g. `Opaque`, `kubernetes.io/dockerconfigjson`).
- **UPDATE** — Secret already managed; rewrite its `data`. Data is replaced, not
  merged — Lockbox is the source of truth for the whole Secret, so a field removed
  upstream disappears here too. An upsert carrying no fields is refused as a
  protocol error rather than emptying the Secret. The k8s Secret type is
  immutable, so the type field is only set on creation and left untouched on updates.
- **ADOPT** — Secret pre-existed and was unmanaged. Requires the operator to
  offer it first by applying `lockbox.io/adopt=true` in-cluster; without that the
  event is refused. Adoption marks the Secret managed and leaves data untouched,
  and adopted Secrets are never entered into the self-heal cache (their data
  belongs to whoever created them). See [Destination limits](#destination-limits).
- **DELETE** — Secret managed and removed upstream; delete it.
- **SELF-HEAL** — If a managed Secret is externally deleted (Flux prune, `kubectl delete`,
  etc.) the controller detects the gap on the next poll tick and recreates the Secret
  from its in-memory cache, without a restart. Recovery time is at most one
  `syncInterval` (default 60s).

The keypair is generated on first start, registered with Lockbox using a
bootstrap API key, and persisted in the `lockbox-credentials` Secret in the
controller's own namespace. Subsequent restarts work without the bootstrap key.

### Destination limits

The Lockbox payload names the namespace, secret name and field key each value is
written to, so those inputs decide how far an event can reach. Two limits bound
it, both enforced before any ciphertext is decrypted, so plaintext for a rejected
event never exists in the process:

- **Namespace denylist** (`lockbox.deniedNamespaces`, default `kube-system`,
  `kube-public`, `kube-node-lease`). Every other namespace is writable, including
  ones created long after install, so namespace churn needs no config change. The
  default set is where a Secret write stops being a leak and becomes a cluster
  takeover. Set `lockbox.allowedNamespaces` to switch to a strict allowlist.
  Events naming the controller's own `lockbox-credentials` Secret are always
  refused.
- **AAD binding** (`lockbox.requireAAD`, default on). Each field is sealed
  against `domain ‖ namespace ‖ name ‖ field`, length-prefixed. Without it a
  ciphertext is a free-floating blob: the server can re-serve the value belonging
  to one secret under any other namespace, name or field and the controller will
  decrypt it there, with no key required. Requires a Lockbox server that seals
  with the identical construction (`lockbox.AADFor`); set false to fall back to
  an older server.

Events naming the controller's **own namespace** are always refused. The adopt
opt-in only guards Secrets that currently exist, so a Secret pruned and
recreated by Flux would otherwise leave a window where an event naming it takes
the CREATE path — and that namespace holds the seed and the bootstrap key.

AAD binds *location*, not *freshness* — `updated_at` cannot participate, because
the sealer never sees it and a partial update re-stamps it while leaving
untouched fields sealed under the old value. Replay of an old blob at the same
coordinates is therefore not prevented here and needs a separate mechanism.

Note what each layer actually buys: the **server-side namespace pin** is what
stops a secret being redirected at all. The denylist stops a redirection into
the namespaces where that becomes cluster takeover — it does not stop
redirection into `default` or any namespace an attacker already reads, so it is
not a fallback for the pin.

#### Enabling AAD on an existing install

`requireAAD` is on by default and there is deliberately **no unbound fallback** —
accepting a blob whose binding fails is what the binding exists to prevent.
Secrets written before the server began sealing carry an empty AAD, so enabling
this against un-migrated data makes the controller refuse every field of every
existing secret. Order matters:

1. Deploy the Lockbox server that seals with `AADFor`.
2. Update `lbx`.
3. Run `lbx reseal` to re-seal existing secrets bound (idempotent; `--dry-run`
   first). `lbx get` reports how many fields are still unbound.
4. Deploy the controller with `lockbox.requireAAD=true`.

If the controller is already running when you start, `lockbox.requireAAD=false`
restores sync while you reseal.

The controller is implemented as a `manager.Runnable` under
[controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) and
ships no CRDs — Secret reconciliation is driven entirely by the upstream
Lockbox delta stream.

### Self-heal behavior

Every sync tick the controller maintains an in-memory cache of the last
successfully reconciled state for each managed Secret. After processing the
Lockbox delta, it lists all `app.kubernetes.io/managed-by=lockbox-k8s-controller`
Secrets and recreates any that are missing. Secrets deleted upstream (Lockbox
`DELETE` event) are evicted from the cache and are not recreated.

This design (periodic full-state check, Option B) was chosen over a Watch-based
approach (Option A) because the controller ships no CRDs and runs as a
`manager.Runnable` rather than a controller-runtime `Reconciler`. A Watch would
require wiring a separate controller and a point-query Lockbox API that does not
exist. The periodic approach is equally robust for the homelab scale (≤20 secrets,
60s interval) and adds no external dependencies.

## Installation

### Helm (recommended)

The chart is published as an OCI artifact in the project's GitLab container
registry on every commit to `main` that touches `deploy/`.

```sh
helm install lockbox \
  oci://registry.cherkaoui.ch/hadicherkaoui/lockbox-k8s-controller/lockbox-k8s-controller \
  --version 0.1.0 \
  --namespace lockbox-system --create-namespace \
  --set lockbox.endpoint=https://lockbox.example \
  --set lockbox.apiKey=<bootstrap-api-key>
```

For SOPS / sealed-secrets workflows, point the chart at a bring-your-own Secret
carrying `endpoint` (string) and optional `api-key` (string) keys:

```sh
helm install lockbox \
  oci://registry.cherkaoui.ch/hadicherkaoui/lockbox-k8s-controller/lockbox-k8s-controller \
  --version 0.1.0 \
  --namespace lockbox-system --create-namespace \
  --set lockbox.existingSecret=my-lockbox-config \
  --set lockbox.skipBootstrapCheck=true
```

For Flux's `HelmRepository` (kind `oci`), the URL is the parent path without
the chart-name segment:

```yaml
apiVersion: source.toolkit.fluxcd.io/v1
kind: HelmRepository
metadata: { name: lockbox, namespace: flux-system }
spec:
  type: oci
  url: oci://registry.cherkaoui.ch/hadicherkaoui/lockbox-k8s-controller
```

Key values — see [`deploy/values.yaml`](deploy/values.yaml) for the full list:

| Value | Default | Notes |
| --- | --- | --- |
| `lockbox.endpoint` | `""` | **Required** unless `existingSecret` is set. |
| `lockbox.apiKey` | `""` | Bootstrap key for first registration; safe to remove after. |
| `lockbox.syncInterval` | `60s` | Poll interval. |
| `lockbox.existingSecret` | `""` | Bring-your-own Secret with `endpoint` + optional `api-key`. |
| `lockbox.skipBootstrapCheck` | `false` | Bypass chart-time guard requiring `apiKey` or `existingSecret`. |
| `lockbox.deniedNamespaces` | `kube-system`, `kube-public`, `kube-node-lease` | Namespaces the syncer refuses to write to. |
| `lockbox.allowedNamespaces` | `[]` | When non-empty, a strict allowlist instead of the denylist. |
| `lockbox.requireAAD` | `true` | Require each ciphertext to authenticate against its destination. |
| `image.digest` | `""` | Pin the image by digest; wins over `tag`. Preferred in production. |
| `metrics.certSecret` | `""` | Secret with `tls.crt`/`tls.key` for the metrics server, replacing the self-signed cert. |
| `replicaCount` | `1` | Leader election picks one active syncer. |
| `metrics.enabled` | `false` | Enables `:8443` HTTPS metrics with auth. |
| `serviceMonitor.enabled` | `false` | Renders a `prometheus-operator` ServiceMonitor (requires `metrics.enabled`). |
| `resources.limits.memory` | `256Mi` | Bumped from kubebuilder default to accommodate burst pages. |

### Kustomize (alternative)

```sh
make docker-build docker-push IMG=<registry>/lockbox-k8s-controller:tag
make deploy IMG=<registry>/lockbox-k8s-controller:tag
```

Then create the `lockbox-config` Secret with `endpoint` and optional `api-key`:

```sh
kubectl -n lockbox-k8s-controller-system create secret generic lockbox-config \
  --from-literal=endpoint=https://lockbox.example \
  --from-literal=api-key=<bootstrap-api-key>
```

### Uninstall

```sh
helm uninstall lockbox -n lockbox-system
# or
make undeploy
```

`lockbox-credentials` is intentionally not removed — keep it if you plan to
reinstall against the same Lockbox server (deleting it forces a fresh keypair
registration).

## Development

Run the controller locally against the current kubeconfig context:

```sh
export LOCKBOX_ENDPOINT=https://lockbox.example
export LOCKBOX_API_KEY=<bootstrap-api-key>
make run
```

Unit tests use envtest plus fake clients:

```sh
make test
make lint           # golangci-lint
helm lint deploy/   # chart validation
```

See [`AGENTS.md`](AGENTS.md) for kubebuilder conventions used in this repo.

## License

Copyright (C) 2026 Hadi Cherkaoui

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see <https://www.gnu.org/licenses/>.

SPDX-License-Identifier: AGPL-3.0-or-later
