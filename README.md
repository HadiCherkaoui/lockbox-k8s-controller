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

- **CREATE** — Secret didn't exist; create it with `lockbox.io/managed=true`.
- **UPDATE** — Secret already managed; rewrite its `data`.
- **ADOPT** — Secret pre-existed and was unmanaged; mark it managed, leave data untouched.
- **DELETE** — Secret managed and removed upstream; delete it.

The keypair is generated on first start, registered with Lockbox using a
bootstrap API key, and persisted in the `lockbox-credentials` Secret in the
controller's own namespace. Subsequent restarts work without the bootstrap key.

The controller is implemented as a `manager.Runnable` under
[controller-runtime](https://github.com/kubernetes-sigs/controller-runtime) and
ships no CRDs — Secret reconciliation is driven entirely by the upstream
Lockbox delta stream.

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
carrying `endpoint` and optional `api-key` keys:

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

Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
