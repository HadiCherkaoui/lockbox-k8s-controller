{{/*
Common helpers for the lockbox-k8s-controller chart.
*/}}

{{/* Name of the chart (truncated to 63 chars per DNS-1123). */}}
{{- define "lockbox.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Fully-qualified release name (truncated to 63 chars). */}}
{{- define "lockbox.fullname" -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{/* Common labels applied to every resource. */}}
{{- define "lockbox.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
app.kubernetes.io/name: {{ include "lockbox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: controller
app.kubernetes.io/part-of: lockbox
{{- end -}}

{{/* Selector labels (subset of `labels`, used for matchLabels — stable across upgrades). */}}
{{- define "lockbox.selectorLabels" -}}
app.kubernetes.io/name: {{ include "lockbox.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* ServiceAccount name. Honors `.Values.rbac.serviceAccountName` override. */}}
{{- define "lockbox.serviceAccountName" -}}
{{- if .Values.rbac.serviceAccountName -}}
{{- .Values.rbac.serviceAccountName -}}
{{- else if .Values.rbac.create -}}
{{- include "lockbox.fullname" . -}}
{{- else -}}
{{- fail "rbac.create=false requires rbac.serviceAccountName to be set (the chart can't reference a SA it didn't create — the pod would stay Pending)" -}}
{{- end -}}
{{- end -}}

{{/* Container image reference. A digest, when set, wins over any tag: it is the
     only form that pins what actually runs, since a tag can be repointed in the
     registry after the fact. Otherwise falls back to image.tag, defaulting to
     .Chart.AppVersion. */}}
{{- define "lockbox.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repo .Values.image.digest -}}
{{- else -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repo $tag -}}
{{- end -}}
{{- end -}}

{{/* Name of the Secret carrying LOCKBOX_ENDPOINT + LOCKBOX_API_KEY.
     Resolves to the user-supplied `lockbox.existingSecret` when set,
     otherwise to a chart-managed Secret named `<fullname>-config`. */}}
{{- define "lockbox.configSecretName" -}}
{{- if .Values.lockbox.existingSecret -}}
{{- .Values.lockbox.existingSecret -}}
{{- else -}}
{{- printf "%s-config" (include "lockbox.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Hard-fail if neither lockbox.endpoint nor lockbox.existingSecret is set —
     the manager would crash-loop on the mustEnv("LOCKBOX_ENDPOINT") guard. */}}
{{- define "lockbox.requireEndpoint" -}}
{{- if and (not .Values.lockbox.endpoint) (not .Values.lockbox.existingSecret) -}}
{{- fail "lockbox.endpoint is required (or set lockbox.existingSecret to point at a bring-your-own Secret with `endpoint` and optional `api-key`)" -}}
{{- end -}}
{{- end -}}

{{/* Hard-fail on initial install if no bootstrap source is configured.
     Without an apiKey (or an existingSecret that carries one) the controller's
     first start can't register its keypair and crashes with an opaque 401.
     Set `lockbox.skipBootstrapCheck=true` to bypass when re-installing
     against a cluster where the `lockbox-credentials` Secret already exists. */}}
{{- define "lockbox.requireBootstrap" -}}
{{- if and (not .Values.lockbox.skipBootstrapCheck) (not .Values.lockbox.existingSecret) (not .Values.lockbox.apiKey) -}}
{{- fail "lockbox.apiKey is required for the initial keypair registration. Set lockbox.apiKey=<bootstrap-key>, OR lockbox.existingSecret=<your-secret>, OR lockbox.skipBootstrapCheck=true if `lockbox-credentials` already exists in the release namespace." -}}
{{- end -}}
{{- end -}}
