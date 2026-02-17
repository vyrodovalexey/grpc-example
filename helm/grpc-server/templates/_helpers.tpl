{{/*
Expand the name of the chart.
*/}}
{{- define "grpc-server.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "grpc-server.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "grpc-server.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "grpc-server.labels" -}}
helm.sh/chart: {{ include "grpc-server.chart" . }}
{{ include "grpc-server.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "grpc-server.selectorLabels" -}}
app.kubernetes.io/name: {{ include "grpc-server.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "grpc-server.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "grpc-server.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Return the image name
*/}}
{{- define "grpc-server.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end }}

{{/*
Return the TLS secret name
*/}}
{{- define "grpc-server.tlsSecretName" -}}
{{- if .Values.tls.existingSecret }}
{{- .Values.tls.existingSecret }}
{{- else }}
{{- include "grpc-server.fullname" . }}-tls
{{- end }}
{{- end }}

{{/*
Return the Vault token secret name
*/}}
{{- define "grpc-server.vaultTokenSecretName" -}}
{{- if .Values.vault.tokenSecretName }}
{{- .Values.vault.tokenSecretName }}
{{- else }}
{{- include "grpc-server.fullname" . }}-vault-token
{{- end }}
{{- end }}

{{/*
Return the OIDC client secret name
*/}}
{{- define "grpc-server.oidcSecretName" -}}
{{- if .Values.oidc.clientSecretName }}
{{- .Values.oidc.clientSecretName }}
{{- else }}
{{- include "grpc-server.fullname" . }}-oidc
{{- end }}
{{- end }}
