{{/*
Expand the name of the chart.
*/}}
{{- define "s3-encryption-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "s3-encryption-gateway.fullname" -}}
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
{{- define "s3-encryption-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "s3-encryption-gateway.labels" -}}
helm.sh/chart: {{ include "s3-encryption-gateway.chart" . }}
{{ include "s3-encryption-gateway.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "s3-encryption-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "s3-encryption-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Convert config value to env var entry
Handles both direct values and valueFrom (secrets/configmaps)
*/}}
{{- define "s3-encryption-gateway.envVar" -}}
{{- if .valueFrom }}
{{- if .valueFrom.secretKeyRef }}
- name: {{ .name }}
  valueFrom:
    secretKeyRef:
      name: {{ .valueFrom.secretKeyRef.name }}
      key: {{ .valueFrom.secretKeyRef.key }}
{{- if .valueFrom.secretKeyRef.optional }}
      optional: {{ .valueFrom.secretKeyRef.optional }}
{{- end }}
{{- else if .valueFrom.configMapKeyRef }}
- name: {{ .name }}
  valueFrom:
    configMapKeyRef:
      name: {{ .valueFrom.configMapKeyRef.name }}
      key: {{ .valueFrom.configMapKeyRef.key }}
{{- if .valueFrom.configMapKeyRef.optional }}
      optional: {{ .valueFrom.configMapKeyRef.optional }}
{{- end }}
{{- end }}
{{- else if .value }}
- name: {{ .name }}
  value: {{ .value | quote }}
{{- end }}
{{- end }}

{{/*
Get value with default
*/}}
{{- define "s3-encryption-gateway.getValue" -}}
{{- if . }}{{ . }}{{ else }}{{ default "" }}{{ end }}
{{- end }}

