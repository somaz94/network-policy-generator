{{/*
Expand the name of the chart.
*/}}
{{- define "network-policy-generator.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "network-policy-generator.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "network-policy-generator.labels" -}}
helm.sh/chart: {{ include "network-policy-generator.chart" . }}
app.kubernetes.io/name: {{ include "network-policy-generator.name" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "network-policy-generator.selectorLabels" -}}
control-plane: controller-manager
{{- end }}
