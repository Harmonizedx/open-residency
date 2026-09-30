{{- define "openresidency.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "openresidency.labels" -}}
app.kubernetes.io/name: {{ include "openresidency.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version }}
{{- end -}}

{{- define "openresidency.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{ .Values.secrets.existingSecret }}
{{- else -}}
{{ include "openresidency.name" . }}-secrets
{{- end -}}
{{- end -}}

{{/*
The image reference. A digest pins the bytes and wins when set; otherwise the tag, defaulting
to the chart's appVersion with the `v` prefix the release workflow uses.
*/}}
{{- define "openresidency.image" -}}
{{- if .Values.image.digest -}}
{{ .Values.image.repository }}@{{ .Values.image.digest }}
{{- else -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default (printf "v%s" .Chart.AppVersion) }}
{{- end -}}
{{- end -}}
