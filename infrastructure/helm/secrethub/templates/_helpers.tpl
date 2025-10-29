{{/*
Expand the name of the chart.
*/}}
{{- define "secrethub.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "secrethub.fullname" -}}
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
{{- define "secrethub.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "secrethub.labels" -}}
helm.sh/chart: {{ include "secrethub.chart" . }}
{{ include "secrethub.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "secrethub.selectorLabels" -}}
app.kubernetes.io/name: {{ include "secrethub.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app: secrethub-core
component: core
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "secrethub.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "secrethub.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
PostgreSQL connection URL
*/}}
{{- define "secrethub.postgresqlUrl" -}}
{{- if .Values.postgresql.external }}
{{- printf "postgresql://%s:%s@%s:%d/%s?sslmode=%s&pool_size=%d" .Values.postgresql.externalUsername (default "" .Values.postgresql.externalPassword) .Values.postgresql.externalHost (.Values.postgresql.externalPort | int) .Values.postgresql.externalDatabase .Values.postgresql.sslMode (.Values.postgresql.poolSize | int) }}
{{- else }}
{{- printf "postgresql://secrethub:secrethub@%s-postgresql:5432/secrethub?pool_size=%d" (include "secrethub.fullname" .) (.Values.postgresql.poolSize | int) }}
{{- end }}
{{- end }}

{{/*
Redis connection URL
*/}}
{{- define "secrethub.redisUrl" -}}
{{- if .Values.redis.external }}
{{- if .Values.redis.sslEnabled }}
{{- if .Values.redis.externalPassword }}
{{- printf "rediss://:%s@%s:%d" .Values.redis.externalPassword .Values.redis.externalHost (.Values.redis.externalPort | int) }}
{{- else }}
{{- printf "rediss://%s:%d" .Values.redis.externalHost (.Values.redis.externalPort | int) }}
{{- end }}
{{- else }}
{{- if .Values.redis.externalPassword }}
{{- printf "redis://:%s@%s:%d" .Values.redis.externalPassword .Values.redis.externalHost (.Values.redis.externalPort | int) }}
{{- else }}
{{- printf "redis://%s:%d" .Values.redis.externalHost (.Values.redis.externalPort | int) }}
{{- end }}
{{- end }}
{{- else }}
{{- printf "redis://%s-redis:6379" (include "secrethub.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Storage class
*/}}
{{- define "secrethub.storageClass" -}}
{{- if .Values.global.storageClass }}
{{- .Values.global.storageClass }}
{{- else if .Values.core.persistence.storageClass }}
{{- .Values.core.persistence.storageClass }}
{{- end }}
{{- end }}
