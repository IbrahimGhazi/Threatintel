{{/*
  Common name / label helpers.
*/}}
{{- define "ti.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ti.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "ti.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels applied to every resource. */}}
{{- define "ti.labels" -}}
helm.sh/chart: {{ include "ti.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: ti-platform
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

{{/* Selector labels per service (pass service name as .svc) */}}
{{- define "ti.selectorLabels" -}}
app.kubernetes.io/name: {{ .svc }}
app.kubernetes.io/instance: {{ .ctx.Release.Name }}
app.kubernetes.io/component: {{ .svc }}
{{- end -}}

{{/* Full resource name per service */}}
{{- define "ti.svcName" -}}
{{- printf "%s-%s" .ctx.Release.Name .svc | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Image reference; per-service repository + global tag/registry. */}}
{{- define "ti.image" -}}
{{- $reg := default .ctx.Values.image.registry .ctx.Values.global.imageRegistry -}}
{{- $repo := .cfg.image.repository -}}
{{- $tag := default .ctx.Values.image.tag .cfg.image.tag -}}
{{- if $reg -}}
{{- printf "%s/%s:%s" $reg $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}

{{/* Reference to the platform secret name (existing or release-created). */}}
{{- define "ti.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" .Release.Name -}}
{{- end -}}
{{- end -}}

{{/*
  DATABASE_URL / REDIS_URL / NATS_URL builders.
  Reads password from the shared secret via envFrom, but URL templates
  use placeholder and are resolved at runtime via envsubst-in-image OR
  by composing in an initContainer. For simplicity we set host/db/user
  here and pass password separately; the app concatenates at startup.
*/}}
{{- define "ti.pgHost" -}}
{{- if .Values.postgresql.enabled -}}
{{- printf "%s-postgresql.%s.svc.%s" .Release.Name .Release.Namespace .Values.global.clusterDomain -}}
{{- else -}}
{{- .Values.externalDatabase.host -}}
{{- end -}}
{{- end -}}

{{- define "ti.redisHost" -}}
{{- if .Values.redis.enabled -}}
{{- printf "%s-redis-master.%s.svc.%s" .Release.Name .Release.Namespace .Values.global.clusterDomain -}}
{{- else -}}
{{- .Values.externalRedis.host | default "redis" -}}
{{- end -}}
{{- end -}}

{{- define "ti.natsUrl" -}}
{{- if .Values.nats.enabled -}}
{{- printf "nats://%s-nats.%s.svc.%s:4222" .Release.Name .Release.Namespace .Values.global.clusterDomain -}}
{{- else -}}
{{- .Values.externalNats.url | default "nats://nats:4222" -}}
{{- end -}}
{{- end -}}

{{/*
  Common pod securityContext.
*/}}
{{- define "ti.podSecurityContext" -}}
runAsNonRoot: {{ .Values.podSecurity.runAsNonRoot }}
runAsUser:    {{ .Values.podSecurity.runAsUser }}
runAsGroup:   {{ .Values.podSecurity.runAsGroup }}
fsGroup:      {{ .Values.podSecurity.fsGroup }}
seccompProfile:
  type: {{ .Values.podSecurity.seccompProfile.type }}
{{- end -}}

{{- define "ti.containerSecurityContext" -}}
allowPrivilegeEscalation: {{ .Values.podSecurity.allowPrivilegeEscalation }}
readOnlyRootFilesystem:   {{ .Values.podSecurity.readOnlyRootFilesystem }}
capabilities:
  drop: {{ toYaml .Values.podSecurity.capabilitiesDrop | nindent 4 }}
{{- end -}}

{{/*
  Env vars common to every platform pod — wires passwords and addresses
  from the shared secret + cluster topology.
*/}}
{{- define "ti.commonEnv" -}}
- name: POSTGRES_HOST
  value: {{ include "ti.pgHost" . | quote }}
- name: POSTGRES_PORT
  value: "{{ .Values.externalDatabase.port }}"
- name: POSTGRES_DB
  value: {{ .Values.externalDatabase.database | quote }}
- name: POSTGRES_USER
  value: {{ .Values.externalDatabase.username | quote }}
- name: POSTGRES_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "ti.secretName" . }}
      key: POSTGRES_PASSWORD
- name: REDIS_HOST
  value: {{ include "ti.redisHost" . | quote }}
- name: REDIS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "ti.secretName" . }}
      key: REDIS_PASSWORD
- name: NATS_URL
  value: {{ include "ti.natsUrl" . | quote }}
- name: NATS_USER
  value: "tiplatform"
- name: NATS_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ include "ti.secretName" . }}
      key: NATS_PASSWORD
- name: API_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "ti.secretName" . }}
      key: API_KEY
- name: SECRET_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "ti.secretName" . }}
      key: SECRET_KEY
- name: DATABASE_URL
  value: "postgresql+asyncpg://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):$(POSTGRES_PORT)/$(POSTGRES_DB)"
# REDIS_URL — per-service DB index supplied by each service template via REDIS_DB.
# Resolved by kubelet env expansion: REDIS_PASSWORD and REDIS_HOST are defined above.
- name: REDIS_DB
  value: "0"
- name: REDIS_URL
  value: "redis://:$(REDIS_PASSWORD)@$(REDIS_HOST):6379/$(REDIS_DB)"
{{- end -}}

{{/* Topology spread + anti-affinity for a given service label. */}}
{{- define "ti.spreadAndAffinity" -}}
affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          topologyKey: kubernetes.io/hostname
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: {{ .svc }}
              app.kubernetes.io/instance: {{ .ctx.Release.Name }}
{{- if .ctx.Values.global.topologySpread.enabled }}
topologySpreadConstraints:
  - maxSkew: 1
    topologyKey: {{ .ctx.Values.global.topologySpread.topologyKey }}
    whenUnsatisfiable: ScheduleAnyway
    labelSelector:
      matchLabels:
        app.kubernetes.io/name: {{ .svc }}
        app.kubernetes.io/instance: {{ .ctx.Release.Name }}
{{- end }}
{{- end -}}
