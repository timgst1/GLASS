{{- define "glass.name" -}}
glass
{{- end -}}

{{- define "glass.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "glass.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "glass.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "glass.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

