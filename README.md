````markdown
# glass – Quickstart & Cluster-Bedienung (inkl. Encryption + KEK Rotation)

`glass` ist ein schlanker Secretstore für Kubernetes: Secrets werden per HTTP API geschrieben/gelesen und können z.B. via External Secrets Operator (ESO) in Kubernetes Secrets synchronisiert werden. Persistenz läuft über SQLite (PVC). Secrets werden im Storage per Envelope Encryption verschlüsselt (DEK pro Version, KEK aus K8s Secret mount).

> Wichtig: Dieses Tutorial geht davon aus, dass dein Helm-Chart **Encryption wirklich verdrahtet**:
> - Env Vars: `ENCRYPTION_MODE`, `KEK_DIR`, `ACTIVE_KEK_ID`
> - Secret-Mount für KEKs (z.B. `/mnt/keks`)
> - Values: `encryption.*` (siehe unten)
>
> Falls dein Chart das noch nicht hat, musst du es einmalig ergänzen (siehe Abschnitt “Helm-Chart: Encryption verdrahten”).

---

## Voraussetzungen

- Kubernetes Cluster (inkl. StorageClass für PVC)
- Helm v3
- `kubectl`
- Optional: External Secrets Operator (ESO)

---

## Architektur in 30 Sekunden

- **Storage**: SQLite DB-Datei auf PVC (kein extra DB-Pod)
- **API**:
  - `PUT /v1/secret` (write)
  - `GET /v1/secret?key=...` (read)
  - `GET /v1/secret/meta?key=...` (meta)
  - `GET /v1/secrets?prefix=...` (bulk/list, ESO-friendly)
- **AuthN**: Bearer Token aus Datei (K8s Secret mount)
- **AuthZ**: Policy-Datei (YAML) aus ConfigMap mount
- **Encryption at Rest**: Envelope (AES-256-GCM), KEKs aus Directory (K8s Secret mount)

---

## Helm-Chart: Encryption verdrahten (einmalig prüfen/ergänzen)

Wenn du im Pod **kein** `/mnt/keks` siehst, dann ist Encryption im Chart noch nicht verdrahtet.

### `values.yaml` – Defaults
Stelle sicher, dass du so etwas hast:

```yaml
encryption:
  mode: none            # none|envelope
  kekDir: /mnt/keks
  activeKekId: default
  kekSecretName: glass-kek
````

### `deployment.yaml` – Env Vars + Mount + Volume

Unter `env:`:

```yaml
- name: ENCRYPTION_MODE
  value: {{ .Values.encryption.mode | quote }}
- name: KEK_DIR
  value: {{ .Values.encryption.kekDir | quote }}
- name: ACTIVE_KEK_ID
  value: {{ .Values.encryption.activeKekId | quote }}
```

Unter `volumeMounts:`:

```yaml
- name: keks
  mountPath: {{ .Values.encryption.kekDir | quote }}
  readOnly: true
```

Unter `volumes:`:

```yaml
- name: keks
  secret:
    secretName: {{ .Values.encryption.kekSecretName | quote }}
```

> Danach `helm upgrade ...` durchführen.

---

## Quickstart: Cluster Deployment (Helm)

### 1) Namespace

```bash
kubectl create namespace glass
```

### 2) KEK Secret erstellen (Encryption)

`glass` erwartet pro KEK eine Datei `<kek_id>` im `KEK_DIR`.
Inhalt: entweder **base64 von 32 bytes** (empfohlen) oder **32 raw bytes**.

```bash
KEK_B64="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"

kubectl -n glass create secret generic glass-kek \
  --from-literal=default="${KEK_B64}"
```

### 3) values-Datei anlegen (Auth/Policy/SQLite + Encryption)

```bash
cat <<'YAML' > values.cluster.yaml
image:
  # Wichtig: repository muss lowercase sein
  repository: ghcr.io/timgst1/glass/glass
  tag: "0.1.0"
  pullPolicy: IfNotPresent

auth:
  mode: bearer
  # Format: name=token (eine Zeile pro Token)
  tokenFileContent: |
    webhook=secret-token

policy:
  # Beispiel: erlaubt read/write/list für team-a/
  content: |
    apiVersion: glass.secretstore/v1alpha1
    kind: Policy
    metadata:
      name: default
    subjects:
      - name: eso
        match:
          kind: bearer
          name: webhook
    roles:
      - name: team-a-rw
        permissions:
          - action: read
            keyPrefix: "team-a/"
          - action: write
            keyPrefix: "team-a/"
          - action: list
            keyPrefix: "team-a/"
    bindings:
      - subject: eso
        roles: [team-a-rw]

storage:
  backend: sqlite
  sqlitePath: /data/glass.db
  persistence:
    # WICHTIG: true => PVC/PV (persistent). false => emptyDir (flüchtig).
    enabled: true
    size: 1Gi
    # storageClassName: "YOUR_STORAGECLASS"

encryption:
  mode: envelope
  kekDir: /mnt/keks
  activeKekId: default
  kekSecretName: glass-kek
YAML
```

### 4) Deploy

```bash
helm upgrade --install glass ./charts/glass -n glass -f values.cluster.yaml
```

### 5) Status prüfen

> Hinweis: Der Service heißt standardmäßig `<release>-glass`.
> Bei `--install glass` ist das **`glass-glass`**.

```bash
kubectl -n glass get pods
kubectl -n glass get svc
kubectl -n glass get pvc
kubectl -n glass rollout status deploy/glass-glass
kubectl -n glass logs deploy/glass-glass -f
```

### 6) Verifizieren: PVC + KEK Mount

**PVC vorhanden?**

```bash
kubectl -n glass get pvc
```

**Pod hat KEK-Secret gemountet?**

```bash
kubectl -n glass describe pod -l app.kubernetes.io/instance=glass | sed -n '/Volumes:/,/QoS Class:/p'
```

Du solltest jetzt neben `auth`, `policy`, `data` auch sehen:

* `keks: Secret ... SecretName: glass-kek`

> Wenn dort `data: EmptyDir` steht, dann ist Persistenz noch aus.
> Wenn `keks` fehlt, ist der Chart noch nicht wie oben verdrahtet.

### 7) API testen (port-forward)

```bash
kubectl -n glass port-forward svc/glass-glass 8080:8080
```

Write:

```bash
curl -sS -X PUT "http://127.0.0.1:8080/v1/secret" \
  -H "Authorization: Bearer secret-token" \
  -H "Content-Type: application/json" \
  -d '{"key":"team-a/db","value":"dbpass"}'
```

Read:

```bash
curl -sS "http://127.0.0.1:8080/v1/secret?key=team-a/db" \
  -H "Authorization: Bearer secret-token"
```

Bulk/List (ESO-friendly Map; default `keys=relative`, `format=map`):

```bash
curl -sS "http://127.0.0.1:8080/v1/secrets?prefix=team-a/" \
  -H "Authorization: Bearer secret-token"
```

Antwort-Beispiel:

```json
{"data":{"db":"dbpass"}}
```

---

## Encryption at Rest (Envelope) – KEK Rotation Tutorial

Ziel:

1. Neuen KEK hinzufügen
2. `ACTIVE_KEK_ID` umstellen (neue Writes nutzen neuen KEK)
3. Alte Records per CLI “rewrap”en (nur `wrapped_dek`, nicht ciphertext)
4. Alten KEK entfernen (erst wenn alles umgestellt ist)

### Schritt A: neuen KEK hinzufügen (Secret erweitern)

```bash
NEW2_KEK_B64="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"

kubectl -n glass patch secret glass-kek \
  --type merge \
  -p "{\"stringData\":{\"kek-2026-01\":\"${NEW2_KEK_B64}\"}}"
```

Damit existieren im Pod (nach Mount/Refresh) z.B.:

* `/mnt/keks/default`
* `/mnt/keks/kek-2026-01`

### Schritt B: ACTIVE_KEK_ID umstellen + rollout

`values.cluster.yaml` anpassen:

```yaml
encryption:
  activeKekId: kek-2026-01
```

Upgrade ausführen:

```bash
helm upgrade --install glass ./charts/glass -n glass -f values.cluster.yaml
kubectl -n glass rollout status deploy/glass-glass
```

Ab jetzt sind **neue Writes** automatisch mit `kek-2026-01` gewrappt.

### Schritt C: Rewrap der alten Records (CLI)

Wichtig:

* Dein Runtime-Image ist distroless, das Binary liegt im Container unter **`/glass`**.
* Wenn du `glass` im PATH willst, baue das Image so, dass es nach `/usr/local/bin/glass` kopiert wird.

**Dry-run (nur zählen):**

```bash
kubectl -n glass exec -it deploy/glass-glass -- \
  /glass rewrap-kek --db /data/glass.db --kek-dir /mnt/keks --from default --to kek-2026-01 --dry-run
```

**Rewrap durchführen:**

```bash
kubectl -n glass exec -it deploy/glass-glass -- \
  /glass rewrap-kek --db /data/glass.db --kek-dir /mnt/keks --from default --to kek-2026-01
```

> Wenn du hier wieder “executable not found” siehst oder der Pod versucht Port 8080 zu binden:
>
> * Stelle sicher, dass du ein Image mit aktueller CLI laufen hast **und**
> * dass du nicht denselben Tag wiederverwendet hast (oder `image.pullPolicy: Always` gesetzt ist).
>
> Der sichere Weg ist: **Tag bumpen** (z.B. `0.1.1`, `0.1.2`).

### Schritt D: Alten KEK entfernen (erst wenn wirklich fertig)

1. Dry-run muss **0** melden:

```bash
kubectl -n glass exec -it deploy/glass-glass -- \
  /glass rewrap-kek --db /data/glass.db --kek-dir /mnt/keks --from default --to kek-2026-01 --dry-run
```

2. Dann entferne `default` aus dem Secret (Beispiel: Secret neu erzeugen oder patchen).

> Wichtig: Entferne den alten KEK erst, wenn wirklich alle Records umgestellt sind – sonst kann `glass` alte Secrets nicht mehr entschlüsseln.

---

## ESO Integration (Webhook Provider)

Offizielle Doku:

* Webhook Provider: [https://external-secrets.io/latest/provider/webhook/](https://external-secrets.io/latest/provider/webhook/)
* All keys to one Secret: [https://external-secrets.io/latest/guides/all-keys-one-secret/](https://external-secrets.io/latest/guides/all-keys-one-secret/)

### 1) Webhook Credentials Secret (Bearer Token für glass)

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: glass-webhook-credentials
  namespace: glass
  labels:
    external-secrets.io/type: webhook
stringData:
  token: secret-token
```

### 2) SecretStore (Webhook Provider)

`glass` liefert beim Bulk-Endpoint `{"data":{...}}` → `result.jsonPath: "$.data"`.

```yaml
apiVersion: external-secrets.io/v1
kind: SecretStore
metadata:
  name: glass-webhook
  namespace: glass
spec:
  provider:
    webhook:
      url: "http://glass-glass.glass.svc.cluster.local:8080/v1/secrets?prefix={{ .remoteRef.key }}&format=map&keys=relative"
      method: GET
      result:
        jsonPath: "$.data"
      headers:
        Authorization: "Bearer {{ .auth.token }}"
      secrets:
        - name: auth
          secretRef:
            name: glass-webhook-credentials
```

### 3) ExternalSecret (dataFrom.extract)

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata:
  name: team-a-secrets
  namespace: glass
spec:
  refreshInterval: 1m
  secretStoreRef:
    name: glass-webhook
    kind: SecretStore
  target:
    name: team-a-secrets
    creationPolicy: Owner
  dataFrom:
    - extract:
        key: "team-a/"
```

---

## Troubleshooting

* **401 Unauthorized**: Token stimmt nicht / falsches Chart-Values (`auth.tokenFileContent`).
* **403 Forbidden**: Policy passt nicht (Subject mismatch oder fehlende Permission).
* **Encryption errors**: `ACTIVE_KEK_ID` existiert nicht im `KEK_DIR`, oder alter KEK wurde zu früh entfernt.
* **DB nicht persistent**: Pod hat `data: EmptyDir` → `storage.persistence.enabled=true` setzen.
* **CLI startet Server (bind 8080)**: Du hast ein Image ohne Subcommand-Dispatcher oder ein altes Image-Digest (Tag wiederverwendet, PullPolicy IfNotPresent).

---

## Security Notes

* SQLite + PVC: standardmäßig **1 Replica**.
* KEKs sind hochsensitiv: RBAC und Secret-Access strikt halten.
* Bearer-Token ist MVP-freundlich; langfristig ist K8s-native Auth (ServiceAccount/TokenReview/OIDC) sinnvoll.

```
::contentReference[oaicite:0]{index=0}
```

