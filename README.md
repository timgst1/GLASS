# glass – Quickstart & Cluster-Bedienung

`glass` ist ein schlanker Secretstore für Kubernetes: Secrets werden per HTTP API geschrieben/gelesen und können z.B. via External Secrets Operator (ESO) in Kubernetes Secrets synchronisiert werden. Persistenz läuft über SQLite (PVC). Secrets werden im Storage per Envelope Encryption verschlüsselt (DEK pro Version, KEK aus K8s Secret mount).

---

## Voraussetzungen

- Kubernetes Cluster (inkl. StorageClass für PVC)
- Helm v3
- `kubectl`
- Optional: External Secrets Operator (ESO), wenn du Sync in K8s Secrets willst

---

## Architektur in 30 Sekunden

- **Storage**: SQLite DB auf PVC
- **API**:
  - `PUT /v1/secret` (write)
  - `GET /v1/secret?key=...` (read)
  - `GET /v1/secret/meta?key=...` (meta)
  - `GET /v1/secrets?prefix=...` (bulk/list, ESO-friendly)
- **AuthN**: Bearer Token aus Datei (K8s Secret mount)
- **AuthZ**: Policy-Datei (YAML) aus ConfigMap mount
- **Encryption at Rest**: Envelope (AES-256-GCM), KEKs aus Directory (K8s Secret mount)

---

## Quickstart: Cluster Deployment (Helm)

### 1) Namespace

```bash
kubectl create namespace glass
```

### 2) KEK Secret erstellen (Encryption)

`glass` nutzt **Envelope Encryption**: pro Secret-Version wird ein DEK erzeugt und mit einem KEK “gewrappt”.
Der KEK kommt aus einem K8s Secret, das als Directory gemountet wird.

Der Datei-Name ist die `kek_id` (z.B. `default`). Der Inhalt muss **base64 von 32 bytes** (oder 32 raw bytes) sein.

```bash
KEK_B64="$(head -c 32 /dev/urandom | base64 | tr -d '
')"

kubectl -n glass create secret generic glass-kek   --from-literal=default="${KEK_B64}"
```

### 3) values-Datei anlegen (Auth/Policy/SQLite + Encryption)

Das Chart erstellt **automatisch**:
- ein Secret `{{ release }}-glass-auth` (Token-Datei) und
- eine ConfigMap `{{ release }}-glass-policy` (Policy-Datei).

Am angenehmsten ist deshalb eine eigene Values-Datei:

```bash
cat <<'YAML' > values.cluster.yaml
image:
  # Wichtig: Repository muss lowercase sein
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

# Encryption at rest (Envelope)
encryption:
  mode: envelope        # none|envelope
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
kubectl -n glass logs deploy/glass-glass -f
```

### 6) API testen (port-forward)

```bash
kubectl -n glass port-forward svc/glass-glass 8080:8080
```

Write:

```bash
curl -sS -X PUT "http://127.0.0.1:8080/v1/secret"   -H "Authorization: Bearer secret-token"   -H "Content-Type: application/json"   -d '{"key":"team-a/db","value":"dbpass"}'
```

Read:

```bash
curl -sS "http://127.0.0.1:8080/v1/secret?key=team-a/db"   -H "Authorization: Bearer secret-token"
```

Meta:

```bash
curl -sS "http://127.0.0.1:8080/v1/secret/meta?key=team-a/db"   -H "Authorization: Bearer secret-token"
```

Bulk/List (ESO-friendly Map; default `keys=relative`, `format=map`):

```bash
curl -sS "http://127.0.0.1:8080/v1/secrets?prefix=team-a/"   -H "Authorization: Bearer secret-token"
```

Antwort-Beispiel:

```json
{"data":{"db":"dbpass"}}
```
## Konfiguration (Helm Values)

Das Helm-Chart setzt die wichtigsten Einstellungen als ENV Vars im Pod. Relevant sind vor allem:

### Auth

```yaml
auth:
  mode: bearer
  tokenFileContent: |
    webhook=secret-token
```

### Policy

```yaml
policy:
  content: |
    # ...deine Policy...
```

### Storage (SQLite)

```yaml
storage:
  backend: sqlite
  sqlitePath: /data/glass.db
  persistence:
    enabled: true
    size: 1Gi
    # storageClassName: "YOUR_STORAGECLASS"
```

### Encryption at Rest (Envelope)

```yaml
encryption:
  mode: envelope        # none|envelope
  kekDir: /mnt/keks
  activeKekId: default
  kekSecretName: glass-kek
```

> Intern werden daraus u.a. diese ENV Vars gesetzt: `AUTH_MODE`, `AUTH_TOKEN_FILE`, `POLICY_FILE`, `STORAGE_BACKEND`, `SQLITE_PATH`, sowie (bei Encryption) `ENCRYPTION_MODE`, `KEK_DIR`, `ACTIVE_KEK_ID`.

---


## Encryption at Rest (Envelope) – Betrieb & Rotation

### Voraussetzung: Helm-Chart muss Encryption verdrahten

Dein Chart verdrahtet standardmäßig nur `AUTH_*`, `POLICY_FILE`, `STORAGE_BACKEND`, `SQLITE_PATH`.
Für Envelope Encryption müssen zusätzlich **Env Vars** und ein **Secret-Mount** für die KEKs gesetzt werden.

Wenn dein Chart diese `encryption.*` Values noch nicht nutzt, ergänze einmalig:

#### Datei: `charts/glass/values.yaml`

```yaml
encryption:
  mode: none            # none|envelope
  kekDir: /mnt/keks
  activeKekId: default
  kekSecretName: glass-kek
```

#### Datei: `charts/glass/templates/deployment.yaml`

Unter `env:` ergänzen:

```yaml
            - name: ENCRYPTION_MODE
              value: {{ .Values.encryption.mode | quote }}
            - name: KEK_DIR
              value: {{ .Values.encryption.kekDir | quote }}
            - name: ACTIVE_KEK_ID
              value: {{ .Values.encryption.activeKekId | quote }}
```

Unter `volumeMounts:` ergänzen:

```yaml
            - name: keks
              mountPath: {{ .Values.encryption.kekDir | quote }}
              readOnly: true
```

Und unter `volumes:` ergänzen:

```yaml
          - name: keks
            secret:
              secretName: {{ .Values.encryption.kekSecretName | quote }}
```

> Danach `helm upgrade` ausführen (siehe Quickstart) und im Pod prüfen, dass `/mnt/keks/default` existiert.

### Wie es funktioniert (kurz)
- Pro Secret-Version wird ein **DEK** (Data Encryption Key) erzeugt.
- Der Secret-Value wird mit DEK (AES-GCM) verschlüsselt.
- Der DEK wird mit einem **KEK** (Key Encryption Key) “gewrappt”.
- In der DB liegen **Ciphertext + Nonces + wrapped DEK + kek_id**, keine Klartexte.

### KEK Rotation: Vorgehen

Ziel: neue Writes mit neuem KEK, alte Records nachziehen (rewrap), dann alten KEK entfernen.

#### Schritt A: neuen KEK hinzufügen (Secret erweitern)
Neuen Key generieren und als weitere Datei im gleichen Secret ablegen:

```bash
NEW2_KEK_B64="$(head -c 32 /dev/urandom | base64 | tr -d '
')"

kubectl -n glass patch secret glass-kek   --type merge   -p "{\"stringData\":{\"kek-2026-01\":\"${NEW2_KEK_B64}\"}}"
```

Damit existieren im Pod dann z.B.:
- `/mnt/keks/default`
- `/mnt/keks/kek-2026-01`

#### Schritt B: ACTIVE_KEK_ID umstellen + rollout

Passe in deiner `values.cluster.yaml` den aktiven Key an:

```yaml
encryption:
  activeKekId: kek-2026-01
```

Dann rolle das Release aus:

```bash
helm upgrade --install glass ./charts/glass -n glass -f values.cluster.yaml
```

Ab jetzt sind **neue Writes** automatisch mit `kek-2026-01` gewrappt.

#### Schritt C: Rewrap der alten Records (CLI)

Es gibt einen CLI-Subcommand:

```bash
glass rewrap-kek --db /data/glass.db --kek-dir /mnt/keks --from default --to kek-2026-01 --dry-run
glass rewrap-kek --db /data/glass.db --kek-dir /mnt/keks --from default --to kek-2026-01
```

##### Option 1: direkt im laufenden Pod (am einfachsten)

```bash
kubectl -n glass exec -it deploy/glass-glass --   glass rewrap-kek --db /data/glass.db --kek-dir /mnt/keks --from default --to kek-2026-01 --dry-run

kubectl -n glass exec -it deploy/glass-glass --   glass rewrap-kek --db /data/glass.db --kek-dir /mnt/keks --from default --to kek-2026-01
```

##### Option 2: Kubernetes Job (sauber/automatisierbar)

> Passe `image:` und Volume-Referenzen (PVC-Name etc.) an deinen Cluster/Chart an.

```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: glass-rewrap-kek
  namespace: glass
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: rewrap
          image: ghcr.io/<org>/glass:<tag>
          command:
            - glass
            - rewrap-kek
            - --db
            - /data/glass.db
            - --kek-dir
            - /mnt/keks
            - --from
            - default
            - --to
            - kek-2026-01
          volumeMounts:
            - name: data
              mountPath: /data
            - name: keks
              mountPath: /mnt/keks
              readOnly: true
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: <DEIN_PVC_NAME>
        - name: keks
          secret:
            secretName: glass-kek
```

#### Schritt D: alten KEK entfernen (erst nach Rewrap!)
Wenn `rewrap-kek` durch ist und `--dry-run` danach **0** meldet, kannst du `default` aus dem K8s Secret entfernen.

> Wichtig: Entferne den alten KEK erst, wenn wirklich alle Records umgestellt sind – sonst kann `glass` alte Secrets nicht mehr entschlüsseln.
## ESO Integration (Webhook Provider)

Offizielle Doku:
- Webhook Provider: https://external-secrets.io/latest/provider/webhook/
- All keys to one Secret: https://external-secrets.io/latest/guides/all-keys-one-secret/

### 1) Webhook Credentials Secret (Bearer Token für glass)

ESO Webhook Provider kann Secrets in Templates verwenden. Dafür braucht das Secret das Label:
`external-secrets.io/type: webhook`.

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

`glass` liefert beim Bulk-Endpoint `{"data":{...}}`.
Wir setzen `result.jsonPath: "$.data"`.

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

Hier ist `remoteRef.key` einfach der Prefix, z.B. `team-a/`.
Das erzeugt ein K8s Secret mit Keys wie `db`, `api`, etc. (ohne `/`).

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

> Wenn du Keys serverseitig flattest (`/` → `_`), sind sie automatisch K8s-Secret-key kompatibel.

---

## Troubleshooting

- **403**: Policy passt nicht (Subject mismatch oder fehlende Permission).
- **404**: Key existiert nicht (oder Key/Prefix falsch).
- **Encryption errors**: `ACTIVE_KEK_ID` existiert nicht im `KEK_DIR`, oder alter KEK wurde zu früh entfernt.
- **ESO sync klappt nicht**: Service-URL/DNS prüfen, `result.jsonPath` auf `$.data` setzen, Token-Header korrekt?

---

## Security Notes (ehrlich & praktisch)

- SQLite + PVC bedeutet: standardmäßig **1 Replica** (sonst brauchst du RWX oder externes DB-Konzept).
- KEKs sind hochsensitiv: RBAC und Secret-Access strikt halten.
- Bearer-Token ist MVP-freundlich; langfristig ist K8s-native Auth (ServiceAccount/TokenReview/OIDC) der bessere Weg.
