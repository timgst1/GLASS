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

### 2) Bearer-Token Secret erstellen (Auth)

Token-Datei: eine Zeile pro gültigem Token.

```bash
kubectl -n glass create secret generic glass-auth-token \
  --from-literal=token="secret-token"
```

> Das Secret wird später als Datei gemountet, z.B. `/mnt/auth/token`.

### 3) KEK Secret erstellen (Encryption)

`glass` erwartet pro KEK eine Datei `<kek_id>` im `KEK_DIR`.
Inhalt: entweder **32 raw bytes** oder **base64 von 32 bytes**.

Empfohlen: base64-Text (einfacher via `--from-literal`):

```bash
NEW_KEK_B64="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"

kubectl -n glass create secret generic glass-kek \
  --from-literal=default="${NEW_KEK_B64}"
```

> `default` ist hier die `kek_id`. Der aktive KEK ist später `ACTIVE_KEK_ID=default`.

### 4) Policy ConfigMap erstellen (AuthZ)

Beispiel-Policy: erlaubt Lesen/Schreiben/Listen für `team-a/` (angepasst an deinen Subject).

> Wichtig: Policies müssen zu deinem Subject passen (z.B. `kind=bearer`, `name=webhook`).

```bash
cat <<'YAML' | kubectl -n glass apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: glass-policy
data:
  policy.yaml: |
    apiVersion: glass/v1
    kind: Policy
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
      - subject:
          kind: bearer
          name: webhook
        role: team-a-rw
YAML
```

### 5) Helm Install / Upgrade

Da ich deinen Chart-Pfad/Values nicht “raten” will: nutze im Repo einmal:

```bash
helm show values ./charts/glass > values-default.yaml
```

Dann installierst du mit den Kern-Parametern. Beispiel (Pfad ggf. anpassen):

```bash
helm upgrade --install glass ./charts/glass -n glass \
  --set env.AUTH_MODE="bearer" \
  --set env.AUTH_TOKEN_FILE="/mnt/auth/token" \
  --set env.POLICY_FILE="/etc/glass/policy.yaml" \
  --set env.STORAGE_BACKEND="sqlite" \
  --set env.SQLITE_PATH="/data/glass.db" \
  --set env.ENCRYPTION_MODE="envelope" \
  --set env.KEK_DIR="/mnt/keks" \
  --set env.ACTIVE_KEK_ID="default"
```

Und du brauchst die passenden Volumes/Mounts:
- PVC → `/data`
- Secret `glass-auth-token` → `/mnt/auth/token`
- Secret `glass-kek` → `/mnt/keks/default`
- ConfigMap `glass-policy` → `/etc/glass/policy.yaml`

Falls dein Chart das nicht direkt anbietet: `values.yaml` entsprechend erweitern (extraVolumes/extraVolumeMounts o.ä.).

### 6) Status prüfen

```bash
kubectl -n glass get pods
kubectl -n glass logs deploy/glass -f
kubectl -n glass get svc
```

### 7) API testen (port-forward)

```bash
kubectl -n glass port-forward svc/glass 8080:8080
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

Meta:

```bash
curl -sS "http://127.0.0.1:8080/v1/secret/meta?key=team-a/db" \
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

## Konfiguration (wichtigste ENV Vars)

- `AUTH_MODE`: `bearer` | `noop`
- `AUTH_TOKEN_FILE`: Pfad zur Token-Datei (bei `bearer`)
- `POLICY_FILE`: Pfad zur Policy YAML
- `STORAGE_BACKEND`: `sqlite` | `memory`
- `SQLITE_PATH`: z.B. `/data/glass.db`

Encryption:
- `ENCRYPTION_MODE`: `envelope` (empfohlen) | `none`
- `KEK_DIR`: Directory mit KEK-Dateien (K8s Secret mount)
- `ACTIVE_KEK_ID`: Dateiname des aktiven KEKs (z.B. `default`)

---

## Encryption at Rest (Envelope) – Betrieb & Rotation

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
NEW2_KEK_B64="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"

kubectl -n glass patch secret glass-kek \
  --type merge \
  -p "{\"stringData\":{\"kek-2026-01\":\"${NEW2_KEK_B64}\"}}"
```

Damit existieren im Pod dann z.B.:
- `/mnt/keks/default`
- `/mnt/keks/kek-2026-01`

#### Schritt B: ACTIVE_KEK_ID umstellen + rollout
Setze in Helm Values:
- `ACTIVE_KEK_ID=kek-2026-01`

und rolle aus:

```bash
helm upgrade --install glass ./charts/glass -n glass \
  --set env.ACTIVE_KEK_ID="kek-2026-01"
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
kubectl -n glass exec -it deploy/glass -- \
  glass rewrap-kek --db /data/glass.db --kek-dir /mnt/keks --from default --to kek-2026-01 --dry-run
```

##### Option 2: Kubernetes Job (sauber/automatisierbar)

> Passe `image:` und Volume-Referenzen (PVC-Name etc.) an deinen Chart an.

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
Wenn `rewrap-kek` durch ist und alles ok: entferne `default` aus dem K8s Secret.

---

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
      url: "http://glass.glass.svc.cluster.local:8080/v1/secrets?prefix={{ .remoteRef.key }}&format=map&keys=relative"
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
