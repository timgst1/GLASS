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

