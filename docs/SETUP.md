# Setup guide

End-to-end instructions for taking this repo from `git clone` to a
running Threat Intelligence Platform on a single host. Tested on
Ubuntu 22.04/24.04. Should also work on any Linux that runs Docker;
macOS works with Docker Desktop.

If you skip the build-time gotcha in step 4, the dashboard will load
but every API call will silently fail with *"Could not connect to the
API server"*. Read step 4 carefully.

---

## 0 — Prerequisites

| Tool | Version | Why |
|---|---|---|
| Docker | 24+ | Image build runtime |
| k3d | 5.6+ | k3s-in-Docker — provides the Kubernetes cluster |
| kubectl | 1.28+ | Cluster access |
| Helm | 3.13+ | Chart deployment |
| Python | 3.11+ | Generating secrets locally |
| `node` / `npm` | 20.x | Only if you want to run the frontend outside Docker |

Verify:

```bash
docker --version   # 24+
k3d   version      # 5.6+
kubectl version --client --short 2>/dev/null
helm  version --short
python3 --version  # 3.11+
```

---

## 1 — Clone and configure environment

```bash
git clone https://github.com/IbrahimGhazi/Threatintel.git
cd Threatintel
cp .env.example .env
```

Open `.env` and fill in **every** value. Generate the random ones with
the snippets in the file's comments. The four critical ones:

```bash
# secrets to generate
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_hex(32))"
python3 -c "import secrets; print('API_KEY=' + secrets.token_urlsafe(16))"
python3 -c "from cryptography.fernet import Fernet; print('MASTER_ENCRYPTION_KEY=' + Fernet.generate_key().decode())"
```

> **Important — keep these in sync:**
> - `API_KEY` and `NEXT_PUBLIC_API_KEY` **must be identical**. The
>   frontend bundle sends `NEXT_PUBLIC_API_KEY` as the `X-API-Key`
>   header; the API validates it against `API_KEY`. Mismatch = every
>   request returns 401.
> - `NEXT_PUBLIC_API_KEY` is **build-time only**. Setting it on the
>   running pod has no effect on the JS bundle. See step 4.
> - Without `MASTER_ENCRYPTION_KEY`, the BYO API-keys feature
>   (`/settings/api-keys`) refuses to store credentials and shows an
>   "encryption disabled" banner.

---

## 2 — Provision the k3d cluster

```bash
k3d cluster create ti-k8s \
  --servers 1 --agents 0 \
  --port "80:80@loadbalancer" \
  --port "443:443@loadbalancer" \
  --k3s-arg "--disable=traefik@server:0"   # we use NGINX from the chart instead
```

Verify:

```bash
kubectl get nodes
# NAME                  STATUS   ROLES                  AGE   VERSION
# k3d-ti-k8s-server-0   Ready    control-plane,master   30s   v1.30.x+k3s1
```

---

## 3 — Pull Helm chart dependencies

The chart vendors its sub-charts (PostgreSQL, Redis, NATS,
kube-prometheus-stack, MinIO) as `*.tgz` files inside `charts/`. Those
are gitignored — fetch them now:

```bash
helm dependency update deploy/k8s/charts/ti-platform
```

You should see five `Saving X charts to the local repository cache`
lines and a refreshed `Chart.lock`.

---

## 4 — Build the platform images (READ THIS — frontend gotcha lives here)

The Helm chart references images by tag, with `imagePullPolicy:
IfNotPresent`. They must exist in the cluster's containerd before the
chart is installed.

### 4a. Backend services (one image per service)

Backend services read every secret at runtime, so build args don't
matter:

```bash
for svc in api ingestion sandbox correlation enrichment icap logserver learner; do
  docker build --provenance=false -t ti-platform/$svc:1.0.0 services/$svc
done
```

### 4b. Frontend — build-arg ceremony required

Next.js inlines any environment variable prefixed with `NEXT_PUBLIC_`
into the static JavaScript bundle **at build time**. If you don't pass
`NEXT_PUBLIC_API_KEY` as a `--build-arg`, it bakes in as an empty
string. The pod's runtime env is irrelevant — the browser will send
`X-API-Key: ` (empty) and every API call returns 401, surfacing as
*"Could not connect to the API server"* on the dashboard.

```bash
# Read API_KEY from your .env so it stays in sync
API_KEY=$(grep '^API_KEY=' .env | cut -d= -f2-)

docker build \
  --provenance=false \
  --build-arg NEXT_PUBLIC_API_URL=/api \
  --build-arg NEXT_PUBLIC_API_KEY="$API_KEY" \
  -t ti-platform/frontend:1.0.0 \
  frontend/
```

To verify the build is correct (do this every time you rebuild the
frontend):

```bash
docker run --rm --entrypoint sh ti-platform/frontend:1.0.0 -c \
  'grep -ohE "X-API-Key\":\"[^\"]+" /app/.next/static/chunks/app/settings/api-keys/page-*.js | head -1'
# Expected: X-API-Key":"<your real API_KEY>"
# WRONG:    X-API-Key":""              ← rebuild with --build-arg
```

### 4c. Import images into the k3d cluster

```bash
for img in api ingestion sandbox correlation enrichment icap logserver learner frontend; do
  k3d image import "ti-platform/$img:1.0.0" -c ti-k8s
done
```

This is the equivalent of `docker push` for k3d. Without it, pods
stay in `ErrImagePull` / `ImagePullBackOff` because Docker images are
not visible to the cluster's containerd by default.

---

## 5 — Create the platform Secret

The chart reads every credential from one Kubernetes Secret. Create it
from your `.env`:

```bash
kubectl create namespace ti

# Creates a Secret named ti-platform-secrets with one key per .env line
kubectl -n ti create secret generic ti-platform-secrets \
  --from-env-file=.env
```

(Or use ExternalSecrets / Sealed Secrets / Vault Agent in production —
see `deploy/k8s/charts/ti-platform/values-prod.yaml`.)

---

## 6 — Install the chart

Dev/single-node install:

```bash
helm install ti deploy/k8s/charts/ti-platform \
  --namespace ti \
  -f deploy/k8s/charts/ti-platform/values-dev.yaml \
  --set secrets.existingSecret=ti-platform-secrets
```

Production install (HA, external DB, ExternalSecrets):

```bash
helm install ti deploy/k8s/charts/ti-platform \
  --namespace ti \
  -f deploy/k8s/charts/ti-platform/values-prod.yaml
```

Wait for everything to settle:

```bash
kubectl -n ti rollout status deploy/ti-api      --timeout=300s
kubectl -n ti rollout status deploy/ti-frontend --timeout=300s
kubectl -n ti get pods
```

---

## 7 — Database initialisation

The PostgreSQL sub-chart loads any SQL dropped into
`/docker-entrypoint-initdb.d` on first boot. The Helm chart wires
`infra/postgres/init/*.sql` in via a ConfigMap — no manual import
required for a fresh install.

If you upgraded an existing cluster and need to apply a new migration
(e.g. `14_api_keys_settings.sql` for the BYO API keys feature),
`kubectl cp` it into the running pod and run it manually:

```bash
kubectl -n ti cp infra/postgres/init/14_api_keys_settings.sql \
  ti-postgresql-0:/tmp/14.sql

kubectl -n ti exec ti-postgresql-0 -- env PGPASSWORD="$POSTGRES_PASSWORD" \
  psql -U tiplatform -d tiplatform -f /tmp/14.sql
```

---

## 8 — Access the platform

The chart's `ingress.yaml` configures a hostname-based ingress. For
single-node development without DNS, the simplest path is a
`kubectl port-forward` driven by a systemd template unit so it
auto-restarts when pods roll.

### 8a. Quick (manual) port-forward

```bash
kubectl -n ti port-forward --address 0.0.0.0 svc/ti-frontend 3000:3000 &
kubectl -n ti port-forward --address 0.0.0.0 svc/ti-api      8000:8000 &
# open http://<this-host>:3000
```

### 8b. Persistent port-forward (recommended)

Drop this in `/etc/systemd/system/ti-portforward@.service` and let
systemd manage it. The `@` makes it a template — instantiate one unit
per service.

```ini
[Unit]
Description=kubectl port-forward for TI platform %i
After=network-online.target

[Service]
Type=simple
User=tiuser
ExecStart=/usr/local/bin/kubectl -n ti port-forward --address 0.0.0.0 svc/%i
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
```

Activate two instances (the `%i` becomes the part after `@`):

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ti-portforward@ti-api:8000:8000.service
sudo systemctl enable --now ti-portforward@ti-frontend:3000:3000.service
```

Restart-on-rollout is automatic because `Restart=always` re-execs
`kubectl port-forward`, which transparently re-attaches to the new
pod.

---

## 9 — Smoke test

```bash
# Frontend serves
curl -sk -o /dev/null -w "frontend=%{http_code}\n" http://localhost:3000/

# API reachable through the Next.js proxy with the baked-in key
curl -s -H "X-API-Key: $(grep '^API_KEY=' .env | cut -d= -f2-)" \
  http://localhost:3000/api/stats/dashboard | python3 -m json.tool | head -10

# BYO API keys feature is online and encryption is enabled
curl -s -H "X-API-Key: $(grep '^API_KEY=' .env | cut -d= -f2-)" \
  http://localhost:3000/api/system/api-keys/_diag/encryption
# Expected: {"available":true}
```

If `_diag/encryption` returns `{"available":false}`, you forgot to set
`MASTER_ENCRYPTION_KEY`. Add it to the secret and restart `ti-api`:

```bash
kubectl -n ti patch secret ti-platform-secrets --type=json \
  -p="[{\"op\":\"add\",\"path\":\"/data/MASTER_ENCRYPTION_KEY\",\"value\":\"$(python3 -c 'from cryptography.fernet import Fernet; import base64; print(base64.b64encode(Fernet.generate_key()).decode())')\"}]"
kubectl -n ti rollout restart deploy/ti-api
```

---

## 10 — Common pitfalls

These are the issues that have actually bitten us in production. Each
points back to the step that prevents it:

| Symptom | Root cause | Fix |
|---|---|---|
| Dashboard shows *"Could not connect to the API server"* despite the API being healthy. | Frontend image was built without `--build-arg NEXT_PUBLIC_API_KEY`; bundle has empty string baked in. | Step 4b. Verify with the `grep X-API-Key` snippet. |
| Pods stuck in `ErrImagePull` after `helm install`. | Built images live in Docker; the cluster's containerd can't see them. | Step 4c — `k3d image import`. |
| `/settings/api-keys` page shows *"Encryption disabled — keys cannot be stored."* | `MASTER_ENCRYPTION_KEY` missing from `ti-platform-secrets`. | Step 1 + step 9 patch snippet. |
| Every API call returns 401. | `API_KEY` ≠ `NEXT_PUBLIC_API_KEY`. | Step 1 — they must be identical. |
| Browser still shows the old behaviour after a frontend rebuild. | `imagePullPolicy: IfNotPresent` — the cluster keeps using the cached image. | Bump the image tag (e.g. `1.0.0` → `1.0.1`) before `kubectl set image`, or run `kubectl rollout restart deploy/ti-frontend` after re-importing the same tag. |
| Port-forward dies after every deploy. | `kubectl port-forward` is bound to a single pod; rollouts terminate it. | Step 8b — use the systemd template unit; `Restart=always` handles it. |
| `make up` doesn't work. | `docker-compose.yml` is not committed; this repo uses Helm/k3d. | Use the steps above. The Makefile is legacy. |
| GeoIP enrichment quietly skipped. | `MAXMIND_LICENSE_KEY` is empty. | Register at maxmind.com (free), add to `.env`, restart `ti-enrichment`. |
| Firewall syslog ingestion creates "unknown source" alerts about your own gateway. | `KNOWN_DEVICE_IPS` is empty. | Add the firewall's IP/CIDR to `.env` and restart `ti-correlation`. |

---

## 11 — Operating

### Roll a new image

```bash
# Build → import → set image (bump the tag every time!)
docker build --provenance=false -t ti-platform/api:1.0.1 services/api
k3d   image import ti-platform/api:1.0.1 -c ti-k8s
kubectl -n ti set image deploy/ti-api ti-api=ti-platform/api:1.0.1
kubectl -n ti rollout status deploy/ti-api
```

For the frontend, repeat the **build-arg ceremony** (step 4b).

### Roll back

```bash
kubectl -n ti rollout undo deploy/ti-api
```

### Tail logs

```bash
kubectl -n ti logs -f deploy/ti-api
kubectl -n ti logs -f deploy/ti-ingestion
kubectl -n ti logs -f deploy/ti-correlation
```

### Open a psql shell

```bash
kubectl -n ti exec -it ti-postgresql-0 -- env PGPASSWORD="$POSTGRES_PASSWORD" \
  psql -U tiplatform -d tiplatform
```

---

## 12 — Where to go next

- Architecture docs and ADRs: `obsidian-vault/`
  (open the folder in [Obsidian](https://obsidian.md/) for the linked
  experience).
- Operational runbooks: `obsidian-vault/runbooks/` — flip detection
  modes, retrain embeddings, redeploy correlation, recover from the
  VM, etc.
- Roadmap: `obsidian-vault/milestones/M4-roadmap.md`.
