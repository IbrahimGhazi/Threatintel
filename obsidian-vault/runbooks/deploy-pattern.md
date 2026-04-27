# Deploy Pattern (k3d image import) #runbook

**The k3d-specific dance** — buildx attestation manifests corrupt direct k3d import. Always use `--provenance=false` and the tar→import pipeline.

## On the server VM (192.168.3.210)

```sh
cd /home/tiuser/ti-platform/services/<svc>

# 1. Build (NO buildx attestation)
docker build --provenance=false -t ti-platform/<svc>:<tag> .

# 2. Save → import
docker save -o /tmp/<svc>-<tag>.tar ti-platform/<svc>:<tag>
k3d image import /tmp/<svc>-<tag>.tar -c ti-k8s

# 3. Roll
kubectl -n ti set image deploy/ti-<svc> <svc>=ti-platform/<svc>:<tag>
kubectl -n ti rollout status deploy/ti-<svc> --timeout=180s
```

## From local Windows (orchestrated)

Use [[runbooks/connect-server-vm]]'s paramiko wrapper. Always `python -u` so stdout isn't block-buffered when running in background.

## Tag bumping

Bump tags rather than mutating `:latest` — k8s pulls only on tag change. Convention:

| Service | Current tag |
|---|---|
| `correlation` | `1.3.0` |
| `learner` | `1.0.0` |
| (add others as bumped) | |

## Post-rollout verification

```sh
# Confirm the new image is actually live
kubectl -n ti get deploy ti-<svc> -o jsonpath='{.spec.template.spec.containers[0].image}'

# Tail for errors
kubectl -n ti logs deploy/ti-<svc> --tail=200 | grep -E "ERROR|CRITICAL|Traceback"
```

## Common failure modes

- ❌ Used buildx without `--provenance=false` → import "succeeds" but k8s ImagePullBackOffs
- ❌ Forgot to `set image` after import → pod still running old image
- ❌ Hit `Error: secret "ti-platform-secret" not found` → the actual secret is **`ti-secrets`**, see [[architecture/services]] and [[00-index]]
