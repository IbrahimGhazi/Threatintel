# Redeploy Correlation Service #runbook

Most-touched service — every M1/M2/M3 change rolls through here. Follow [[runbooks/deploy-pattern]] but with these specifics.

## Files that trigger a rebuild

- `services/correlation/main.py` — pipeline + loops
- `services/correlation/reputation.py` — scorer
- `services/correlation/rules/*.py` — rule logic
- `services/correlation/Dockerfile` — base image / Tranco fetch
- `services/correlation/requirements.txt`

## Standard flow

```sh
# 1. sftp the changed files into /home/tiuser/ti-platform/services/correlation/
# 2. py_compile sanity check
python3 -m py_compile services/correlation/main.py services/correlation/reputation.py

# 3. Build, save, import
NEW_TAG="ti-platform/correlation:X.Y.Z"
cd /home/tiuser/ti-platform/services/correlation
docker build --provenance=false -t "$NEW_TAG" .
docker save -o /tmp/correlation-X.Y.Z.tar "$NEW_TAG"
k3d image import /tmp/correlation-X.Y.Z.tar -c ti-k8s

# 4. Roll
kubectl -n ti set image deploy/ti-correlation correlation="$NEW_TAG"
kubectl -n ti rollout status deploy/ti-correlation --timeout=180s
```

## Post-roll checklist

After `--timeout=180s` succeeds, give it 25s to settle, then:

```sh
# image pinned correctly?
kubectl -n ti get deploy ti-correlation -o jsonpath='{.spec.template.spec.containers[0].image}'

# startup markers (use --since= to defeat log rotation)
kubectl -n ti logs deploy/ti-correlation --since=10m | \
  grep -iE "ReputationScorer|Reputation detection|Correlation service|embeddings refreshed|ERROR|CRITICAL|Traceback"

# expected lines:
#   ReputationScorer loaded: tranco=100000 ...
#   ReputationScorer ready (tranco=100000, recent_domains=N)
#   Reputation detection mode=enforce (thresholds=6 floors=6)
#   ReputationScorer embeddings refreshed: hosts=N destinations=M far=0.30 near=0.85   ← M3 marker
```

## Performance smoke test (3-min window)

```sql
SELECT rule_name, COUNT(*) FILTER (WHERE would_fire) AS would_fire, COUNT(*) AS total
FROM reputation_shadow_events
WHERE created_at > NOW() - INTERVAL '3 minutes'
GROUP BY rule_name ORDER BY total DESC;
```

Expect dns_tunneling, service_scan, host_discovery to dominate; `would_fire=0` on a healthy bank network.

## Rollback

```sh
kubectl -n ti rollout undo deploy/ti-correlation
```
