"""
System resource metrics — host-level and per-pod stats.

Host metrics are read from /proc inside this pod (the kernel surfaces the
node view for unprivileged containers — good enough for the dashboard).

Pod metrics come from the Kubernetes API:
  - /api/v1/namespaces/{ns}/pods                  → inventory & phase
  - /apis/metrics.k8s.io/v1beta1/namespaces/{ns}/pods → metrics-server usage

The ServiceAccount this pod runs under needs the RBAC defined in
chart template `templates/rbac-api.yaml` (get/list on pods and
pods.metrics.k8s.io in the release namespace).
"""

import asyncio
import os
import re
import time
import logging
from typing import Any, Dict, List, Optional, Tuple

import httpx
from fastapi import APIRouter, Depends

from app.middleware.auth import require_api_key

router = APIRouter(prefix="/system", tags=["System"])
log = logging.getLogger("ti.metrics")

_CACHE: Dict[str, Any] = {}
_CACHE_TTL = 5  # seconds

# Persistent state for host CPU delta calculation.
_prev_cpu_times: Optional[List[int]] = None


# ── Host metrics from /proc ──────────────────────────────────────────────────

def _read_proc_meminfo() -> Dict[str, int]:
    """Parse /proc/meminfo → values in bytes."""
    info: Dict[str, int] = {}
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2:
                    info[parts[0].rstrip(":")] = int(parts[1]) * 1024
    except (OSError, ValueError):
        pass
    return info


def _read_cpu_times() -> Optional[List[int]]:
    """Read aggregate CPU jiffies from /proc/stat (first 'cpu' line)."""
    try:
        with open("/proc/stat") as f:
            for line in f:
                if line.startswith("cpu "):
                    return [int(x) for x in line.split()[1:]]
    except (OSError, ValueError):
        pass
    return None


def _cpu_count() -> int:
    try:
        with open("/proc/stat") as f:
            return sum(1 for l in f if l.startswith("cpu") and l[3:4].isdigit())
    except OSError:
        return os.cpu_count() or 1


def _get_host_cpu_percent() -> float:
    """Compute CPU% between two successive reads of /proc/stat."""
    global _prev_cpu_times
    current = _read_cpu_times()
    if not current:
        return 0.0
    if _prev_cpu_times is None:
        _prev_cpu_times = current
        return 0.0

    deltas = [c - p for c, p in zip(current, _prev_cpu_times)]
    _prev_cpu_times = current
    total = sum(deltas)
    if total == 0:
        return 0.0
    # fields: user nice system idle iowait irq softirq steal …
    idle = deltas[3] + (deltas[4] if len(deltas) > 4 else 0)
    return round((1 - idle / total) * 100, 1)


def _read_loadavg() -> List[float]:
    try:
        with open("/proc/loadavg") as f:
            p = f.read().split()
            return [float(p[0]), float(p[1]), float(p[2])]
    except (OSError, ValueError, IndexError):
        return [0.0, 0.0, 0.0]


def _read_uptime() -> float:
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0])
    except (OSError, ValueError):
        return 0.0


def _get_disk_usage(path: str = "/") -> Dict[str, Any]:
    try:
        st = os.statvfs(path)
        total = st.f_frsize * st.f_blocks
        free = st.f_frsize * st.f_bfree
        used = total - free
        return {
            "total": total,
            "used": used,
            "free": free,
            "percent": round(used / total * 100, 1) if total else 0,
        }
    except OSError:
        return {"total": 0, "used": 0, "free": 0, "percent": 0}


def _get_host_metrics() -> Dict[str, Any]:
    mem = _read_proc_meminfo()
    mem_total = mem.get("MemTotal", 0)
    mem_avail = mem.get("MemAvailable", 0)
    mem_used = mem_total - mem_avail
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    swap_used = swap_total - swap_free

    return {
        "cpu_count": _cpu_count(),
        "cpu_percent": _get_host_cpu_percent(),
        "load_average": _read_loadavg(),
        "memory": {
            "total": mem_total,
            "used": mem_used,
            "available": mem_avail,
            "percent": round(mem_used / mem_total * 100, 1) if mem_total else 0,
        },
        "swap": {
            "total": swap_total,
            "used": swap_used,
            "percent": round(swap_used / swap_total * 100, 1) if swap_total else 0,
        },
        "disk": _get_disk_usage("/"),
        "uptime_seconds": _read_uptime(),
    }


# ── In-cluster Kubernetes config ─────────────────────────────────────────────

_SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
_SA_TOKEN_PATH = f"{_SA_DIR}/token"
_SA_CA_PATH = f"{_SA_DIR}/ca.crt"
_SA_NS_PATH = f"{_SA_DIR}/namespace"


def _k8s_api_base() -> Optional[str]:
    host = os.getenv("KUBERNETES_SERVICE_HOST")
    port = os.getenv("KUBERNETES_SERVICE_PORT", "443")
    if not host:
        return None
    return f"https://{host}:{port}"


def _k8s_namespace() -> Optional[str]:
    try:
        with open(_SA_NS_PATH) as f:
            return f.read().strip()
    except OSError:
        return os.getenv("POD_NAMESPACE") or os.getenv("NAMESPACE")


def _k8s_token() -> Optional[str]:
    try:
        with open(_SA_TOKEN_PATH) as f:
            return f.read().strip()
    except OSError:
        return None


def _k8s_available() -> bool:
    return bool(_k8s_api_base() and _k8s_token() and os.path.exists(_SA_CA_PATH))


# Pod phase → UI state vocabulary (reuse the Docker-era palette).
_PHASE_TO_STATE: Dict[str, str] = {
    "Running":   "running",
    "Pending":   "created",
    "Succeeded": "exited",
    "Failed":    "dead",
    "Unknown":   "dead",
}


# Optional overrides when a label value is not already the SVC_INFO key.
_LABEL_SLUG_OVERRIDES: Dict[str, str] = {
    "primary": "postgresql",
    "master":  "redis",
}


def _derive_slug(pod: Dict[str, Any]) -> str:
    """Map a pod to a SVC_INFO key the frontend can look up."""
    labels = (pod.get("metadata") or {}).get("labels") or {}
    name = (pod.get("metadata") or {}).get("name", "")

    # 1) Helm chart pods set app.kubernetes.io/name == service slug.
    slug = labels.get("app.kubernetes.io/name")
    if slug:
        return _LABEL_SLUG_OVERRIDES.get(slug, slug)

    # 2) Some subcharts only set app.kubernetes.io/component.
    slug = labels.get("app.kubernetes.io/component")
    if slug:
        return _LABEL_SLUG_OVERRIDES.get(slug, slug)

    # 3) Fallback: derive from pod name by stripping replica suffix + ordinal.
    #    ti-api-66db886895-2j7n7 → ti-api → api
    #    ti-postgresql-0         → ti-postgresql → postgresql
    stem = re.sub(r"-[a-z0-9]{6,10}-[a-z0-9]{5}$", "", name)
    stem = re.sub(r"-\d+$", "", stem)
    parts = stem.split("-", 1)
    return parts[1] if len(parts) == 2 else stem


# ── Quantity parser (K8s resource.Quantity) ──────────────────────────────────

_QUANTITY_RE = re.compile(r"^\s*([-+]?[0-9]*\.?[0-9]+)\s*([a-zA-Z]*)\s*$")

_BIN_MULT = {
    "Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3,
    "Ti": 1024 ** 4, "Pi": 1024 ** 5, "Ei": 1024 ** 6,
}
_DEC_MULT = {
    "n": 1e-9, "u": 1e-6, "m": 1e-3, "": 1.0,
    "k": 1e3, "M": 1e6, "G": 1e9, "T": 1e12, "P": 1e15, "E": 1e18,
}


def _parse_quantity(q: Any) -> float:
    """Parse a K8s resource.Quantity string (e.g. '500m', '256Mi') → float."""
    if q is None:
        return 0.0
    m = _QUANTITY_RE.match(str(q))
    if not m:
        return 0.0
    val, suf = m.group(1), m.group(2)
    try:
        v = float(val)
    except ValueError:
        return 0.0
    if suf in _BIN_MULT:
        return v * _BIN_MULT[suf]
    if suf in _DEC_MULT:
        return v * _DEC_MULT[suf]
    return v  # unknown suffix — best effort


def _sum_pod_cpu_nanocores(usages: List[Dict[str, Any]]) -> int:
    """Sum per-container CPU usage (cores, as float) and return nanocores."""
    total = 0.0
    for c in usages:
        cpu = (c.get("usage") or {}).get("cpu", "0")
        total += _parse_quantity(cpu) * 1e9
    return int(total)


def _sum_pod_mem_bytes(usages: List[Dict[str, Any]]) -> int:
    total = 0
    for c in usages:
        mem = (c.get("usage") or {}).get("memory", "0")
        total += int(_parse_quantity(mem))
    return total


def _pod_mem_limit_bytes(pod: Dict[str, Any]) -> int:
    total = 0
    for c in (pod.get("spec") or {}).get("containers", []) or []:
        lim = ((c.get("resources") or {}).get("limits") or {}).get("memory")
        if lim:
            total += int(_parse_quantity(lim))
    return total


def _pod_state(pod: Dict[str, Any]) -> Tuple[str, str]:
    """Return (state, human-readable status) using the legacy UI vocab."""
    status = pod.get("status") or {}
    phase = status.get("phase", "Unknown")
    state = _PHASE_TO_STATE.get(phase, "dead")

    # Surface waiting reasons that the UI has a colour for.
    for cs in status.get("containerStatuses") or []:
        waiting = ((cs.get("state") or {}).get("waiting")) or {}
        reason = waiting.get("reason")
        if reason in ("CrashLoopBackOff", "ImagePullBackOff", "ErrImagePull"):
            return "restarting", reason
        if reason == "ContainerCreating" and state == "created":
            return "created", reason

    if phase == "Running":
        all_ready = True
        any_ready = False
        for cs in status.get("containerStatuses") or []:
            ready = cs.get("ready", False)
            any_ready = any_ready or ready
            all_ready = all_ready and ready
        status_text = "Running (ready)" if all_ready else (
            "Running (partial)" if any_ready else "Running (not ready)"
        )
    else:
        status_text = phase

    return state, status_text


_EMPTY_POD = {
    "cpu_percent": 0,
    "memory":   {"used": 0, "limit": 0, "percent": 0},
    "network":  {"rx_bytes": 0, "tx_bytes": 0},
    "block_io": {"read_bytes": 0, "write_bytes": 0},
}


async def _k8s_get(client: httpx.AsyncClient, path: str) -> Dict[str, Any]:
    r = await client.get(path)
    r.raise_for_status()
    return r.json()


async def _fetch_pod_metrics() -> List[Dict[str, Any]]:
    """List pods in the release namespace, joined with metrics-server usage."""
    if not _k8s_available():
        log.debug("In-cluster K8s credentials missing — /system/metrics "
                  "will return no pod rows")
        return []

    base = _k8s_api_base()
    ns = _k8s_namespace() or "default"
    token = _k8s_token()
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    pods_out: List[Dict[str, Any]] = []
    try:
        async with httpx.AsyncClient(
            base_url=base, headers=headers, verify=_SA_CA_PATH, timeout=10.0,
        ) as client:
            pods_raw = await _k8s_get(
                client, f"/api/v1/namespaces/{ns}/pods",
            )

            # Usage is best-effort: a broken metrics-server must not take the
            # whole endpoint down.
            usage_by_pod: Dict[str, List[Dict[str, Any]]] = {}
            try:
                metrics_raw = await _k8s_get(
                    client,
                    f"/apis/metrics.k8s.io/v1beta1/namespaces/{ns}/pods",
                )
                for item in metrics_raw.get("items", []):
                    usage_by_pod[item["metadata"]["name"]] = \
                        item.get("containers", [])
            except Exception as exc:
                log.info("metrics.k8s.io query failed "
                         "(metrics-server missing or RBAC?): %s", exc)

            for pod in pods_raw.get("items", []):
                meta = pod.get("metadata") or {}
                name = meta.get("name", "unknown")
                slug = _derive_slug(pod)
                state, status_text = _pod_state(pod)

                if state != "running":
                    pods_out.append({
                        "name": name, "service": slug,
                        "state": state, "status": status_text,
                        **_EMPTY_POD,
                    })
                    continue

                usages = usage_by_pod.get(name, [])
                cpu_ncores = _sum_pod_cpu_nanocores(usages)
                mem_used = _sum_pod_mem_bytes(usages)
                mem_limit = _pod_mem_limit_bytes(pod)
                # Percentage of a single core (matches the Docker CPU% scale
                # the UI already handles — values can exceed 100% for multi-
                # core pods).
                cpu_percent = round(cpu_ncores / 1e9 * 100, 2)

                pods_out.append({
                    "name": name,
                    "service": slug,
                    "state": state,
                    "status": status_text,
                    "cpu_percent": cpu_percent,
                    "memory": {
                        "used": mem_used,
                        "limit": mem_limit,
                        "percent":
                            round(mem_used / mem_limit * 100, 1)
                            if mem_limit else 0,
                    },
                    # metrics-server does not expose per-pod network or block
                    # I/O. Kept as zeros to preserve the response schema.
                    "network":  {"rx_bytes": 0, "tx_bytes": 0},
                    "block_io": {"read_bytes": 0, "write_bytes": 0},
                })
    except Exception as exc:
        log.warning("Kubernetes API query failed: %s", exc)
        return []

    return sorted(pods_out, key=lambda x: (x["service"], x["name"]))


# ── Cached wrapper ───────────────────────────────────────────────────────────

async def _collect() -> Dict[str, Any]:
    now = time.monotonic()
    if _CACHE.get("ts") and now - _CACHE["ts"] < _CACHE_TTL:
        return _CACHE["data"]

    host = _get_host_metrics()
    pods = await _fetch_pod_metrics()

    # Wire-compat: the field is still named `containers` so the existing
    # frontend keeps working. It now carries Kubernetes pods, not Docker
    # containers.
    data = {
        "host": host,
        "containers": pods,
        "collected_at": time.time(),
    }
    _CACHE["data"] = data
    _CACHE["ts"] = now
    return data


# ── Endpoint ─────────────────────────────────────────────────────────────────

@router.get("/metrics")
async def get_system_metrics(
    _: str = Depends(require_api_key),
) -> Dict[str, Any]:
    """
    Host-level and per-pod resource utilisation.

    - Host: CPU %, memory, swap, disk, load average, uptime (from /proc).
    - Pods: CPU %, memory (via metrics.k8s.io), state (derived from pod
      phase and containerStatuses). Network and block I/O are reported as
      zero — metrics-server does not expose those counters.
    - Results are cached for 5 s.
    """
    return await _collect()
