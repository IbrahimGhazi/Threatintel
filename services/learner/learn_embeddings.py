"""M3 behavioral-embedding learner (nightly batch).

Pulls 7 days of per-(host, hour) aggregates from log_entries, builds a
~40-dim feature vector per sample, trains a tiny numpy autoencoder
(40 -> 32 -> 40), encodes one embedding per host, derives each
destination's "normal caller centroid" as the mean of the embeddings
of hosts that contacted it, and upserts everything into entity_embedding.

Runs in ~30s at this scale. No GPU, no torch; pure numpy + psycopg2.
"""
from __future__ import annotations

import json
import logging
import math
import os
import sys
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import psycopg2
import psycopg2.extras

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format='{"time": "%(asctime)s", "level": "%(levelname)s", "service": "learner", "message": "%(message)s"}',
    stream=sys.stdout,
)
logger = logging.getLogger("learner")

DATABASE_URL  = os.getenv("DATABASE_URL", "")
WINDOW_DAYS   = int(os.getenv("LEARNER_WINDOW_DAYS", "7"))
DIM_HIDDEN    = int(os.getenv("LEARNER_DIM_HIDDEN", "32"))
EPOCHS        = int(os.getenv("LEARNER_EPOCHS", "200"))
LEARNING_RATE = float(os.getenv("LEARNER_LR", "0.05"))
BATCH_SIZE    = int(os.getenv("LEARNER_BATCH", "64"))
MIN_HOST_SAMPLES = int(os.getenv("LEARNER_MIN_HOST_SAMPLES", "5"))
MIN_DST_CALLERS  = int(os.getenv("LEARNER_MIN_DST_CALLERS", "2"))
MAX_DESTINATIONS = int(os.getenv("LEARNER_MAX_DESTINATIONS", "20000"))

# Fixed port buckets — any port not in this list becomes "other".
PORT_BUCKETS = [22, 53, 80, 123, 135, 139, 389, 443, 445, 465, 587,
                636, 993, 995, 1433, 3306, 3389, 5353, 5985, 8080, 8443]
PROTO_BUCKETS = ["tcp", "udp", "icmp"]
ACTION_BUCKETS = ["allow", "deny", "drop", "block"]


# ── Feature engineering ──────────────────────────────────────────────────────

FEATURE_NAMES = (
    ["log_events", "log_bytes", "log_unique_dsts", "log_unique_ports"]
    + [f"port_{p}" for p in PORT_BUCKETS] + ["port_other"]
    + [f"proto_{p}" for p in PROTO_BUCKETS] + ["proto_other"]
    + [f"action_{a}" for a in ACTION_BUCKETS] + ["action_other"]
    + ["port_entropy", "dst_entropy", "hour_sin", "hour_cos", "dow_sin", "dow_cos"]
)


def _entropy(counts: Dict[Any, int]) -> float:
    total = sum(counts.values())
    if total <= 0:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)


def _featurise(agg: Dict[str, Any]) -> np.ndarray:
    """Turn one (host, hour) aggregate dict into a numeric feature vector."""
    feats: List[float] = []

    n        = max(agg["events"], 1)
    bytes_t  = agg["bytes_total"]
    uniq_dst = agg["unique_dsts"]
    uniq_prt = agg["unique_ports"]

    feats.append(math.log10(n + 1))
    feats.append(math.log10(bytes_t + 1))
    feats.append(math.log10(uniq_dst + 1))
    feats.append(math.log10(uniq_prt + 1))

    # Port histogram (proportions)
    port_counts: Dict[int, int] = agg["port_counts"]
    bucket_total = sum(port_counts.get(p, 0) for p in PORT_BUCKETS)
    other = sum(port_counts.values()) - bucket_total
    for p in PORT_BUCKETS:
        feats.append(port_counts.get(p, 0) / n)
    feats.append(max(other, 0) / n)

    # Protocol mix
    proto_counts: Dict[str, int] = agg["proto_counts"]
    proto_seen = sum(proto_counts.get(p, 0) for p in PROTO_BUCKETS)
    for p in PROTO_BUCKETS:
        feats.append(proto_counts.get(p, 0) / n)
    feats.append(max(n - proto_seen, 0) / n)

    # Action mix
    action_counts: Dict[str, int] = agg["action_counts"]
    act_seen = sum(action_counts.get(a, 0) for a in ACTION_BUCKETS)
    for a in ACTION_BUCKETS:
        feats.append(action_counts.get(a, 0) / n)
    feats.append(max(n - act_seen, 0) / n)

    # Distribution entropies
    feats.append(_entropy(port_counts))
    feats.append(_entropy(agg["dst_counts"]))

    # Cyclical hour / day-of-week
    hour = agg["hour_of_day"]; dow = agg["day_of_week"]
    feats.append(math.sin(2 * math.pi * hour / 24))
    feats.append(math.cos(2 * math.pi * hour / 24))
    feats.append(math.sin(2 * math.pi * dow / 7))
    feats.append(math.cos(2 * math.pi * dow / 7))

    return np.asarray(feats, dtype=np.float64)


# ── Data loading ─────────────────────────────────────────────────────────────

def load_aggregates(conn) -> Tuple[Dict[str, List[Dict]], Dict[str, List[str]]]:
    """Return (host_agg_map, dst_callers_map).

    host_agg_map[src_ip] = [ {events, bytes_total, unique_dsts, unique_ports,
                              port_counts, proto_counts, action_counts,
                              dst_counts, hour_of_day, day_of_week}, ... ]
                           — one per (host, hour_bucket).
    dst_callers_map[dst_ip] = [ caller1, caller2, ... ]   (distinct)
    """
    host_agg: Dict[str, List[Dict]] = defaultdict(list)
    dst_callers: Dict[str, set] = defaultdict(set)

    # Two passes: one for per-(host, hour) summary (volume/diversity counters)
    # and one for histogram rows (port/proto/action/destination distributions).
    # Aggregation is finished in Python — simpler than juggling jsonb_object_agg
    # with sum-dedup, and at this scale (~1.5M rows) fast enough.
    sql_hours = """
        SELECT
            source_ip,
            date_trunc('hour', processed_at) AS h,
            EXTRACT(HOUR FROM processed_at)::int AS hod,
            EXTRACT(DOW  FROM processed_at)::int AS dow,
            COUNT(*)                         AS events,
            COALESCE(SUM((parsed->>'bytes_total')::bigint), 0) AS bytes_total,
            COUNT(DISTINCT parsed->>'dst_ip')   AS unique_dsts,
            COUNT(DISTINCT parsed->>'dst_port') AS unique_ports
        FROM log_entries
        WHERE processed_at > NOW() - (INTERVAL '1 day' * %s)
          AND source_ip IS NOT NULL
          AND parsed IS NOT NULL
        GROUP BY source_ip, h, hod, dow
        HAVING COUNT(*) >= 5
        ORDER BY source_ip, h;
    """

    sql_hist = """
        SELECT
            source_ip,
            date_trunc('hour', processed_at) AS h,
            parsed->>'dst_ip'   AS dst_ip_k,
            parsed->>'dst_port' AS port_k,
            parsed->>'protocol' AS proto_k,
            parsed->>'action'   AS action_k,
            COUNT(*) AS c
        FROM log_entries
        WHERE processed_at > NOW() - (INTERVAL '1 day' * %s)
          AND source_ip IS NOT NULL
          AND parsed IS NOT NULL
        GROUP BY source_ip, h, dst_ip_k, port_k, proto_k, action_k;
    """

    logger.info("Loading per-hour summary (window=%d days)...", WINDOW_DAYS)
    t0 = time.time()
    with conn.cursor(name="hours_cur", cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.itersize = 5000
        cur.execute(sql_hours, (WINDOW_DAYS,))
        summary = {(r["source_ip"], r["h"]): dict(r) for r in cur}
    logger.info("Per-hour summary loaded: %d buckets in %.1fs", len(summary), time.time() - t0)

    if not summary:
        logger.warning("No data — nothing to train on")
        return {}, {}

    logger.info("Loading histogram rows...")
    t0 = time.time()
    with conn.cursor(name="hist_cur", cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.itersize = 20000
        cur.execute(sql_hist, (WINDOW_DAYS,))
        for i, r in enumerate(cur, 1):
            key = (r["source_ip"], r["h"])
            s = summary.get(key)
            if s is None:
                continue
            c = int(r["c"])
            port_k   = r["port_k"]
            proto_k  = (r["proto_k"] or "").lower() if r["proto_k"] else None
            action_k = (r["action_k"] or "").lower() if r["action_k"] else None
            dst_ip_k = r["dst_ip_k"]
            s.setdefault("port_counts", {})
            s.setdefault("proto_counts", {})
            s.setdefault("action_counts", {})
            s.setdefault("dst_counts", {})
            if port_k:
                try:
                    pk = int(port_k)
                except (TypeError, ValueError):
                    pk = None
                if pk is not None:
                    s["port_counts"][pk] = s["port_counts"].get(pk, 0) + c
            if proto_k:
                s["proto_counts"][proto_k] = s["proto_counts"].get(proto_k, 0) + c
            if action_k:
                s["action_counts"][action_k] = s["action_counts"].get(action_k, 0) + c
            if dst_ip_k:
                s["dst_counts"][dst_ip_k] = s["dst_counts"].get(dst_ip_k, 0) + c
                dst_callers[dst_ip_k].add(r["source_ip"])
            if i % 200000 == 0:
                logger.info("  %d histogram rows processed...", i)
    logger.info("Histograms loaded in %.1fs", time.time() - t0)

    for s in summary.values():
        s.setdefault("port_counts", {})
        s.setdefault("proto_counts", {})
        s.setdefault("action_counts", {})
        s.setdefault("dst_counts", {})
        s["hour_of_day"] = s["hod"]
        s["day_of_week"] = s["dow"]

    host_agg: Dict[str, List[Dict]] = defaultdict(list)
    for (src, _h), agg in summary.items():
        host_agg[src].append(agg)

    return host_agg, dst_callers


# ── Autoencoder (pure numpy, MLP, tanh activation) ──────────────────────────

class TinyAutoencoder:
    def __init__(self, dim_in: int, dim_hidden: int, seed: int = 1337) -> None:
        rng = np.random.default_rng(seed)
        # Xavier init
        self.W1 = rng.normal(0, np.sqrt(1.0 / dim_in), (dim_in, dim_hidden))
        self.b1 = np.zeros(dim_hidden)
        self.W2 = rng.normal(0, np.sqrt(1.0 / dim_hidden), (dim_hidden, dim_in))
        self.b2 = np.zeros(dim_in)
        self.dim_in = dim_in
        self.dim_hidden = dim_hidden

    def encode(self, x: np.ndarray) -> np.ndarray:
        return np.tanh(x @ self.W1 + self.b1)

    def decode(self, h: np.ndarray) -> np.ndarray:
        return h @ self.W2 + self.b2

    def forward(self, x: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        h = self.encode(x)
        return h, self.decode(h)

    def train(self, X: np.ndarray, epochs: int, lr: float, batch: int) -> float:
        n = X.shape[0]
        losses = []
        for epoch in range(epochs):
            idx = np.random.permutation(n)
            total = 0.0
            for start in range(0, n, batch):
                b_idx = idx[start : start + batch]
                xb = X[b_idx]
                h, xh = self.forward(xb)
                err = xh - xb  # (B, dim_in)
                grad_W2 = h.T @ err / xb.shape[0]
                grad_b2 = err.mean(axis=0)
                # backprop through tanh
                dh = err @ self.W2.T * (1 - h**2)
                grad_W1 = xb.T @ dh / xb.shape[0]
                grad_b1 = dh.mean(axis=0)
                self.W1 -= lr * grad_W1; self.b1 -= lr * grad_b1
                self.W2 -= lr * grad_W2; self.b2 -= lr * grad_b2
                total += 0.5 * float((err**2).sum()) / xb.shape[0]
            avg = total / max(n // batch, 1)
            losses.append(avg)
            if epoch % 20 == 0 or epoch == epochs - 1:
                logger.info("  epoch %d  loss=%.4f", epoch, avg)
        return losses[-1]


# ── DB I/O ───────────────────────────────────────────────────────────────────

def upsert_model(conn, model_name: str, ae: TinyAutoencoder,
                 means: np.ndarray, stds: np.ndarray,
                 loss: float, n_samples: int) -> None:
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO embedding_model
                (model_name, dim_in, dim_hidden, feature_means, feature_stds,
                 w1, b1, w2, b2, training_loss, trained_at, sample_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), %s)
            ON CONFLICT (model_name) DO UPDATE SET
              dim_in = EXCLUDED.dim_in,
              dim_hidden = EXCLUDED.dim_hidden,
              feature_means = EXCLUDED.feature_means,
              feature_stds  = EXCLUDED.feature_stds,
              w1 = EXCLUDED.w1, b1 = EXCLUDED.b1,
              w2 = EXCLUDED.w2, b2 = EXCLUDED.b2,
              training_loss = EXCLUDED.training_loss,
              trained_at    = NOW(),
              sample_count  = EXCLUDED.sample_count
            """,
            (
                model_name,
                ae.dim_in,
                ae.dim_hidden,
                means.tolist(),
                stds.tolist(),
                ae.W1.flatten().tolist(),
                ae.b1.tolist(),
                ae.W2.flatten().tolist(),
                ae.b2.tolist(),
                float(loss),
                int(n_samples),
            ),
        )
    conn.commit()


def upsert_embeddings(conn, rows: List[Tuple[str, str, List[float], Dict[str, Any], int]]) -> int:
    """rows: (entity_type, entity_value, vector, feature_stats, sample_count)"""
    with conn.cursor() as cur:
        psycopg2.extras.execute_batch(
            cur,
            """
            INSERT INTO entity_embedding
                (entity_type, entity_value, vector, feature_stats, sample_count, updated_at)
            VALUES (%s, %s, %s, %s, %s, NOW())
            ON CONFLICT (entity_type, entity_value) DO UPDATE SET
              vector        = EXCLUDED.vector,
              feature_stats = EXCLUDED.feature_stats,
              sample_count  = EXCLUDED.sample_count,
              updated_at    = NOW()
            """,
            [(t, v, vec, json.dumps(stats), cnt) for (t, v, vec, stats, cnt) in rows],
            page_size=500,
        )
    conn.commit()
    return len(rows)


# ── Orchestration ────────────────────────────────────────────────────────────

def _l2norm(v: np.ndarray) -> np.ndarray:
    n = np.linalg.norm(v)
    return v / n if n > 1e-9 else v


def main() -> int:
    if not DATABASE_URL:
        logger.error("DATABASE_URL not set")
        return 2

    conn = psycopg2.connect(DATABASE_URL)
    try:
        host_agg, dst_callers = load_aggregates(conn)

        if not host_agg:
            logger.warning("No host aggregates — exiting")
            return 0

        # 1. Build feature matrix
        rows: List[np.ndarray] = []
        row_sources: List[str] = []
        for src, aggs in host_agg.items():
            for agg in aggs:
                rows.append(_featurise(agg))
                row_sources.append(src)
        X = np.vstack(rows)
        n_features = X.shape[1]
        logger.info("Built feature matrix: shape=%s, feature_names=%d", X.shape, len(FEATURE_NAMES))
        assert n_features == len(FEATURE_NAMES), (n_features, len(FEATURE_NAMES))

        # 2. Standardize
        means = X.mean(axis=0)
        stds  = X.std(axis=0) + 1e-6
        Xn = (X - means) / stds

        # 3. Train autoencoder
        logger.info("Training autoencoder: in=%d hidden=%d epochs=%d lr=%.3f bs=%d",
                    n_features, DIM_HIDDEN, EPOCHS, LEARNING_RATE, BATCH_SIZE)
        ae = TinyAutoencoder(n_features, DIM_HIDDEN)
        loss = ae.train(Xn, EPOCHS, LEARNING_RATE, BATCH_SIZE)
        logger.info("Final training loss: %.4f", loss)

        # 4. Encode per-host embeddings (mean over all samples for that host)
        host_vectors: Dict[str, np.ndarray] = {}
        host_sample_counts: Dict[str, int] = {}
        for src, aggs in host_agg.items():
            if len(aggs) < MIN_HOST_SAMPLES:
                continue
            per = np.vstack([(_featurise(a) - means) / stds for a in aggs])
            embs = ae.encode(per)
            centroid = _l2norm(embs.mean(axis=0))
            host_vectors[src] = centroid
            host_sample_counts[src] = len(aggs)
        logger.info("Encoded %d host embeddings (min_samples=%d)",
                    len(host_vectors), MIN_HOST_SAMPLES)

        # 5. Destination centroids = mean of embeddings of callers
        dst_vectors: Dict[str, Tuple[np.ndarray, int]] = {}
        for dst, callers in dst_callers.items():
            valid = [host_vectors[c] for c in callers if c in host_vectors]
            if len(valid) < MIN_DST_CALLERS:
                continue
            dst_vectors[dst] = (_l2norm(np.mean(np.vstack(valid), axis=0)), len(valid))
        logger.info("Encoded %d destination centroids (min_callers=%d)",
                    len(dst_vectors), MIN_DST_CALLERS)
        if len(dst_vectors) > MAX_DESTINATIONS:
            # Keep the most-observed destinations
            ranked = sorted(dst_vectors.items(), key=lambda kv: -kv[1][1])[:MAX_DESTINATIONS]
            dst_vectors = dict(ranked)
            logger.info("Capped destinations to top %d by caller count", MAX_DESTINATIONS)

        # 6. Persist
        model_rows: List[Tuple[str, str, List[float], Dict[str, Any], int]] = []
        for src, vec in host_vectors.items():
            stats = {"samples": host_sample_counts[src], "dim": DIM_HIDDEN}
            model_rows.append(("host", src, vec.tolist(), stats, host_sample_counts[src]))
        for dst, (vec, n_callers) in dst_vectors.items():
            stats = {"callers": n_callers, "dim": DIM_HIDDEN}
            model_rows.append(("destination", dst, vec.tolist(), stats, n_callers))

        n = upsert_embeddings(conn, model_rows)
        upsert_model(conn, "host_v1", ae, means, stds, loss, int(X.shape[0]))
        logger.info("Upserted %d embedding rows (hosts=%d, destinations=%d) + model row",
                    n, len(host_vectors), len(dst_vectors))

        return 0
    finally:
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
