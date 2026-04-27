"""Isotonic probability calibration for the URL classifier.

Why this exists
---------------
XGBoost's ``predict_proba`` scores are systematically mis-scaled: a
score of 0.8 does not mean "80 % of URLs with that score are truly
malicious". That confuses downstream thresholding, analyst-facing
confidence displays, and the risk-score blend. An isotonic regression
fit once on a **held-out validation fold** makes the output a proper
calibrated probability at near-zero inference cost.

Persistence
-----------
We deliberately avoid pickling scikit-learn objects on the serve path —
pickles tie us to the exact scikit-learn minor version and make
deployment fragile. Instead we serialise the fitted monotonic step
function as plain JSON (two arrays, X and Y). ``apply`` at inference
time is a single ``numpy.interp`` call.

API
---
    calib = IsotonicCalibrator.fit(raw_scores, labels)
    calib.save(Path("..."))
    calib = IsotonicCalibrator.load(Path("..."))    # empty if missing
    p_calibrated = calib.apply(p_raw)
    p_calibrated = calib.apply_batch(p_raw_array)
    calib.fitted  -> bool
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import numpy as np


class IsotonicCalibrator:
    """Lightweight JSON-persisted isotonic calibrator.

    When loaded from a file that does not exist, the instance behaves as
    an identity function — ``apply(p) == p``. This means the service can
    always call ``calib.apply(p)`` without first checking for a model.
    """
    __slots__ = ("_x", "_y", "_fitted", "_meta")

    def __init__(self) -> None:
        # identity curve
        self._x: np.ndarray = np.array([0.0, 1.0], dtype=np.float64)
        self._y: np.ndarray = np.array([0.0, 1.0], dtype=np.float64)
        self._fitted = False
        self._meta: dict = {}

    # ── Construction ─────────────────────────────────────────────────────
    @classmethod
    def fit(cls, scores: np.ndarray, labels: np.ndarray,
            meta: Optional[dict] = None) -> "IsotonicCalibrator":
        """Fit monotonic mapping from raw XGBoost scores → P(malicious).

        ``scores`` is the 1-D array of raw ``predict_proba`` / ``inplace_predict``
        outputs on a held-out set. ``labels`` is the 0/1 ground-truth.
        """
        from sklearn.isotonic import IsotonicRegression  # heavy, lazy import
        s = np.asarray(scores, dtype=np.float64).ravel()
        y = np.asarray(labels, dtype=np.float64).ravel()
        if s.shape != y.shape:
            raise ValueError(f"shape mismatch: {s.shape} vs {y.shape}")

        ir = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        ir.fit(s, y)

        obj = cls()
        # IsotonicRegression stores the monotonic knots here:
        obj._x = np.asarray(ir.X_thresholds_, dtype=np.float64)
        obj._y = np.asarray(ir.y_thresholds_, dtype=np.float64)
        obj._fitted = True
        obj._meta = dict(meta or {})
        obj._meta.setdefault("n_train", int(s.size))
        obj._meta.setdefault("pos_rate", float(y.mean()))
        return obj

    # ── Application ──────────────────────────────────────────────────────
    def apply(self, p: float) -> float:
        if not self._fitted:
            return float(p)
        return float(np.clip(np.interp(p, self._x, self._y), 0.0, 1.0))

    def apply_batch(self, p: np.ndarray) -> np.ndarray:
        if not self._fitted:
            return np.asarray(p, dtype=np.float64)
        return np.clip(np.interp(p, self._x, self._y), 0.0, 1.0)

    # ── Persistence ──────────────────────────────────────────────────────
    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "format_version": 1,
            "fitted":  self._fitted,
            "x":       self._x.tolist(),
            "y":       self._y.tolist(),
            "meta":    self._meta,
        }, indent=2))

    @classmethod
    def load(cls, path: Path) -> "IsotonicCalibrator":
        obj = cls()
        p = Path(path)
        if not p.is_file():
            return obj   # identity
        try:
            data = json.loads(p.read_text())
        except Exception:
            return obj
        obj._x = np.asarray(data.get("x", [0.0, 1.0]), dtype=np.float64)
        obj._y = np.asarray(data.get("y", [0.0, 1.0]), dtype=np.float64)
        obj._fitted = bool(data.get("fitted", True))
        obj._meta = dict(data.get("meta") or {})
        return obj

    # ── Introspection ────────────────────────────────────────────────────
    @property
    def fitted(self) -> bool:
        return self._fitted

    @property
    def meta(self) -> dict:
        return dict(self._meta)

    def __repr__(self) -> str:
        return (f"IsotonicCalibrator(fitted={self._fitted}, "
                f"knots={len(self._x)}, meta={self._meta})")


# ─── Temperature scaling (for multi-class softmax models, e.g. URLBert) ──────

class TemperatureScaler:
    """Single-parameter temperature scaling for multi-class softmax outputs.

    When a deep classifier outputs logits ``z`` over K classes, the vanilla
    softmax ``softmax(z)`` is typically over-confident (high-90s mean score,
    true accuracy several points lower). Temperature scaling fits a single
    scalar T > 0 such that ``softmax(z / T)`` is well-calibrated:

        T ≈ 1   → logits already well calibrated (rare)
        T > 1   → vanilla softmax is over-confident (typical)
        T < 1   → model is under-confident

    The fit minimises NLL on a held-out set and is done via a closed-form
    grid search (no torch dependency needed at fit time — we bring our
    own optim).

    Like the isotonic variant, persistence is plain JSON — one number.
    Identity behaviour when not fitted.

    Usage
    -----
        scaler = TemperatureScaler.fit(logits, labels)       # 2-D and 1-D arrays
        probs  = scaler.apply_logits(np.array([...]))       # (N, K) softmaxed
        probs  = scaler.apply_probs(raw_softmax_probs)      # re-soft via log
        scaler.save(path); TemperatureScaler.load(path)
    """
    __slots__ = ("_T", "_fitted", "_meta")

    def __init__(self, T: float = 1.0) -> None:
        self._T = float(T)
        self._fitted = False
        self._meta: dict = {}

    @property
    def T(self) -> float:
        return self._T

    @property
    def fitted(self) -> bool:
        return self._fitted

    @property
    def meta(self) -> dict:
        return dict(self._meta)

    @classmethod
    def fit(cls, logits: np.ndarray, labels: np.ndarray,
            grid: Optional[np.ndarray] = None,
            meta: Optional[dict] = None) -> "TemperatureScaler":
        """Fit T by minimising multi-class NLL on (logits, labels)."""
        z = np.asarray(logits, dtype=np.float64)
        y = np.asarray(labels, dtype=np.int64).ravel()
        if z.ndim != 2:
            raise ValueError("logits must be 2-D (N, K)")
        if z.shape[0] != y.shape[0]:
            raise ValueError(f"shape mismatch: {z.shape} vs {y.shape}")

        if grid is None:
            grid = np.concatenate([
                np.linspace(0.5, 1.0,  26, endpoint=False),
                np.linspace(1.0, 3.0,  41),
                np.linspace(3.0, 8.0,  26),
            ])

        best_T, best_nll = 1.0, float("inf")
        for T in grid:
            nll = _nll(z / T, y)
            if nll < best_nll:
                best_nll, best_T = float(nll), float(T)

        obj = cls(best_T)
        obj._fitted = True
        obj._meta = dict(meta or {})
        obj._meta.setdefault("n_train", int(y.size))
        obj._meta.setdefault("nll_before", float(_nll(z, y)))
        obj._meta.setdefault("nll_after",  best_nll)
        return obj

    def apply_logits(self, logits: np.ndarray) -> np.ndarray:
        """Softmax(logits / T) — shape-preserving, last-axis softmax."""
        z = np.asarray(logits, dtype=np.float64) / self._T
        z = z - z.max(axis=-1, keepdims=True)
        e = np.exp(z)
        return e / e.sum(axis=-1, keepdims=True)

    def apply_probs(self, probs: np.ndarray, eps: float = 1e-9) -> np.ndarray:
        """Apply T-scaling to pre-softmax probabilities by going via log."""
        p = np.clip(np.asarray(probs, dtype=np.float64), eps, 1.0)
        logits = np.log(p)
        return self.apply_logits(logits)

    def save(self, path: Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "format_version": 1,
            "kind":   "temperature",
            "fitted": self._fitted,
            "T":      self._T,
            "meta":   self._meta,
        }, indent=2))

    @classmethod
    def load(cls, path: Path) -> "TemperatureScaler":
        p = Path(path)
        if not p.is_file():
            return cls()
        try:
            data = json.loads(p.read_text())
        except Exception:
            return cls()
        obj = cls(float(data.get("T", 1.0)))
        obj._fitted = bool(data.get("fitted", True))
        obj._meta = dict(data.get("meta") or {})
        return obj

    def __repr__(self) -> str:
        return (f"TemperatureScaler(T={self._T:.4f}, "
                f"fitted={self._fitted}, meta={self._meta})")


def _nll(z: np.ndarray, y: np.ndarray) -> float:
    """Multi-class negative log-likelihood on logits z and integer labels y."""
    z = z - z.max(axis=-1, keepdims=True)
    e = np.exp(z)
    logp = z - np.log(e.sum(axis=-1, keepdims=True))
    return float(-logp[np.arange(y.size), y].mean())
