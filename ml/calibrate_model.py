"""CLI — fit an isotonic calibrator for the URL classifier.

Usage
-----
    python -m ml.calibrate_model \\
        --data  path/to/eval.csv \\
        --model ml/model/url_classifier.json \\
        --out   ml/model/url_classifier.calib.json

The CSV must have columns ``url,label`` with ``label`` in {0, 1}. Use
data the model has **not** seen during training — a held-out validation
split — otherwise the calibrator will overfit the training distribution
and actively hurt production accuracy.

Output
------
* JSON calibrator file at ``--out``
* Pre- and post-calibration reliability diagrams on stdout, plus Brier
  score (lower = better calibrated).

Runtime
-------
~O(N) prediction + one isotonic fit. A 200 k-row eval set completes in
well under a minute on a single core.
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

import numpy as np
import pandas as pd

# Local imports — keep heavy deps lazy
from ml.calibration import IsotonicCalibrator
from ml.feature_extractor import extract_features

log = logging.getLogger("ti.url_intel.calibrate")


def _predict_scores(model_path: Path, urls) -> np.ndarray:
    from xgboost import XGBClassifier
    clf = XGBClassifier()
    clf.load_model(str(model_path))
    booster = clf.get_booster()
    X = np.vstack([extract_features(u) for u in urls]).astype(np.float32)
    return np.asarray(booster.inplace_predict(X), dtype=np.float64).ravel()


def _brier(scores: np.ndarray, labels: np.ndarray) -> float:
    return float(np.mean((scores - labels) ** 2))


def _reliability(scores: np.ndarray, labels: np.ndarray, bins: int = 10) -> str:
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(scores, edges) - 1, 0, bins - 1)
    lines = [f"  {'bucket':<14} {'n':>8} {'mean_p':>8} {'observed':>10} {'gap':>8}"]
    for b in range(bins):
        mask = idx == b
        n = int(mask.sum())
        if n == 0:
            continue
        mp = float(scores[mask].mean())
        obs = float(labels[mask].mean())
        lines.append(
            f"  [{edges[b]:.2f},{edges[b+1]:.2f})  {n:>8d} "
            f"{mp:>8.3f} {obs:>10.3f} {obs - mp:>+8.3f}"
        )
    return "\n".join(lines)


def main(argv=None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--data", required=True, type=Path,
                   help="CSV with columns url,label (held-out set)")
    p.add_argument("--model", type=Path,
                   default=Path("ml/model/url_classifier.json"))
    p.add_argument("--out",   type=Path,
                   default=Path("ml/model/url_classifier.calib.json"))
    p.add_argument("--bins",  type=int, default=10,
                   help="Reliability-diagram bins (default 10)")
    p.add_argument("--sample", type=int, default=0,
                   help="Randomly subsample to N rows (0 = all)")
    args = p.parse_args(argv)

    if not args.data.is_file():
        print(f"ERR: data file not found: {args.data}", file=sys.stderr)
        return 2
    if not args.model.is_file():
        print(f"ERR: model not found: {args.model}", file=sys.stderr)
        return 2

    df = pd.read_csv(args.data)
    if not {"url", "label"}.issubset(df.columns):
        print("ERR: CSV must have columns url,label", file=sys.stderr)
        return 2
    if args.sample and args.sample < len(df):
        df = df.sample(args.sample, random_state=0).reset_index(drop=True)

    print(f"Loaded {len(df):,} labelled examples "
          f"({df['label'].mean():.1%} positive)", file=sys.stderr)

    print("Scoring with XGBoost booster...", file=sys.stderr)
    raw = _predict_scores(args.model, df["url"].astype(str).tolist())
    y   = df["label"].astype(int).to_numpy()

    print("\n── Pre-calibration reliability ──")
    print(_reliability(raw, y, bins=args.bins))
    print(f"  Brier = {_brier(raw, y):.4f}")

    calib = IsotonicCalibrator.fit(raw, y, meta={
        "source_csv": str(args.data),
        "model_path": str(args.model),
        "n_rows":     int(len(df)),
    })
    cal = calib.apply_batch(raw)

    print("\n── Post-calibration reliability ──")
    print(_reliability(cal, y, bins=args.bins))
    print(f"  Brier = {_brier(cal, y):.4f}")

    calib.save(args.out)
    print(f"\nSaved calibrator → {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
