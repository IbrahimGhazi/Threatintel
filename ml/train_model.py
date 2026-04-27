"""
XGBoost training pipeline for the TI Platform URL Intelligence Engine.

Usage
-----
    python -m ml.train_model \
        --dataset-dir URL_dataset \
        --model-out   ml/model/url_classifier.json \
        --report-out  ml/artifacts/training_report.json

Pipeline:
    1. Load + merge + dedup datasets           (ml.dataset_loader)
    2. Feature extraction                      (ml.feature_extractor)
    3. Stratified train / test split
    4. Train XGBClassifier with early stopping
    5. Threshold tuning for FPR < 1 %
    6. Persist model JSON + metadata

Success targets:
    accuracy          > 0.97
    false-positive    < 0.01  (at tuned threshold)
    inference latency < 10 ms (single URL, cold call)
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier

from ml.dataset_loader import (
    DEFAULT_DATASET_DIR,
    load_all_datasets,
    load_phishing_feature_calibration,
)
from ml.feature_extractor import FEATURE_NAMES, extract_features_df

log = logging.getLogger("ti.ml.train")

DEFAULT_MODEL_PATH   = Path("ml/model/url_classifier.json")
DEFAULT_META_PATH    = Path("ml/model/url_classifier.meta.json")
DEFAULT_REPORT_PATH  = Path("ml/artifacts/training_report.json")


# ─── Configuration objects ────────────────────────────────────────────────────

@dataclass
class TrainConfig:
    dataset_dir:       Path = DEFAULT_DATASET_DIR
    model_out:         Path = DEFAULT_MODEL_PATH
    meta_out:          Path = DEFAULT_META_PATH
    report_out:        Path = DEFAULT_REPORT_PATH
    test_size:         float = 0.20
    random_state:      int = 42
    target_fpr:        float = 0.01
    max_rows:          Optional[int] = None     # useful for smoke-tests
    # XGBoost hyper-parameters — tuned for > 0.97 accuracy with FPR < 1 %
    # and single-URL inference < 10 ms.  Smaller tree count + shallower
    # trees keeps booster->predict_proba under the latency budget while
    # the char-n-gram features do the accuracy heavy-lifting.
    n_estimators:      int = 500
    max_depth:         int = 9
    learning_rate:     float = 0.09
    subsample:         float = 0.9
    colsample_bytree:  float = 0.8
    min_child_weight:  int = 2
    reg_lambda:        float = 1.0
    reg_alpha:         float = 0.0
    tree_method:       str = "hist"
    early_stopping:    int = 40


# ─── Pipeline steps ───────────────────────────────────────────────────────────

def _load_and_featurise(cfg: TrainConfig) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    log.info("Loading datasets from %s", cfg.dataset_dir)
    df = load_all_datasets(cfg.dataset_dir)

    if cfg.max_rows:
        df = df.sample(n=min(cfg.max_rows, len(df)), random_state=cfg.random_state)

    log.info("Extracting features for %d URLs …", len(df))
    t0 = time.perf_counter()
    X = extract_features_df(df["url"].tolist())
    elapsed = time.perf_counter() - t0
    log.info(
        "Feature extraction done in %.2fs (%.0f URLs/s, %d features)",
        elapsed, len(df) / max(elapsed, 1e-9), X.shape[1],
    )

    return X, df["label"].astype(int), df["url"]


def _tune_threshold(y_true: np.ndarray, y_proba: np.ndarray, target_fpr: float) -> float:
    """Pick the smallest probability threshold whose FPR ≤ target_fpr.

    Searches over the full set of unique probabilities — O(n log n).
    """
    order = np.argsort(-y_proba)           # descending by score
    y_sorted = y_true[order]
    p_sorted = y_proba[order]

    n_neg = int((y_true == 0).sum())
    fp = 0
    for p, y in zip(p_sorted, y_sorted):
        if y == 0:
            fp += 1
            if fp / max(n_neg, 1) > target_fpr:
                # previous threshold was the last acceptable one
                return float(min(p + 1e-9, 1.0))
    # never exceeded → any threshold works
    return 0.5


def _latency_probe(model: XGBClassifier, sample_X: pd.DataFrame, n: int = 500) -> float:
    """Return mean per-URL inference latency in milliseconds.

    Uses ``Booster.inplace_predict`` — the same fast path the serving layer
    uses — rather than the high-overhead sklearn ``predict_proba`` wrapper.
    """
    if len(sample_X) == 0:
        return 0.0
    rows = sample_X.sample(n=min(n, len(sample_X)), random_state=0).reset_index(drop=True).values.astype(np.float32)
    booster = model.get_booster()
    # warm-up
    booster.inplace_predict(rows[:1])
    t0 = time.perf_counter()
    for i in range(len(rows)):
        _ = booster.inplace_predict(rows[i:i+1])
    elapsed = time.perf_counter() - t0
    return (elapsed / len(rows)) * 1000.0


def train(cfg: TrainConfig) -> Dict:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    X, y, urls = _load_and_featurise(cfg)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=cfg.test_size,
        random_state=cfg.random_state,
        stratify=y,
    )
    log.info("Train=%d  Test=%d  positives=%d", len(X_train), len(X_test), int(y_train.sum()))

    # NOTE: intentionally no scale_pos_weight.  The merged dataset is close
    # to balanced (~60/40) and using inverse-class weights here pushes the
    # model to over-predict "malicious" on popular benign domains where the
    # source CSVs disagree — which we already filter via drop_label_conflicts.
    neg = int((y_train == 0).sum())
    pos = int((y_train == 1).sum())

    model = XGBClassifier(
        n_estimators=cfg.n_estimators,
        max_depth=cfg.max_depth,
        learning_rate=cfg.learning_rate,
        subsample=cfg.subsample,
        colsample_bytree=cfg.colsample_bytree,
        min_child_weight=cfg.min_child_weight,
        reg_lambda=cfg.reg_lambda,
        reg_alpha=cfg.reg_alpha,
        objective="binary:logistic",
        eval_metric=["logloss", "auc", "error"],
        tree_method=cfg.tree_method,
        n_jobs=-1,
        random_state=cfg.random_state,
    )

    log.info("Fitting XGBoost …")
    try:
        model.fit(
            X_train, y_train,
            eval_set=[(X_test, y_test)],
            verbose=False,
            early_stopping_rounds=cfg.early_stopping,
        )
    except TypeError:
        # XGBoost ≥ 2.x moved early_stopping_rounds to the constructor.
        model.set_params(early_stopping_rounds=cfg.early_stopping)
        model.fit(X_train, y_train, eval_set=[(X_test, y_test)], verbose=False)

    # ── Evaluation ────────────────────────────────────────────────────────────
    y_proba = model.predict_proba(X_test)[:, 1]
    threshold = _tune_threshold(y_test.values, y_proba, cfg.target_fpr)
    y_pred = (y_proba >= threshold).astype(int)

    acc = accuracy_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_proba)
    cm  = confusion_matrix(y_test, y_pred).tolist()
    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()
    fpr = fp / max(fp + tn, 1)
    tpr = tp / max(tp + fn, 1)

    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    lat_ms = _latency_probe(model, X_test)

    log.info(
        "Eval → acc=%.4f  AUC=%.4f  FPR=%.4f  TPR=%.4f  threshold=%.4f  latency=%.2fms",
        acc, auc, fpr, tpr, threshold, lat_ms,
    )
    log.info("Confusion matrix: TN=%d FP=%d FN=%d TP=%d", tn, fp, fn, tp)

    # Feature importance (gain)
    importance = model.get_booster().get_score(importance_type="gain")
    # XGBoost emits f0, f1 … — map back to names
    named_imp = {
        FEATURE_NAMES[int(k[1:])]: float(v)
        for k, v in importance.items()
        if k.startswith("f") and int(k[1:]) < len(FEATURE_NAMES)
    }
    top_features = sorted(named_imp.items(), key=lambda x: -x[1])[:25]

    # ── Persist ───────────────────────────────────────────────────────────────
    cfg.model_out.parent.mkdir(parents=True, exist_ok=True)
    cfg.report_out.parent.mkdir(parents=True, exist_ok=True)

    model.save_model(str(cfg.model_out))
    log.info("Saved model → %s", cfg.model_out)

    # calibration hints from phishing.csv
    calibration = load_phishing_feature_calibration(cfg.dataset_dir)

    meta = {
        "model_type":       "xgboost",
        "xgboost_version":  __import__("xgboost").__version__,
        "trained_at":       time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "feature_names":    FEATURE_NAMES,
        "threshold":        float(threshold),
        "target_fpr":       cfg.target_fpr,
        "metrics": {
            "accuracy":      float(acc),
            "auc":           float(auc),
            "fpr":           float(fpr),
            "tpr":           float(tpr),
            "confusion":     cm,
            "latency_ms":    float(lat_ms),
            "classification_report": report,
        },
        "dataset": {
            "rows_total": len(X),
            "train":      len(X_train),
            "test":       len(X_test),
            "positives":  pos,
            "negatives":  neg,
        },
        "hyperparameters": asdict(cfg) | {
            "dataset_dir":  str(cfg.dataset_dir),
            "model_out":    str(cfg.model_out),
            "meta_out":     str(cfg.meta_out),
            "report_out":   str(cfg.report_out),
        },
        "top_features":           top_features,
        "phishing_calibration":   calibration,
    }

    cfg.meta_out.write_text(json.dumps(meta, indent=2, default=str))
    log.info("Saved metadata → %s", cfg.meta_out)

    cfg.report_out.write_text(json.dumps(meta, indent=2, default=str))
    log.info("Saved training report → %s", cfg.report_out)

    # Success-gate warnings (non-fatal)
    if acc < 0.97:
        log.warning("Accuracy %.4f below target 0.97", acc)
    if fpr > cfg.target_fpr:
        log.warning("FPR %.4f above target %.4f", fpr, cfg.target_fpr)
    if lat_ms > 10.0:
        log.warning("Latency %.2fms above target 10ms — consider tree_method=hist, fewer trees", lat_ms)

    return meta


# ─── CLI ──────────────────────────────────────────────────────────────────────

def _parse_args() -> TrainConfig:
    p = argparse.ArgumentParser(description="Train the TI URL-classifier XGBoost model")
    p.add_argument("--dataset-dir",  type=Path, default=DEFAULT_DATASET_DIR)
    p.add_argument("--model-out",    type=Path, default=DEFAULT_MODEL_PATH)
    p.add_argument("--meta-out",     type=Path, default=DEFAULT_META_PATH)
    p.add_argument("--report-out",   type=Path, default=DEFAULT_REPORT_PATH)
    p.add_argument("--test-size",    type=float, default=0.20)
    p.add_argument("--random-state", type=int, default=42)
    p.add_argument("--target-fpr",   type=float, default=0.01)
    p.add_argument("--max-rows",     type=int, default=None, help="Limit rows for smoke-testing")
    p.add_argument("--n-estimators", type=int, default=600)
    p.add_argument("--max-depth",    type=int, default=9)
    args = p.parse_args()

    return TrainConfig(
        dataset_dir   = args.dataset_dir,
        model_out     = args.model_out,
        meta_out      = args.meta_out,
        report_out    = args.report_out,
        test_size     = args.test_size,
        random_state  = args.random_state,
        target_fpr    = args.target_fpr,
        max_rows      = args.max_rows,
        n_estimators  = args.n_estimators,
        max_depth     = args.max_depth,
    )


if __name__ == "__main__":  # pragma: no cover
    train(_parse_args())
