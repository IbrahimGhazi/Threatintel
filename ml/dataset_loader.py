"""
Dataset loader for the URL Intelligence Engine.

Loads the four URL datasets that ship with the TI platform, normalises their
schemas to a common `(url, label)` shape, merges them, deduplicates, and
cleans the URLs.

Source datasets (expected at ``ti-platform/URL_dataset/`` on the server):

  * balanced_urls.csv        columns: url,label,result       (0 benign / 1 malicious)
  * malicious_phish.csv      columns: url,type               (benign / phishing / defacement / malware)
  * phishing_site_urls.csv   columns: URL,Label              (good / bad)
  * phishing.csv             engineered boolean features     (used to calibrate
                             the hand-crafted suspicious-indicator weights in
                             feature_extractor.py; NOT merged into url+label).

Public API
----------
    load_all_datasets(root: Path) -> pandas.DataFrame
    load_phishing_feature_calibration(root: Path) -> dict

The returned DataFrame has exactly two columns: ``url`` (str) and ``label``
(int, 0 = benign, 1 = malicious).
"""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Dict, Optional

import pandas as pd

log = logging.getLogger("ti.ml.dataset_loader")

# ─── Constants ────────────────────────────────────────────────────────────────

DEFAULT_DATASET_DIR = Path(
    os.environ.get("TI_URL_DATASET_DIR", "URL_dataset")
).expanduser()

BALANCED_FILE       = "balanced_urls.csv"
MALICIOUS_PHISH     = "malicious_phish.csv"
PHISHING_SITE_URLS  = "phishing_site_urls.csv"
PHISHING_FEATURES   = "phishing.csv"

# malicious_phish.csv label mapping
_MPHISH_LABEL_MAP = {
    "benign":     0,
    "phishing":   1,
    "defacement": 1,
    "malware":    1,
}

# phishing_site_urls.csv label mapping
_PSU_LABEL_MAP = {
    "good": 0,
    "bad":  1,
}

# balanced_urls.csv label mapping (both the `label` text column and the
# `result` int column carry the target; we prefer `result` if present).
_BALANCED_LABEL_MAP = {
    "benign":    0,
    "malicious": 1,
}

# Strip control chars / whitespace from URLs
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _read_csv(path: Path) -> pd.DataFrame:
    """Tolerant CSV reader.  Falls back to latin-1 if utf-8 fails."""
    try:
        return pd.read_csv(path, low_memory=False)
    except UnicodeDecodeError:
        log.warning("UTF-8 decode failed for %s, retrying as latin-1", path)
        return pd.read_csv(path, low_memory=False, encoding="latin-1")


def _clean_url(url: object) -> Optional[str]:
    """Normalise a raw URL string.

    * strips whitespace / control chars
    * lowercases the scheme + host portion (path remains case-sensitive)
    * rejects anything that is clearly not a URL/domain
    """
    if not isinstance(url, str):
        return None
    s = _CONTROL_RE.sub("", url).strip().strip('"').strip("'")
    if not s or len(s) < 4 or len(s) > 2048:
        return None
    # Lowercase scheme + authority for better dedup, keep path casing.
    if "://" in s:
        scheme, rest = s.split("://", 1)
        if "/" in rest:
            host, path = rest.split("/", 1)
            s = f"{scheme.lower()}://{host.lower()}/{path}"
        else:
            s = f"{scheme.lower()}://{rest.lower()}"
    else:
        # bare domain / host+path
        if "/" in s:
            host, path = s.split("/", 1)
            s = f"{host.lower()}/{path}"
        else:
            s = s.lower()
    return s


# ─── Per-dataset loaders ──────────────────────────────────────────────────────

def _load_balanced(path: Path) -> pd.DataFrame:
    df = _read_csv(path)
    # prefer the already-numeric `result` column
    if "result" in df.columns:
        labels = pd.to_numeric(df["result"], errors="coerce")
    elif "label" in df.columns:
        labels = (
            df["label"].astype(str).str.strip().str.lower()
            .map(_BALANCED_LABEL_MAP)
        )
    else:
        raise ValueError(f"{path.name}: neither 'result' nor 'label' column found")

    if "url" not in df.columns:
        raise ValueError(f"{path.name}: missing required 'url' column")

    out = pd.DataFrame({"url": df["url"].astype(str), "label": labels})
    return out.dropna()


def _load_malicious_phish(path: Path) -> pd.DataFrame:
    df = _read_csv(path)
    if "url" not in df.columns or "type" not in df.columns:
        raise ValueError(f"{path.name}: expected columns url,type")

    labels = (
        df["type"].astype(str).str.strip().str.lower()
        .map(_MPHISH_LABEL_MAP)
    )
    out = pd.DataFrame({"url": df["url"].astype(str), "label": labels})
    return out.dropna()


def _load_phishing_site_urls(path: Path) -> pd.DataFrame:
    df = _read_csv(path)
    # header may be URL/Label or url/label
    cols = {c.lower(): c for c in df.columns}
    url_col   = cols.get("url")
    label_col = cols.get("label")
    if url_col is None or label_col is None:
        raise ValueError(f"{path.name}: expected columns URL,Label")

    labels = (
        df[label_col].astype(str).str.strip().str.lower()
        .map(_PSU_LABEL_MAP)
    )
    out = pd.DataFrame({"url": df[url_col].astype(str), "label": labels})
    return out.dropna()


# ─── Public API ───────────────────────────────────────────────────────────────

def _canonical(u: str) -> str:
    """Collapse ``https://www.Google.com/`` and ``google.com`` to the same key."""
    if not isinstance(u, str):
        return ""
    s = u.strip().lower()
    for pref in ("https://", "http://", "ftp://"):
        if s.startswith(pref):
            s = s[len(pref):]
            break
    if s.startswith("www."):
        s = s[4:]
    return s.rstrip("/")


def load_all_datasets(
    root: Path = DEFAULT_DATASET_DIR,
    drop_duplicates: bool = True,
    drop_label_conflicts: bool = True,
) -> pd.DataFrame:
    """Load, normalise, merge and clean the three URL+label datasets.

    The ``phishing.csv`` engineered-feature file is intentionally excluded
    from the training labels — it has no raw URLs — and is instead used by
    :func:`load_phishing_feature_calibration` to tune the hand-crafted
    suspicious-indicator weights used inside the feature extractor.

    Parameters
    ----------
    root:
        Directory that contains the four CSV files.
    drop_duplicates:
        Deduplicate on the ``url`` column.  If both benign and malicious
        labels exist for the same URL (should be rare), the malicious
        label wins — conservative for a security detector.
    """
    root = Path(root)
    if not root.is_dir():
        raise FileNotFoundError(f"Dataset directory does not exist: {root}")

    frames = []
    for name, loader in (
        (BALANCED_FILE,      _load_balanced),
        (MALICIOUS_PHISH,    _load_malicious_phish),
        (PHISHING_SITE_URLS, _load_phishing_site_urls),
    ):
        p = root / name
        if not p.is_file():
            log.warning("Dataset file missing, skipping: %s", p)
            continue
        try:
            df = loader(p)
        except Exception as exc:
            log.error("Failed to load %s: %s", p, exc)
            continue
        df["source"] = name
        frames.append(df)
        log.info("Loaded %s: %d rows", name, len(df))

    if not frames:
        raise RuntimeError(f"No datasets could be loaded from {root}")

    merged = pd.concat(frames, ignore_index=True)

    # Clean URLs
    merged["url"] = merged["url"].map(_clean_url)
    merged = merged.dropna(subset=["url"])
    merged["label"] = merged["label"].astype(int)
    merged = merged[merged["label"].isin([0, 1])]

    # Canonicalise URLs to match the form real inference traffic arrives in
    # (bare host + path, no scheme, no www.).  This removes training-vs-
    # inference skew where `https://www.google.com` in training and
    # `google.com` at inference otherwise produce different feature vectors
    # and different char-n-gram hashes.
    merged["url"] = merged["url"].map(_canonical)
    merged = merged[merged["url"].astype(bool)]

    if drop_label_conflicts:
        # Any URL that appears with both labels (across or within source
        # datasets after canonicalisation) is almost certainly noise —
        # drop ALL rows for it.
        distinct_labels = merged.groupby("url")["label"].nunique()
        conflicts = set(distinct_labels[distinct_labels > 1].index)
        if conflicts:
            before = len(merged)
            merged = merged[~merged["url"].isin(conflicts)]
            log.info(
                "Dropped %d rows across %d conflicting canonical URLs (kept %d)",
                before - len(merged), len(conflicts), len(merged),
            )

    if drop_duplicates:
        merged = (
            merged.drop_duplicates(subset=["url"], keep="first")
            .reset_index(drop=True)
        )

    log.info(
        "Merged dataset: %d rows  (benign=%d, malicious=%d)",
        len(merged),
        int((merged["label"] == 0).sum()),
        int((merged["label"] == 1).sum()),
    )
    return merged[["url", "label", "source"]]


def load_phishing_feature_calibration(
    root: Path = DEFAULT_DATASET_DIR,
) -> Dict[str, float]:
    """Compute per-feature mean values from ``phishing.csv``.

    The file contains engineered boolean/ternary features for known phishing
    samples.  We use the mean of each column as a *weight hint* for the
    corresponding hand-crafted feature inside the feature extractor
    (``contains_login``, ``using_ip``, ``long_url`` …).  Features that never
    appear in phishing get near-zero weight; features that appear in every
    phishing sample get weight ≈ 1.

    Returns a mapping ``{feature_name_snake: weight}``.
    """
    p = Path(root) / PHISHING_FEATURES
    if not p.is_file():
        log.warning("phishing.csv calibration file not found: %s", p)
        return {}

    df = _read_csv(p)

    # Restrict to the phishing class if a class/Result column is present
    class_col = None
    for cand in ("class", "Result", "result", "label", "Label"):
        if cand in df.columns:
            class_col = cand
            break
    if class_col is not None:
        # Phishing is typically encoded as -1 or 1; keep only the positive class
        mal = df[df[class_col].isin([1, "1", "phishing", "bad"])]
        if len(mal) == 0:  # try -1 convention
            mal = df[df[class_col].isin([-1, "-1"])]
        if len(mal) > 0:
            df = mal

    weights: Dict[str, float] = {}
    for col in df.columns:
        if col == class_col:
            continue
        series = pd.to_numeric(df[col], errors="coerce").dropna()
        if len(series) == 0:
            continue
        # Features are typically in {-1, 0, 1}.  Normalise to [0, 1].
        mn, mx = series.min(), series.max()
        if mx - mn > 0:
            norm = (series - mn) / (mx - mn)
        else:
            norm = series * 0
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", col).lower()
        weights[snake] = float(norm.mean())
    return weights


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":  # pragma: no cover
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    ap = argparse.ArgumentParser(description="Merge and inspect URL datasets")
    ap.add_argument("--root", default=str(DEFAULT_DATASET_DIR))
    ap.add_argument("--out",  default=None, help="Optional path to write merged CSV")
    args = ap.parse_args()

    df = load_all_datasets(Path(args.root))
    print(df.head())
    print(df["label"].value_counts())
    print(df["source"].value_counts())

    if args.out:
        df.to_csv(args.out, index=False)
        print(f"Wrote merged dataset to {args.out}")
