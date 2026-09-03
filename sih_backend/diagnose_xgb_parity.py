"""
diagnose_xgb_parity.py — find the FIRST XGBoost value that diverges from Kaggle

Run this on the SAME .eml file, in BOTH local and Kaggle environments.
Compare printed values top to bottom — the first line that differs is the
actual bug location.

Usage:
    python diagnose_xgb_parity.py "path/to/some_email.eml"
"""

import sys
import os
import json
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import xgboost as xgb

import config
from core.eml_parser import parse_eml
from layers.text_structural.xgboost_model import build_xgb_features


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192 * 1024):
            h.update(chunk)
    return h.hexdigest()[:16]


def main(eml_path):
    print("=" * 90)
    print("XGBOOST V2 PARITY DIAGNOSTIC")
    print("=" * 90)

    # ── 0. File integrity checks ─────────────────────────────────────────
    print("\n--- 0. FILE CHECKSUMS ---")
    print(f"xgboost_phishing_v2.json sha256[:16]      : {sha256_of_file(config.XGB_MODEL_PATH)}")
    print(f"xgboost_phishing_v2.json size (bytes)      : {os.path.getsize(config.XGB_MODEL_PATH)}")
    print(f"xgboost_feature_cols_v2.json sha256[:16]   : {sha256_of_file(config.XGB_FEATURES_PATH)}")

    with open(eml_path, "rb") as f:
        eml_bytes = f.read()
    print(f"\nInput .eml sha256[:16]: {hashlib.sha256(eml_bytes).hexdigest()[:16]}")
    print(f"Input .eml size: {len(eml_bytes)} bytes")

    parsed = parse_eml(eml_bytes)

    # ── 1. Parsed email summary (body extraction sanity) ────────────────
    print("\n--- 1. PARSED EMAIL SUMMARY ---")
    print(f"  subject             : {parsed.subject!r}")
    print(f"  from_addr           : {parsed.from_addr!r}")
    print(f"  body_text length    : {len(parsed.body_text)}")
    print(f"  body_text checksum  : {hashlib.sha256(parsed.body_text.encode('utf-8', errors='ignore')).hexdigest()[:16]}")
    print(f"  header_block_text length : {len(parsed.header_block_text)}")
    print(f"  total_email_length  : {parsed.total_email_length}")
    print(f"  is_multipart        : {parsed.is_multipart}")
    print(f"  has_html / has_plain: {parsed.has_html} / {parsed.has_plain}")
    print(f"  received_headers count: {len(parsed.received_headers)}")
    print(f"  attachment_count    : {parsed.attachment_count}")

    # ── 2. Feature column order ──────────────────────────────────────────
    print("\n--- 2. FEATURE COLUMN ORDER (from xgboost_feature_cols_v2.json) ---")
    with open(config.XGB_FEATURES_PATH) as f:
        feat_data = json.load(f)
    feature_cols = feat_data["features"] if isinstance(feat_data, dict) else feat_data
    print(f"  feature_count: {len(feature_cols)}")
    print(f"  order: {feature_cols}")

    # ── 3. All 42 raw feature values ─────────────────────────────────────
    print("\n--- 3. RAW 42 FEATURE VALUES ---")
    features = build_xgb_features(parsed, feature_cols)
    for name, val in zip(feature_cols, features[0]):
        print(f"  {name:<32} = {val}")

    # ── 4. DMatrix summary ───────────────────────────────────────────────
    print("\n--- 4. DMATRIX ---")
    dmat = xgb.DMatrix(features, feature_names=feature_cols)
    print(f"  DMatrix shape: ({dmat.num_row()}, {dmat.num_col()})")
    feat_checksum = hashlib.sha256(features.astype(np.float64).tobytes()).hexdigest()[:16]
    print(f"  feature vector checksum: {feat_checksum}")

    # ── 5. Model load + prediction ───────────────────────────────────────
    print("\n--- 5. MODEL PREDICTION ---")
    model = xgb.Booster()
    model.load_model(config.XGB_MODEL_PATH)
    pred = model.predict(dmat)
    print(f"  raw prediction: {float(pred[0]):.8f}")
    print(f"  xgboost version: {xgb.__version__}")

    print("\n" + "=" * 90)
    print("DIAGNOSTIC COMPLETE — run this same script on Kaggle and diff line by line")
    print("=" * 90)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python diagnose_xgb_parity.py path/to/email.eml")
        sys.exit(1)
    main(sys.argv[1])
