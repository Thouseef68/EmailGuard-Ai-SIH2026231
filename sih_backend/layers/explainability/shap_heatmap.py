# layers/explainability/shap_heatmap.py
"""
SHAP explainability for XGBoost — shows which structural features
pushed the verdict toward PHISHING or LEGITIMATE.
"""

import json
import numpy as np
import shap
import xgboost as xgb
import pandas as pd

import config
from core.eml_parser import ParsedEmail, extract_xgb_features

_model        = None
_explainer    = None
_feature_cols = None


# replace _load() only

def _load():
    global _model, _explainer, _feature_cols
    if _explainer is not None:
        return

    print("[shap] loading model...")
    with open(config.XGB_FEATURES_PATH) as f:
        _feature_cols = json.load(f)["features"]

    _model = xgb.XGBClassifier()
    _model.load_model(config.XGB_MODEL_PATH)

    # Fix: patch base_score before passing to SHAP
    booster = _model.get_booster()
    config_str = booster.save_config()
    import json as _json
    cfg = _json.loads(config_str)
    # Force base_score to plain float string
    cfg["learner"]["learner_model_param"]["base_score"] = "0.5"
    booster.load_config(_json.dumps(cfg))

    _explainer = shap.TreeExplainer(booster)
    print("[shap] ready.")


def run(parsed: ParsedEmail, raw_str: str) -> dict:
    _load()

    feat = extract_xgb_features(parsed, raw_str)
    df   = pd.DataFrame([{c: feat.get(c, 0) for c in _feature_cols}])

    shap_values = _explainer(df)
    sv = shap_values.values[0]   # per-sample SHAP values

    # Positive = pushes toward phishing, negative = pushes toward legitimate
    pairs = sorted(zip(_feature_cols, sv), key=lambda x: abs(x[1]), reverse=True)

    top = []
    for name, value in pairs[:10]:
        top.append({
            "feature":    name,
            "shap_value": round(float(value), 4),
            "direction":  "phishing" if value > 0 else "legitimate",
            "raw_value":  round(float(feat.get(name, 0)), 4),
        })

    summary = []
    for t in top[:3]:
        direction = "raised" if t["direction"] == "phishing" else "lowered"
        summary.append(
            f"'{t['feature']}' = {t['raw_value']} {direction} phishing suspicion"
        )

    return {
        "top_features": top,
        "summary":      summary,
        "base_value":   round(float(shap_values.base_values[0]), 4),
    }