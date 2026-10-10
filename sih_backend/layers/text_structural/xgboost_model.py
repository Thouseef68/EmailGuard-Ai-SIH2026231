"""
layers/text_structural/xgboost_model.py — XGBoost V4-Clean structural classifier

20 features, produced by eml_feature_extractor_v4.extract_v4_features().
The feature names come from xgboost_v4_clean_feature_cols.json and must all be
produced by that extractor. If they are not, predict() raises instead of
quietly feeding zeros to the model (which is what hid the V3 -> V4 mismatch).
"""

import json
import numpy as np
import xgboost as xgb

import config
from core.eml_parser import ParsedEmail
from .eml_feature_extractor_v4 import extract_v4_features, FEATURE_COLS as V4_COLS


class XGBoostEngine:
    """Loads once via .load(), then call .predict(parsed, raw_str) -> float."""

    def __init__(self):
        self.model        = None
        self.feature_cols = None
        self.schema_error = None
        self._loaded      = False

    def load(self):
        if self._loaded:
            return
        print(f"[xgboost] loading model from {config.XGB_MODEL_PATH} ...")
        self.model = xgb.Booster()
        self.model.load_model(config.XGB_MODEL_PATH)

        with open(config.XGB_FEATURES_PATH) as f:
            feat_data = json.load(f)
        self.feature_cols = feat_data["features"] if isinstance(feat_data, dict) else feat_data

        missing = [c for c in self.feature_cols if c not in V4_COLS]
        if missing:
            self.schema_error = f"model expects features the V4 extractor does not produce: {missing}"
            print(f"[xgboost] SCHEMA MISMATCH - {self.schema_error}")

        self._loaded = True
        print(f"[xgboost] ready — {len(self.feature_cols)} features.")

    def predict(self, parsed: ParsedEmail, raw_str: str = "") -> float:
        """Returns phishing probability (0-1). raw_str is kept for call compatibility."""
        if not self._loaded:
            self.load()
        if self.schema_error:
            raise RuntimeError(self.schema_error)

        feat = extract_v4_features(parsed)
        arr  = np.array([[feat[col] for col in self.feature_cols]], dtype=float)
        dmat = xgb.DMatrix(arr, feature_names=self.feature_cols)
        return float(self.model.predict(dmat)[0])