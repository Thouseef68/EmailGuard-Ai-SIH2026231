"""
layers/text_structural/xgboost_model.py — XGBoost V3 structural classifier

45-feature schema (42 original + 3 ratio features added in V3):
    email_length, header_length, body_length, subject_length,
    subject_word_count, subject_exclamation_count, subject_question_count,
    subject_uppercase_ratio, from_present, to_present, cc_present,
    bcc_present, reply_to_present, date_present, message_id_present,
    from_count, to_count, cc_count, bcc_count, received_count,
    return_path_present, authentication_results_present,
    dkim_signature_present, spf_present, mime_version_present,
    content_type_present, multipart, attachment_count, body_url_count,
    unique_domain_count, http_url_count, https_url_count, html_present,
    plain_text_present, body_exclamation_count, body_question_count,
    body_uppercase_ratio, urgent_word_count, money_word_count,
    credential_word_count, login_word_count, verify_word_count,
    https_ratio, url_per_kb, dom_per_url

V3 changes:
    - credential_word_count: removed "login","account","username" (too broad)
    - 3 new ratio features: https_ratio, url_per_kb, dom_per_url
    - uses extract_xgb_features() from eml_parser — no duplicate logic
"""

import json
import numpy as np
import xgboost as xgb

import config
from core.eml_parser import ParsedEmail, extract_xgb_features


class XGBoostEngine:
    """Loads once via .load(), then call .predict(parsed, raw_str) -> float."""

    def __init__(self):
        self.model        = None
        self.feature_cols = None
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

        self._loaded = True
        print(f"[xgboost] ready — {len(self.feature_cols)} features.")

    def predict(self, parsed: ParsedEmail, raw_str: str) -> float:
        """Returns phishing probability (0–1)."""
        if not self._loaded:
            self.load()

        feat = extract_xgb_features(parsed, raw_str)
        arr  = np.array([[feat.get(col, 0) for col in self.feature_cols]], dtype=float)
        dmat = xgb.DMatrix(arr, feature_names=self.feature_cols)
        return float(self.model.predict(dmat)[0])