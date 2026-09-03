"""
layers/text_structural — the locked, working core (Phase 2/3/4 complete).

run(parsed, raw_str) returns the full text_structural section of the report:
    {
        "deberta": {"probability":..., "verdict":...},
        "xgboost": {"probability":..., "verdict":...},
        "fusion": {"fused_probability":..., "status":..., "verdict":...},
        "agreement": bool,
    }
"""

from core.eml_parser import ParsedEmail
from .deberta_model import DebertaEngine
from .xgboost_model import XGBoostEngine
from .fusion_gate import fuse

NAME = "text_structural"

_deberta_engine = DebertaEngine()
_xgb_engine     = XGBoostEngine()


def load():
    _deberta_engine.load()
    _xgb_engine.load()


def run(parsed: ParsedEmail, raw_str: str = "") -> dict:
    deberta_prob = _deberta_engine.predict(parsed)
    xgb_prob     = _xgb_engine.predict(parsed, raw_str)

    deberta_verdict = "PHISHING" if deberta_prob >= 0.5 else "LEGITIMATE"
    xgb_verdict     = "PHISHING" if xgb_prob     >= 0.5 else "LEGITIMATE"

    fusion_result = fuse(deberta_prob, xgb_prob)

    return {
        "deberta": {"probability": round(deberta_prob, 4), "verdict": deberta_verdict},
        "xgboost": {"probability": round(xgb_prob,     4), "verdict": xgb_verdict},
        "fusion":  fusion_result,
        "agreement": deberta_verdict == xgb_verdict,
    }