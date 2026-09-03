import config

def fuse(deberta_prob: float, xgb_prob: float) -> dict:

    # XGBoost known weakness: confidently wrong on modern legit emails
    # When DeBERTa is very sure it's legit, trust DeBERTa
    if deberta_prob < 0.10 and xgb_prob > config.VETO_HIGH:
        fused_prob = deberta_prob * 0.8 + xgb_prob * 0.2  # lean heavily on DeBERTa
        return {
            "fused_probability": round(fused_prob, 4),
            "status": "AUTO_DECIDED",
            "verdict": "LEGITIMATE" if fused_prob < 0.5 else "PHISHING",
        }

    strong_disagree = (
        (xgb_prob > config.VETO_HIGH and deberta_prob < config.VETO_LOW) or
        (deberta_prob > config.VETO_HIGH and xgb_prob < config.VETO_LOW)
    )

    fused_prob = config.W_DEBERTA * deberta_prob + config.W_XGB * xgb_prob

    if strong_disagree:
        status  = "HIGH_DISAGREEMENT_REVIEW"
        verdict = "NEEDS_HUMAN_REVIEW"
    elif config.HITL_LOW <= fused_prob <= config.HITL_HIGH:
        status  = "HITL_QUEUE"
        verdict = "UNCERTAIN_NEEDS_REVIEW"
    else:
        status  = "AUTO_DECIDED"
        verdict = "PHISHING" if fused_prob >= 0.5 else "LEGITIMATE"

    return {
        "fused_probability": round(fused_prob, 4),
        "status":  status,
        "verdict": verdict,
    }