# layers/nlp_extra/zero_shot_intent.py
"""
Zero-shot NLI intent classifier — no fine-tuning needed.
Classifies email into 6 phishing intent categories using
cross-encoder/nli-deberta-v3-small.
"""

import torch
from transformers import pipeline
from core.eml_parser import ParsedEmail

INTENT_LABELS = [
    "This email is trying to steal login credentials, passwords, OTP or PIN",
    "This email is attempting financial fraud, fake refund, or requesting money transfer",
    "This email claims an account has been suspended or locked urgently",
    "This email contains malware, malicious links or dangerous attachments",
    "This email is trying to steal personal identity information like Aadhaar or PAN",
    "This email is unsolicited spam, advertisement or adult content",
    "This email is a normal legitimate transactional or informational message",
]

_SHORT_NAMES = [
    "credential theft",
    "financial fraud",
    "account suspension",
    "malware delivery",
    "identity theft",
    "spam or advertisement",
    "legitimate email",
]

_classifier = None

def _load():
    global _classifier
    if _classifier is None:
        print("[zero_shot_intent] loading model...")
        _classifier = pipeline(
            "zero-shot-classification",
            model="cross-encoder/nli-deberta-v3-small",
            device=0 if torch.cuda.is_available() else -1,
        )
        print("[zero_shot_intent] ready.")

def run(parsed: ParsedEmail) -> dict:
    _load()
    text = f"Subject: {parsed.subject}\n\n{parsed.body_text}"[:1024]
    result = _classifier(text, INTENT_LABELS, multi_label=False)

    # Map back to short names
    label_map = dict(zip(INTENT_LABELS, _SHORT_NAMES))
    top_label = label_map[result["labels"][0]]
    top_score = result["scores"][0]

    return {
        "top_intent":  top_label,
        "confidence":  round(top_score, 4),
        "is_phishing": top_label not in ("legitimate email", "spam or advertisement"),
        "is_spam":     top_label == "spam or advertisement",
        "all_intents": [
            {"label": label_map[l], "score": round(s, 4)}
            for l, s in zip(result["labels"], result["scores"])
        ],
    }