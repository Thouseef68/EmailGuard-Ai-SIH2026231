# layers/nlp_extra/pii_masking.py
"""
DPDP Act 2023 PII masking — strips Aadhaar, PAN, phone, email addresses
from report output before display. Original content untouched in parser.
"""

import re

# ── PII patterns (Indian-specific) ────────────────────────────────────────
_PATTERNS = [
    # ── Card FIRST (before Aadhaar to avoid overlap) ──────────────────────
    (r'\b4[0-9]{3}\s[0-9]{4}\s[0-9]{4}\s[0-9]{4}\b',     "[CARD REDACTED]"),  # Visa
    (r'\b5[1-5][0-9]{2}\s[0-9]{4}\s[0-9]{4}\s[0-9]{4}\b', "[CARD REDACTED]"),  # Mastercard
    # ── Aadhaar — starts with 2-9, never 0 or 1 ───────────────────────────
    (r'\b[2-9]{1}[0-9]{3}\s[0-9]{4}\s[0-9]{4}\b',         "[AADHAAR REDACTED]"),
    (r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b',                      "[PAN REDACTED]"),
    (r'\b[6-9]\d{9}\b',                                     "[PHONE REDACTED]"),
    (r'[\w\.-]+@[\w\.-]+\.\w{2,4}',                        "[EMAIL REDACTED]"),
    (r'\b\d{2}/\d{2}/\d{4}\b',                             "[DOB REDACTED]"),
    (r'(?i)\b(account\s*no|a\/c|acct)[:\s#]*\d{9,18}\b',  "[ACCOUNT REDACTED]"),
    (r'(?i)(ifsc|IFSC)[:\s]*[A-Z]{4}0[A-Z0-9]{6}',        "[IFSC REDACTED]"),
]
def mask(text: str) -> str:
    """Replace all PII in text with redacted placeholders."""
    for pattern, replacement in _PATTERNS:
        text = re.sub(pattern, replacement, text)
    return text

def mask_report(report: dict) -> dict:
    """
    Recursively mask PII in a report dict before sending to frontend.
    Operates on a copy — does not modify the original.
    """
    import copy
    report = copy.deepcopy(report)

    def _recurse(obj):
        if isinstance(obj, str):
            return mask(obj)
        if isinstance(obj, dict):
            return {k: _recurse(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [_recurse(i) for i in obj]
        return obj

    return _recurse(report)