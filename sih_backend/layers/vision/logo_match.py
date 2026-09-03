# layers/vision/logo_match.py
"""
Brand logo spoofing detection via OCR text matching.
Imports BRAND_DOMAIN_MAP from config — single source of truth.
"""
from typing import List, Dict, Any
from config import BRAND_DOMAIN_MAP


def detect_brand_spoofing(
    ocr_texts: List[str],
    sender_domain: str,
) -> Dict[str, Any]:
    combined = " ".join(ocr_texts).lower()
    sender   = sender_domain.lower().strip()

    detected: List[Dict[str, Any]] = []
    spoofing_brands: List[str] = []

    for brand_keyword, trusted_domains in BRAND_DOMAIN_MAP.items():
        if brand_keyword.lower() not in combined:
            continue

        domain_ok = any(
            sender == td or sender.endswith("." + td)
            for td in trusted_domains
        )
        entry = {
            "brand":           brand_keyword,
            "trusted_domains": trusted_domains,
            "sender_domain":   sender,
            "domain_matches":  domain_ok,
            "spoofing":        not domain_ok,
        }
        detected.append(entry)
        if not domain_ok and sender:
            spoofing_brands.append(brand_keyword)

    return {
        "detected_brands":  detected,
        "spoofing_detected":len(spoofing_brands) > 0,
        "spoofing_brands":  spoofing_brands,
    }