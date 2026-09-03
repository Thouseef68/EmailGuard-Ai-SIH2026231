# layers/forensics/address_mismatch.py
"""
Address mismatch detection:
- Reply-To hijack
- Return-Path domain mismatch
- Display name spoofing (brand name in display name, wrong actual domain)
"""
from core.eml_parser import ParsedEmail
from config import BRAND_DOMAIN_MAP


def _domain_matches_brand(display_name: str, actual_domain: str) -> bool:
    """
    Check if display name mentions a known brand
    but the actual sending domain is not that brand's trusted domain.
    Returns True if spoofing is suspected.
    """
    name_lower = display_name.lower()
    domain_lower = actual_domain.lower()

    for brand, trusted_domains in BRAND_DOMAIN_MAP.items():
        if brand.lower() in name_lower:
            # Brand name found in display name
            domain_ok = any(
                domain_lower == td or domain_lower.endswith("." + td)
                for td in trusted_domains
            )
            if not domain_ok:
                return True   # spoofing detected
    return False


def run(parsed: ParsedEmail) -> dict:
    findings = []
    score    = 0
    verdict  = "none"

    # ── Check 1: Reply-To hijack ──────────────────────────────────────────
    if parsed.reply_to_addr and parsed.reply_to_domain:
        if parsed.reply_to_domain.lower() != parsed.from_domain.lower():
            findings.append({
                "check":   "REPLY_TO_HIJACK",
                "result":  "high",
                "from":    parsed.from_domain,
                "reply_to":parsed.reply_to_domain,
                "meaning": (
                    f"Reply-To domain ({parsed.reply_to_domain}) differs from "
                    f"From domain ({parsed.from_domain}) — replies go to attacker"
                ),
            })
            score += 3

    # ── Check 2: Return-Path mismatch ────────────────────────────────────
    if parsed.return_path_addr and parsed.return_path_domain:
        if parsed.return_path_domain.lower() != parsed.from_domain.lower():
            # Subdomains of the same brand are acceptable
            # e.g. deskservice-mailer.unionbankcrm.bank.in vs unionbankcrm.bank.in
            from_parts   = parsed.from_domain.lower().split(".")
            rp_parts     = parsed.return_path_domain.lower().split(".")
            # Check if they share the same root domain (last 2-3 parts)
            same_root    = from_parts[-2:] == rp_parts[-2:]
            if not same_root:
                findings.append({
                    "check":       "RETURN_PATH_MISMATCH",
                    "result":      "medium",
                    "from":        parsed.from_domain,
                    "return_path": parsed.return_path_domain,
                    "meaning":     "Bounce emails go to a different domain — possible spoofing",
                })
                score += 1

    # ── Check 3: Display name spoofing ────────────────────────────────────
    display_name = ""
    if parsed.from_addr and "<" in parsed.from_addr:
        # Extract display name: "HDFC Bank <alerts@hdfcbank.com>"
        display_name = parsed.from_addr.split("<")[0].strip().strip('"')

    if display_name and parsed.from_domain:
        if _domain_matches_brand(display_name, parsed.from_domain):
            findings.append({
                "check":   "DISPLAY_NAME_SPOOFING",
                "result":  "high",
                "display": display_name,
                "domain":  parsed.from_domain,
                "meaning": (
                    f"Display name '{display_name}' claims to be a known brand "
                    f"but actual domain '{parsed.from_domain}' is not trusted"
                ),
            })
            score += 4

    # ── Verdict ───────────────────────────────────────────────────────────
    if score >= 4:
        verdict = "high"
    elif score >= 2:
        verdict = "medium"
    elif score >= 1:
        verdict = "low"
    else:
        verdict = "none"

    return {
        "verdict":  verdict,
        "score":    score,
        "findings": findings,
    }