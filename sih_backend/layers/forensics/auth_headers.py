# layers/forensics/auth_headers.py
"""
SPF/DKIM/DMARC detailed analysis — goes beyond pass/fail to explain
WHY authentication failed and what it means for phishing risk.
"""

from core.eml_parser import ParsedEmail


def run(parsed: ParsedEmail) -> dict:
    findings = []
    score    = 0

    # ── SPF ────────────────────────────────────────────────────────────────
    spf = parsed.spf.lower()
    if spf == "pass":
        findings.append({"check": "SPF", "result": "pass",
                         "meaning": "Sending server is authorized to send for this domain"})
    elif spf == "fail":
        findings.append({"check": "SPF", "result": "fail",
                         "meaning": "Sending server is NOT authorized — high phishing risk"})
        score += 3
    elif spf == "softfail":
        findings.append({"check": "SPF", "result": "softfail",
                         "meaning": "Sending server is suspicious — domain owner is uncertain"})
        score += 2
    elif spf == "neutral":
        findings.append({"check": "SPF", "result": "neutral",
                         "meaning": "Domain owner has not declared SPF policy"})
        score += 1
    else:
        findings.append({"check": "SPF", "result": "none",
                         "meaning": "No SPF record found — sender domain unverified"})
        score += 1

    # ── DKIM ───────────────────────────────────────────────────────────────
    dkim = parsed.dkim.lower()
    if dkim == "pass":
        findings.append({"check": "DKIM", "result": "pass",
                         "meaning": "Email content is intact and cryptographically verified"})
    elif dkim == "fail":
        findings.append({"check": "DKIM", "result": "fail",
                         "meaning": "Email content was tampered after sending — very high risk"})
        score += 4
    elif dkim == "none":
        findings.append({"check": "DKIM", "result": "none",
                         "meaning": "No DKIM signature — content integrity unverified"})
        score += 1

    # ── DMARC ──────────────────────────────────────────────────────────────
    dmarc = parsed.dmarc.lower()
    if dmarc == "pass":
        findings.append({"check": "DMARC", "result": "pass",
                         "meaning": "SPF and DKIM align with From domain — trusted sender"})
    elif dmarc == "fail":
        findings.append({"check": "DMARC", "result": "fail",
                         "meaning": "From domain does not align with SPF/DKIM — spoofed sender"})
        score += 4
    elif dmarc == "none":
        findings.append({"check": "DMARC", "result": "none",
                         "meaning": "No DMARC policy — domain allows spoofing"})
        score += 1

    # ── Self-registered domain detection ───────────────────────────────────
    # SPF+DMARC pass but DKIM none = self-registered domain (own records validate)
    if spf == "pass" and dmarc == "pass" and dkim == "none":
        findings.append({
            "check":   "SELF_REGISTERED_DOMAIN",
            "result":  "warning",
            "meaning": "SPF/DMARC pass but no DKIM — likely self-registered disposable domain"
        })
        score += 2

    # ── Overall verdict ────────────────────────────────────────────────────
    if score == 0:   risk = "trusted"
    elif score <= 2: risk = "low"
    elif score <= 4: risk = "medium"
    else:            risk = "high"

    return {
        "verdict":  risk,
        "score":    score,
        "findings": findings,
    }