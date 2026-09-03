# layers/forensics/whois_lookup.py
"""
WHOIS domain age lookup — newly registered domains are high phishing risk.
Domains < 30 days old = high risk, < 180 days = medium risk.
"""

import datetime
import whois
from core.eml_parser import ParsedEmail


def _lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return {"domain": domain, "age_days": None, "risk": "unknown", "error": "No creation date"}

        age = (datetime.datetime.now() - created.replace(tzinfo=None)).days
        if age < 30:    risk = "high"
        elif age < 180: risk = "medium"
        elif age < 365: risk = "low"
        else:           risk = "trusted"

        return {
            "domain":     domain,
            "age_days":   age,
            "created":    str(created.date()),
            "registrar":  str(w.registrar or "unknown"),
            "risk":       risk,
        }
    except Exception as e:
        return {"domain": domain, "age_days": None, "risk": "unknown", "error": str(e)[:80]}


def run(parsed: ParsedEmail) -> dict:
    domains_to_check = set()

    if parsed.from_domain:
        domains_to_check.add(parsed.from_domain)
    if parsed.reply_to_domain and parsed.reply_to_domain != parsed.from_domain:
        domains_to_check.add(parsed.reply_to_domain)

    results = [_lookup(d) for d in list(domains_to_check)[:3]]  # cap at 3

    max_risk  = "trusted"
    risk_order = {"trusted": 0, "unknown": 1, "low": 2, "medium": 3, "high": 4}
    for r in results:
        if risk_order.get(r["risk"], 0) > risk_order.get(max_risk, 0):
            max_risk = r["risk"]

    return {
        "verdict": max_risk,
        "domains": results,
    }