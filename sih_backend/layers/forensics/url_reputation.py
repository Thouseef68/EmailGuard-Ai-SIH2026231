# layers/forensics/url_reputation.py
"""
URL reputation check via VirusTotal API.
Checks URLs found in email body against VT's 70+ antivirus engines.
"""

import re
import base64
import requests
from core.eml_parser import ParsedEmail
import config

VT_URL = "https://www.virustotal.com/api/v3/urls"

def _check_url(url: str) -> dict:
    try:
        # VirusTotal URL ID = base64url(url) without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": config.VIRUSTOTAL_API_KEY}

        # First try GET (cached result)
        r = requests.get(f"{VT_URL}/{url_id}", headers=headers, timeout=10)

        if r.status_code == 404:
            # Not cached — submit for scan
            r = requests.post(VT_URL, headers=headers,
                              data={"url": url}, timeout=10)
            if r.status_code != 200:
                return {"url": url, "risk": "unknown", "error": f"VT submit failed: {r.status_code}"}
            # Re-fetch after submit
            r = requests.get(f"{VT_URL}/{url_id}", headers=headers, timeout=10)

        if r.status_code != 200:
            return {"url": url, "risk": "unknown", "error": f"VT error: {r.status_code}"}

        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total      = sum(stats.values())

        if malicious >= 3:        risk = "high"
        elif malicious >= 1:      risk = "medium"
        elif suspicious >= 2:     risk = "medium"
        elif suspicious >= 1:     risk = "low"
        else:                     risk = "trusted"

        return {
            "url":        url,
            "malicious":  malicious,
            "suspicious": suspicious,
            "total":      total,
            "risk":       risk,
        }
    except Exception as e:
        return {"url": url, "risk": "unknown", "error": str(e)[:80]}


def run(parsed: ParsedEmail) -> dict:
    if not getattr(config, "VIRUSTOTAL_API_KEY", ""):
        return {"verdict": "skipped", "reason": "No API key configured"}

    urls = re.findall(r'https?://\S+', parsed.body_text.lower())[:5]  # cap at 5
    if not urls:
        return {"verdict": "none", "findings": [], "checked": 0}

    findings = []
    for url in urls:
        result = _check_url(url)
        if result["risk"] not in ("trusted", "unknown"):
            findings.append(result)

    risk_order = {"none": 0, "trusted": 0, "unknown": 1, "low": 1, "medium": 2, "high": 3}
    max_risk = "none"
    for f in findings:
        if risk_order.get(f["risk"], 0) > risk_order.get(max_risk, 0):
            max_risk = f["risk"]

    return {
        "verdict":  max_risk,
        "findings": findings,
        "checked":  len(urls),
    }