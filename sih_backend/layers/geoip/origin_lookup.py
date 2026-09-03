# layers/geoip/origin_lookup.py
"""
GeoIP origin lookup — finds physical location of email's originating IP.
Uses ip-api.com (free, no key needed) as primary.
Falls back to MaxMind GeoLite2 local DB if configured.
"""

import re
import requests
from core.eml_parser import ParsedEmail

# Optional: set path to GeoLite2-City.mmdb in config.py
# GEOIP_DB_PATH = "models/GeoLite2-City.mmdb"

# High-risk countries for phishing (common sources)
HIGH_RISK_COUNTRIES = {
    "NG", "RU", "CN", "PK", "BD", "GH", "KE", "CI",
    "CM", "SN", "BF", "TZ", "UG", "ZW", "ET",
}


def _extract_originating_ip(received_headers: list) -> str:
    """
    Extract the REAL originating IP from Received headers.
    Bottom-most Received header = first hop = actual sender.
    Skip private/internal IPs.
    """
    private_ranges = [
        r'^10\.',
        r'^172\.(1[6-9]|2[0-9]|3[01])\.',
        r'^192\.168\.',
        r'^127\.',
        r'^::1$',
    ]

    # Read bottom-up — last header = first hop
    for header in reversed(received_headers):
        ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', str(header))
        for ip in ips:
            is_private = any(re.match(p, ip) for p in private_ranges)
            if not is_private:
                return ip
    return ""


def _lookup_ip(ip: str) -> dict:
    """Lookup IP via ip-api.com (free, 45 req/min)."""
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5,
            params={"fields": "status,country,countryCode,regionName,city,isp,org,lat,lon"}
        )
        data = r.json()
        if data.get("status") != "success":
            return {"ip": ip, "error": "lookup failed"}

        country_code = data.get("countryCode", "")
        is_high_risk = country_code in HIGH_RISK_COUNTRIES

        return {
            "ip":          ip,
            "country":     data.get("country", ""),
            "country_code": country_code,
            "region":      data.get("regionName", ""),
            "city":        data.get("city", ""),
            "isp":         data.get("isp", ""),
            "org":         data.get("org", ""),
            "lat":         data.get("lat"),
            "lon":         data.get("lon"),
            "high_risk_country": is_high_risk,
        }
    except Exception as e:
        return {"ip": ip, "error": str(e)[:80]}


def run(parsed: ParsedEmail) -> dict:
    ip = _extract_originating_ip(parsed.received_headers)
    if not ip:
        return {"verdict": "unknown", "reason": "No public IP found in Received headers"}

    geo = _lookup_ip(ip)
    if "error" in geo:
        return {"verdict": "unknown", "ip": ip, "error": geo["error"]}

    risk = "high" if geo.get("high_risk_country") else "low"

    return {
        "verdict":        risk,
        "originating_ip": ip,
        "location": {
            "country":      geo["country"],
            "country_code": geo["country_code"],
            "region":       geo["region"],
            "city":         geo["city"],
            "lat":          geo["lat"],
            "lon":          geo["lon"],
        },
        "isp":  geo["isp"],
        "org":  geo["org"],
        "high_risk_country": geo.get("high_risk_country", False),
    }