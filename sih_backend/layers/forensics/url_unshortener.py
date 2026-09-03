# layers/forensics/url_unshorten.py
"""
URL unshortening — follows redirect chains to reveal final destination.
Then runs the final URL through typosquat analysis.
"""

import re
import requests
from layers.forensics.typosquat import analyze_domain, SUSPICIOUS_TLDS
from core.eml_parser import ParsedEmail

SHORTENERS = {
    "bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","buff.ly",
    "short.io","rebrand.ly","cutt.ly","is.gd","tiny.cc","bl.ink",
    "shorte.st","adf.ly","bc.vc","linktr.ee","tr.im","clck.ru",
}

def _final_url(url: str, timeout: int = 5) -> tuple:
    """Follow redirects, return (final_url, hop_count, error)."""
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout,
                          headers={"User-Agent": "Mozilla/5.0"})
        return r.url, len(r.history), None
    except requests.exceptions.Timeout:
        return url, 0, "timeout"
    except Exception as e:
        return url, 0, str(e)[:80]

def _extract_domain(url: str) -> str:
    m = re.match(r'https?://([^/\s]+)', url)
    return m.group(1).lower() if m else ""

def run(parsed: ParsedEmail) -> dict:
    body = parsed.body_text
    # in run(), before processing each url:
    urls = [u.rstrip('>)"\'') for u in re.findall(r'https?://\S+', parsed.body_text.lower())]

    findings = []
    for url in urls:
        url = url.rstrip('>)"\'')
        domain = _extract_domain(url)
        is_shortener = any(domain == s or domain.endswith("."+s) for s in SHORTENERS)

        result = {"url": url, "shortener": is_shortener}

        if is_shortener:
            final, hops, err = _final_url(url)
            final_domain = _extract_domain(final)
            typo = analyze_domain(final_domain)
            result.update({
                "final_url":    final,
                "final_domain": final_domain,
                "hops":         hops,
                "error":        err,
                "typosquat":    typo,
                "risk":         typo["risk"] if not err else "unresolvable",
            })
        else:
            typo = analyze_domain(domain)
            result.update({
                "final_url":    url,
                "final_domain": domain,
                "hops":         0,
                "typosquat":    typo,
                "risk":         typo["risk"],
            })

        if result["risk"] in ("high","medium","unresolvable"):
            findings.append(result)

    max_risk = "none"
    risk_order = {"none":0,"low":1,"medium":2,"unresolvable":2,"high":3,"trusted":0}
    for f in findings:
        if risk_order.get(f["risk"],0) > risk_order.get(max_risk,0):
            max_risk = f["risk"]

    return {
        "verdict":  max_risk,
        "findings": findings,
        "checked":  len(urls),
    }