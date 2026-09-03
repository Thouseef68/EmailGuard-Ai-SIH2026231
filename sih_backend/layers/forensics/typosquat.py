# layers/forensics/typosquat.py
"""
Typosquat + domain entropy detection.
Catches: misspelled legit domains (paypa1.com), gibberish domains (oatuskmaufr.ru),
         homoglyphs (pаypal.com with Cyrillic а), subdomain abuse (paypal.com.evil.xyz)
"""

import re
import math
from core.eml_parser import ParsedEmail

# ── Indian + global domain whitelist ──────────────────────────────────────
WHITELIST = {
    # Indian banks/finance
    "sbi.co.in","hdfcbank.com","icicibank.com","axisbank.com","kotak.com",
    "pnbindia.in","bankofbaroda.in","canarabank.com","unionbankofindia.co.in",
    "yesbank.in","indusind.com","idfcfirstbank.com","rblbank.com",
    # Indian govt/services
    "gov.in","nic.in","india.gov.in","incometax.gov.in","irctc.co.in",
    "uidai.gov.in","epfindia.gov.in","nsdl.co.in","npci.org.in",
    "scholarships.gov.in","digilocker.gov.in","cowin.gov.in",
    # Indian payments/UPI
    "upi.npci.org.in","phonepe.com","paytm.com","gpay.com","bhimupi.org.in",
    # Indian e-commerce/services
    "flipkart.com","amazon.in","myntra.com","zomato.com","swiggy.com",
    "ola.com","uber.com","makemytrip.com","cleartrip.com","yatra.com",
    "bigbasket.com","blinkit.com","zepto.in","meesho.com","nykaa.com",
    # Global tech
    "google.com","microsoft.com","apple.com","amazon.com","meta.com",
    "linkedin.com","twitter.com","github.com","dropbox.com","adobe.com",
    "zoom.us","slack.com","atlassian.com","salesforce.com","oracle.com",
    "aws.amazon.com","azure.microsoft.com","cloud.google.com",
    # Email providers
    "gmail.com","yahoo.com","outlook.com","hotmail.com","protonmail.com",
    "rediffmail.com","yandex.com",
    #paypal
    "paypal.com",       # ← ADD THIS
    "paypal.in",
    # Trusted infra
    "cloudflare.com","akamai.com","fastly.com","letsencrypt.org",
    #union bank
    "unionbankofindia.co.in",   # ← add to WHITELIST
    "unionbankofindia.com",
}

# ── Homoglyph map (confusable unicode → ascii) ─────────────────────────────
HOMOGLYPHS = str.maketrans({
    'а':'a','е':'e','о':'o','р':'p','с':'c','х':'x','у':'y',  # Cyrillic
    'ο':'o','ρ':'p','ν':'v','μ':'u',                           # Greek
    '0':'o','1':'l','3':'e','4':'a','5':'s','6':'g','@':'a',   # Leet
    'ı':'i','ĺ':'l','ń':'n','ŕ':'r',
})

# ── High-risk TLDs (not inherently bad, but context-dependent) ─────────────
SUSPICIOUS_TLDS = {
    ".ru",".cn",".tk",".ml",".ga",".cf",".gq",".xyz",".top",".club",
    ".work",".click",".link",".online",".site",".website",".info",
    ".biz",".icu",".vip",".live",".stream",".download",
}


def _entropy(s: str) -> float:
    """Shannon entropy — high entropy = random/gibberish string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    return -sum((f/len(s)) * math.log2(f/len(s)) for f in freq.values())


def _levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        curr = [i+1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j]+(ca!=cb), prev[j+1]+1, curr[j]+1))
        prev = curr
    return prev[-1]


def _normalize(domain: str) -> str:
    return domain.lower().translate(HOMOGLYPHS).strip(".")


def _sld(domain: str) -> str:
    """Extract second-level domain: 'mail.evil.paypal.com.xyz' → 'paypal.com.xyz'"""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


# replace analyze_domain() function only — rest of file unchanged

def analyze_domain(domain: str) -> dict:
    if not domain:
        return {"domain": domain, "risk": "none", "reasons": []}

    norm     = _normalize(domain)
    sld      = _sld(norm)
    orig_sld = _sld(domain.lower())
    name     = sld.split(".")[0]
    reasons  = []
    score    = 0

    # 1. Homoglyph/leet impersonation — normalized matches whitelist but original doesn't
    whitelist_norm = {_normalize(w) for w in WHITELIST}
    if norm in whitelist_norm and domain.lower() not in {w.lower() for w in WHITELIST}:
        reasons.append(f"Homoglyph/leet impersonation of whitelisted domain")
        score += 5

    # 2. Brand name in subdomain/prefix with fake suffix
    #    e.g. sbi-secure-login.xyz, hdfc-alert.ru, irctc-refund.in
    brand_names = {w.split(".")[0] for w in WHITELIST} | {
        "sbi","hdfc","icici","axis","kotak","irctc","uidai","paytm",
        "phonepe","gpay","flipkart","amazon","google","microsoft","paypal",
        "apple","whatsapp","facebook","instagram","linkedin","github",
    }
    for brand in brand_names:
        if brand in name and name != brand:
            reasons.append(f"Brand name '{brand}' in suspicious domain")
            score += 3
            break

    # 3. Entropy check — lowered to 3.2 to catch oatuskmaufr-style gibberish
    ent = _entropy(name.replace("-",""))   # strip hyphens before entropy
    if ent > 3.0 and score == 0:           # skip if already flagged by brand check
        reasons.append(f"High domain entropy ({ent:.2f}) — likely gibberish/random")
        score += 3

    # 4. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if norm.endswith(tld):
            reasons.append(f"Suspicious TLD: {tld}")
            score += 2 if score > 0 else 1   # double weight if combined with other signals
            break

    # 5. Subdomain abuse — whitelist domain used as subdomain of different root
    for trusted in WHITELIST:
        trusted_norm = _normalize(trusted)
        if trusted_norm in norm and not norm.endswith(trusted_norm):
            reasons.append(f"Whitelist domain '{trusted}' used as subdomain of '{domain}'")
            score += 4
            break

    # 6. Levenshtein ≤ 2 from whitelist (only if not already flagged)
    if score == 0:
        for trusted in WHITELIST:
            dist = _levenshtein(orig_sld, _sld(trusted.lower()))
            if 0 < dist <= 2:
                reasons.append(f"Typosquat: '{domain}' is {dist} edit(s) from '{trusted}'")
                score += 3
                break

    # 7. Exact whitelist match — trusted (original domain, not normalized)
    if domain.lower() in {w.lower() for w in WHITELIST}:
        return {"domain": domain, "risk": "trusted", "reasons": ["Whitelisted domain"]}

    risk = "none"
    if score >= 4:   risk = "high"
    elif score >= 2: risk = "medium"
    elif score >= 1: risk = "low"

    return {"domain": domain, "risk": risk, "score": score, "reasons": reasons}

def run(parsed: ParsedEmail) -> dict:
    """Run typosquat analysis on From, Reply-To, Return-Path, and body URLs."""
    findings = []

    # Check header domains
    for label, domain in [
        ("from",        parsed.from_domain),
        ("reply_to",    parsed.reply_to_domain),
        ("return_path", parsed.return_path_domain),
    ]:
        if domain and domain != parsed.from_domain or label == "from":
            result = analyze_domain(domain)
            if result["risk"] not in ("none", "trusted"):
                findings.append({"field": label, **result})

    # Check body URL domains
    body_domains = set(re.findall(r'https?://([^/\s\'"<>]+)', parsed.body_text.lower()))
    for dom in list(body_domains)[:20]:   # cap at 20 to avoid newsletter spam
        result = analyze_domain(dom)
        if result["risk"] in ("high", "medium"):
            findings.append({"field": "body_url", **result})

    # Overall verdict
    max_risk  = "none"
    risk_order = {"none":0, "low":1, "trusted":0, "medium":2, "high":3}
    for f in findings:
        if risk_order.get(f["risk"], 0) > risk_order.get(max_risk, 0):
            max_risk = f["risk"]

    return {
        "verdict":  max_risk,
        "findings": findings,
        "checked":  len(body_domains) + 3,
    }