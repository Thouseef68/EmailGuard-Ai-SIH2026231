"""
core/report_text.py — EmailGuard AI structured plain-text forensic report

Turns the finished analysis dict (the same JSON /analyze returns) into one
formal, numbered, plain-text document: no images, no screenshots, no HTML.

Design rules
  * Every section of the analysis report is included. Sections whose fields
    are not known in advance (forensics, geoip, smtp_chain, vision,
    attachments, explainability, nlp_extra) are rendered by a generic
    walker, so a field added to a layer later appears here with no change.
  * ASCII only, 80 columns, so it opens identically in Notepad, a browser,
    a printer or a court bundle.
  * Never raises: a bad field degrades to "-" instead of breaking the report.

Public API
  build_text_report(report: dict, generated_at=None) -> str
  report_filename(report: dict) -> str
"""

import ipaddress
import json
import os
import re
import textwrap
import unicodedata
from datetime import datetime, timedelta, timezone

WIDTH = 80
LABEL_W = 26
IST = timezone(timedelta(hours=5, minutes=30))

PRODUCT = "EmailGuard AI"
CONTACT = "founder@emailguardai.me"

_ACRONYMS = {
    "spf": "SPF", "dkim": "DKIM", "dmarc": "DMARC", "ip": "IP", "ips": "IPs",
    "url": "URL", "urls": "URLs", "ocr": "OCR", "qr": "QR", "vt": "VirusTotal",
    "smtp": "SMTP", "asn": "ASN", "isp": "ISP", "pdf": "PDF", "dns": "DNS",
    "tld": "TLD", "shap": "SHAP", "nli": "NLI", "ioc": "IOC", "iocs": "IOCs",
    "whois": "WHOIS", "geoip": "GeoIP", "id": "ID", "xgboost": "XGBoost",
    "deberta": "DeBERTa", "llm": "LLM", "pii": "PII", "html": "HTML",
    "fcrdns": "FCrDNS", "mx": "MX", "ttl": "TTL", "tls": "TLS", "eml": "EML",
    "sha256": "SHA-256", "ipfs": "IPFS", "cid": "CID", "ms": "(ms)",
}

# Keys that carry markup / binary / duplicate data and add nothing to a document.
_SKIP_KEYS = {"html", "heatmap_html", "heatmap", "image", "images", "image_b64",
              "base64", "dossier", "raw_bytes", "report_text", "report_filename"}

_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

_VERDICT_TEXT = {
    "PHISHING": "PHISHING - the message is assessed as malicious or fraudulent.",
    "LEGITIMATE": "LEGITIMATE - no basis was found to treat the message as malicious.",
    "HUMAN_REVIEW": "REQUIRES HUMAN REVIEW - the evidence does not support an automatic decision.",
}

_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]\}]+", re.I)
_IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

_LAT_KEYS = ("latitude", "lat")
_LON_KEYS = ("longitude", "lon", "lng", "long")

_CHAINS = {
    "11155111": ("Ethereum Sepolia (public test network)", "https://sepolia.etherscan.io/tx/"),
    "80002": ("Polygon Amoy (public test network)", "https://amoy.polygonscan.com/tx/"),
    "137": ("Polygon mainnet", "https://polygonscan.com/tx/"),
    "1": ("Ethereum mainnet", "https://etherscan.io/tx/"),
}
_TESTNETS = {"11155111", "80002"}


# ── text helpers ─────────────────────────────────────────────────────────────

_REPL = {"\u26a0": "[!]", "\u2014": "-", "\u2013": "-", "\u2026": "...", "\u2192": "->",
         "\u2713": "[ok]", "\u2022": "*", "\u2018": "'", "\u2019": "'",
         "\u201c": '"', "\u201d": '"', "\u00a0": " "}


def _ascii(value) -> str:
    s = str(value)
    for a, b in _REPL.items():
        s = s.replace(a, b)
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[ \t]+", " ", s.replace("\r", "")).strip()


def _pretty(key) -> str:
    words = [w for w in re.split(r"[_\s]+", str(key)) if w]
    return " ".join(_ACRONYMS.get(w.lower(), w.capitalize()) for w in words)


def _scalar(v) -> str:
    if v is None or v == "":
        return "-"
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, float):
        return f"{v:.4f}".rstrip("0").rstrip(".") or "0"
    if isinstance(v, (bytes, bytearray)):
        return "[binary data omitted]"
    s = _ascii(v)
    if len(s) > 400 and " " not in s[:400]:
        return "[binary/encoded data omitted]"
    if s[:1] == "<" and len(s) > 200:
        return "[markup omitted]"
    if s.startswith("data:image"):
        return "[embedded image omitted]"
    if len(s) > 4000:
        return s[:4000] + f" ... [truncated, {len(s) - 4000} more characters]"
    return s


def _is_scalar(v) -> bool:
    return not isinstance(v, (dict, list, tuple, set))


def _wrap(text: str, indent: int = 0, bullet: str = "") -> list:
    pad = " " * indent
    sub = pad + " " * len(bullet)
    lines = textwrap.wrap(text or "-", width=WIDTH, initial_indent=pad + bullet,
                          subsequent_indent=sub, break_long_words=True, break_on_hyphens=False)
    return lines or [pad + bullet + "-"]


def _kv(label: str, value, indent: int = 0) -> list:
    pad = " " * indent
    text = _scalar(value)
    head = f"{label}:"
    width = WIDTH - indent - LABEL_W
    long_token = " " not in text and len(text) > width      # hashes, CIDs, URLs
    if long_token:                                           # keep copy-pasteable on one line
        return [pad + head, " " * (indent + 4) + text]
    if width < 24 or len(head) >= LABEL_W:
        return [pad + head] + _wrap(text, indent + 4)
    parts = textwrap.wrap(text, width=width, break_long_words=True, break_on_hyphens=False) or ["-"]
    out = [pad + head.ljust(LABEL_W) + parts[0]]
    out += [pad + " " * LABEL_W + p for p in parts[1:]]
    return out


def _h1(num, title: str) -> list:
    return ["", "=" * WIDTH, f"SECTION {num}.  {title.upper()}", "=" * WIDTH, ""]


def _h2(title: str, indent: int = 0) -> list:
    pad = " " * indent
    return ["", pad + title, pad + "-" * min(len(title), WIDTH - indent)]


def _note(text: str, indent: int = 0) -> list:
    return _wrap("Note: " + text, indent)


# ── generic walker (for layers whose fields are not fixed) ───────────────────

def _render(value, indent: int = 0, depth: int = 0) -> list:
    out = []
    if depth > 7:
        return [" " * indent + "[nested data omitted]"]
    if isinstance(value, dict):
        for k, v in value.items():
            ks = str(k)
            if ks.startswith("_") or ks.lower() in _SKIP_KEYS:
                continue
            label = _pretty(ks)
            if isinstance(v, dict):
                if not v:
                    out += _kv(label, "-", indent)
                else:
                    out.append(" " * indent + label + ":")
                    out += _render(v, indent + 2, depth + 1)
            elif isinstance(v, (list, tuple, set)):
                v = list(v)
                if not v:
                    out += _kv(label, "None", indent)
                elif all(_is_scalar(x) for x in v):
                    short = all(len(_scalar(x)) <= 36 for x in v) and len(v) <= 8
                    if short:
                        out += _kv(label, ", ".join(_scalar(x) for x in v), indent)
                    else:
                        out.append(" " * indent + label + ":")
                        for x in v:
                            out += _wrap(_scalar(x), indent + 2, "- ")
                else:
                    out.append(" " * indent + label + ":")
                    for i, item in enumerate(v, 1):
                        out.append(" " * (indent + 2) + f"[{i}]")
                        out += _render(item, indent + 6, depth + 1) if isinstance(item, dict) \
                            else _wrap(_scalar(item), indent + 6)
            else:
                out += _kv(label, v, indent)
    elif isinstance(value, (list, tuple, set)):
        for i, item in enumerate(list(value), 1):
            if isinstance(item, dict):
                out.append(" " * indent + f"[{i}]")
                out += _render(item, indent + 4, depth + 1)
            else:
                out += _wrap(_scalar(item), indent, "- ")
    else:
        out += _wrap(_scalar(value), indent)
    return out or [" " * indent + "-"]


def _section_generic(num, title: str, data, intro: str = "") -> list:
    out = _h1(num, title)
    if intro:
        out += _wrap(intro) + [""]
    if not data:
        out += ["This layer returned no data for this email."]
    elif isinstance(data, dict):
        out += _render(data)
    else:
        out += _render(data)
    return out


# ── lookups ──────────────────────────────────────────────────────────────────

def _find(obj, names, depth: int = 0):
    """First non-empty scalar stored under any of `names`, searched breadth-first-ish."""
    if depth > 3 or not isinstance(obj, dict):
        return None
    for n in names:
        v = obj.get(n)
        if v not in (None, "") and _is_scalar(v):
            return v
    for k in ("blockchain", "anchor", "evidence", "storage", "persistence", "record"):
        sub = obj.get(k)
        if isinstance(sub, dict):
            hit = _find(sub, names, depth + 1)
            if hit is not None:
                return hit
    return None


def _walk_dicts(obj, depth: int = 0):
    if depth > 8:
        return
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _walk_dicts(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _walk_dicts(v, depth + 1)


def _to_float(v):
    try:
        f = float(v)
        return f
    except Exception:
        return None


def _map_links(*parts) -> list:
    links, seen = [], set()
    for part in parts:
        for d in _walk_dicts(part):
            lat = next((_to_float(d[k]) for k in _LAT_KEYS if k in d and _to_float(d[k]) is not None), None)
            lon = next((_to_float(d[k]) for k in _LON_KEYS if k in d and _to_float(d[k]) is not None), None)
            if lat is None or lon is None or not (-90 <= lat <= 90 and -180 <= lon <= 180):
                continue
            if lat == 0 and lon == 0:
                continue
            key = (round(lat, 4), round(lon, 4))
            if key in seen:
                continue
            seen.add(key)
            where = ", ".join(_ascii(d[k]) for k in ("city", "region", "country") if d.get(k))
            ip = _ascii(d.get("ip") or d.get("origin_ip") or "")
            links.append({
                "label": " / ".join(x for x in (ip, where) if x) or "Located point",
                "url": f"https://www.google.com/maps?q={lat},{lon}",
            })
    return links


def _collect_ips(*parts) -> list:
    found = []
    blob = " ".join(json.dumps(p, default=str) for p in parts if p)
    for m in _IP_RE.findall(blob):
        try:
            ip = ipaddress.ip_address(m)
        except ValueError:
            continue
        if m not in [x[0] for x in found]:
            found.append((m, "public" if ip.is_global else "private / reserved"))
    return found


def _collect_urls(report: dict) -> list:
    skip = {"report_text"}
    blob = json.dumps({k: v for k, v in report.items() if k not in skip}, default=str)
    urls = []
    for u in _URL_RE.findall(blob):
        u = u.rstrip(".,;\\")
        if u not in urls and "google.com/maps" not in u:
            urls.append(u)
    return urls


def _fmt_time(dt: datetime) -> str:
    utc = dt.astimezone(timezone.utc).strftime("%d %b %Y, %H:%M:%S UTC")
    ist = dt.astimezone(IST).strftime("%d %b %Y, %H:%M:%S IST")
    return f"{utc}  ({ist})"


# ── main builder ─────────────────────────────────────────────────────────────

def report_filename(report: dict) -> str:
    aid = _find(report or {}, ("analysis_id",))
    tag = re.sub(r"[^A-Za-z0-9_-]", "", str(aid))[:36] if aid else \
        datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"EmailGuardAI_Forensic_Report_{tag}.txt"


def build_text_report(report: dict, generated_at=None) -> str:
    r = report if isinstance(report, dict) else {}
    now = generated_at or datetime.now(timezone.utc)
    L = []

    parsed = r.get("parsed") or {}
    llm = r.get("llm_analyst") or {}
    verdict = str(r.get("final_verdict") or llm.get("verdict") or "HUMAN_REVIEW").upper()
    conf = r.get("final_confidence", llm.get("confidence"))
    analysis_id = _find(r, ("analysis_id",))
    report_hash = _find(r, ("report_hash", "sha256", "sha256_hash"))
    ipfs_cid = _find(r, ("ipfs_cid", "cid"))
    tx_hash = _find(r, ("tx_hash", "transaction_hash"))

    # ---- Title block ---------------------------------------------------------
    L += ["=" * WIDTH, PRODUCT.upper().center(WIDTH),
          "EMAIL THREAT FORENSIC ANALYSIS REPORT".center(WIDTH), "=" * WIDTH, ""]
    L += _kv("Analysis ID", analysis_id or "Not assigned")
    L += _kv("Source file", r.get("source"))
    L += _kv("Report generated", _fmt_time(now))
    L += _kv("Generated by", f"{PRODUCT} automated analysis pipeline")
    L += _kv("Classification", "Confidential - contains analysis of a private email")
    L += ["", "CONTENTS",
          "   1.  Executive Summary and Final Determination",
          "   2.  Message Identity and Authentication",
          "   3.  AI Analyst Findings (decision-making layer)",
          "   4.  Local Model Evidence (advisory)",
          "   5.  Indicators and Flags Raised",
          "   6.  Forensic Checks",
          "   7.  Origin and Network Trace",
          "   8.  Content and Intent Analysis",
          "   9.  Image Analysis (OCR, QR codes, brand logos)",
          "  10.  Attachment Analysis",
          "  11.  Indicator Summary (domains, IP addresses, URLs, map links)",
          "  12.  Evidence Integrity and Blockchain Anchor",
          "  13.  Methodology, Limitations and Legal Notice"]

    # ---- 1 Executive summary -------------------------------------------------
    L += _h1(1, "Executive summary and final determination")
    L += _kv("FINAL DETERMINATION", verdict)
    L += _wrap(_VERDICT_TEXT.get(verdict, verdict), 0)
    L += [""]
    L += _kv("Confidence", f"{conf}%" if conf is not None else "-")
    L += _kv("Decided by", f"AI analyst model {llm.get('model') or 'n/a'}")
    L += _kv("Analyst status",
             "Completed normally" if llm.get("status") == "ok" else
             "FALLBACK - the AI analyst was unavailable; the message was routed to human review")
    L += _kv("Subject", parsed.get("subject"))
    L += _kv("From", parsed.get("from_addr"))
    findings = llm.get("forensic_findings") or []
    sev = {s: sum(1 for f in findings if str(f.get("severity")).upper() == s) for s in _SEV_ORDER}
    L += _kv("Forensic findings", f"{sev['HIGH']} high, {sev['MEDIUM']} medium, {sev['LOW']} low, {sev['INFO']} informational")
    L += _kv("Flags raised", len(r.get("flags") or []))
    L += _h2("Reasons for the determination")
    reasons = llm.get("reasons") or ([r["decision_reason"]] if r.get("decision_reason") else [])
    if reasons:
        for i, text in enumerate(reasons, 1):
            L += _wrap(_scalar(text), 0, f"{i}. ")
    else:
        L += ["No reasons were returned."]
    L += _h2("Decision basis")
    L += _wrap("Every email is assessed by an AI analyst that receives a dossier of verified forensic "
               "facts (headers, authentication, links, domains, attachments, images). The analyst's "
               "verdict is the final determination. The local machine-learning models in Section 4 "
               "are supplied to it as advisory evidence only and do not decide the outcome. A "
               "validator compares the analyst's statements against the verified facts and records any "
               "disagreement in Section 3.")

    # ---- 2 Identity ----------------------------------------------------------
    L += _h1(2, "Message identity and authentication")
    for label, key in (("Subject", "subject"), ("From address", "from_addr"), ("From domain", "from_domain"),
                       ("Reply-To address", "reply_to"), ("SPF result", "spf"), ("DKIM result", "dkim"),
                       ("DMARC result", "dmarc"), ("Received hops", "received_hops"),
                       ("Attachments", "attachment_count")):
        L += _kv(label, parsed.get(key))
    extra = {k: v for k, v in parsed.items() if k not in (
        "subject", "from_addr", "from_domain", "reply_to", "spf", "dkim", "dmarc",
        "received_hops", "attachment_count")}
    if extra:
        L += _render(extra)
    L += [""]
    L += _note("SPF, DKIM and DMARC show only that the sending server is configured for the domain "
               "that signed or sent the message. An attacker who owns a domain can pass all three. "
               "A pass is therefore not proof that the sender is the organisation named in the "
               "display name.")

    # ---- 3 AI analyst --------------------------------------------------------
    L += _h1(3, "AI analyst findings (decision-making layer)")
    L += _kv("Model", llm.get("model"))
    L += _kv("Analyst verdict (raw)", llm.get("llm_verdict_raw"))
    L += _kv("Final verdict", llm.get("verdict") or verdict)
    L += _kv("Confidence", f"{llm.get('confidence')}%" if llm.get("confidence") is not None else "-")
    L += _kv("Validator mode", llm.get("validator_mode"))
    L += _kv("Asked a second time", llm.get("re_asked"))
    L += _kv("Response time", f"{llm.get('latency_ms')} ms" if llm.get("latency_ms") is not None else "-")
    if llm.get("error"):
        L += _kv("Error", llm.get("error"))

    L += _h2("Verified forensic findings (computed by code, not by the model)")
    if findings:
        ordered = sorted(findings, key=lambda f: _SEV_ORDER.get(str(f.get("severity")).upper(), 9))
        for f in ordered:
            L += _wrap(_scalar(f.get("text")), 0, f"{str(f.get('id')):<4} [{str(f.get('severity')).upper():<6}] ")
    else:
        L += ["No forensic findings were recorded."]

    L += _h2("Analyst response to each HIGH finding")
    hf = llm.get("high_findings") or []
    if hf:
        for h in hf:
            L += _wrap(f"{h.get('stance', '').upper()}: {_scalar(h.get('why'))}", 0, f"{h.get('id')}  ")
    else:
        L += ["No HIGH findings required a response."]

    L += _h2("Findings cited by the analyst")
    L += _wrap(", ".join(llm.get("cited_findings") or []) or "None cited.")

    L += _h2("Validator audit notes")
    notes = llm.get("validation_notes") or []
    if notes:
        for n in notes:
            L += _wrap(_scalar(n), 0, "- ")
    else:
        L += ["No disagreement between the analyst and the verified facts was recorded."]

    # ---- 4 Local models ------------------------------------------------------
    L += _h1(4, "Local model evidence (advisory)")
    L += _wrap("These scores come from the locally hosted DeBERTa V12 text model and XGBoost structural "
               "model, combined by a fixed fusion gate. They are advisory inputs to the AI analyst and "
               "are known to be biased in both directions (HTML-heavy legitimate mail can score high; "
               "calm, professional phishing can score low).")
    L += [""]
    ts = r.get("text_structural")
    if isinstance(ts, dict) and ts:
        for name in ("deberta", "xgboost", "fusion"):
            if isinstance(ts.get(name), dict):
                L += _h2({"deberta": "DeBERTa V12 (text model)", "xgboost": "XGBoost (structural model)",
                          "fusion": "Fusion gate"}[name])
                L += _render(ts[name], 2)
        rest = {k: v for k, v in ts.items() if k not in ("deberta", "xgboost", "fusion")}
        if rest:
            L += _h2("Other")
            L += _render(rest, 2)
    else:
        L += ["The local models returned no result for this email."]

    # ---- 5 Flags -------------------------------------------------------------
    L += _h1(5, "Indicators and flags raised")
    flags = [str(f) for f in (r.get("flags") or [])]
    if not flags:
        L += ["No flags were raised."]
    groups = {}
    for f in flags:
        m = re.match(r"^\[([A-Z]+)\]\s*(.*)$", f.strip(), re.S)
        groups.setdefault(m.group(1) if m else "GENERAL", []).append(m.group(2) if m else f)
    titles = {"GENERAL": "General and header flags", "VISION": "Image analysis", "ATTACH": "Attachments",
              "SMTP": "SMTP delivery chain", "VALIDATOR": "Validator"}
    n = 0
    for g in ["GENERAL"] + [k for k in groups if k != "GENERAL"]:
        if g not in groups:
            continue
        L += _h2(titles.get(g, g.title()))
        for text in groups[g]:
            n += 1
            L += _wrap(_scalar(text), 0, f"{n:>2}. ")

    # ---- 6-10 generic layers -------------------------------------------------
    forensics = r.get("forensics")
    L += _h1(6, "Forensic checks")
    L += _wrap("Deterministic checks run on the headers, domains and links of the message.") + [""]
    if isinstance(forensics, dict) and forensics:
        sub_titles = {"auth_headers": "Authentication headers", "address_mismatch": "Sender address consistency",
                      "typosquat": "Look-alike (typosquat) domains", "url_unshorten": "Shortened URL expansion",
                      "whois": "Domain registration (WHOIS)", "url_reputation": "URL reputation (VirusTotal)"}
        for k, v in forensics.items():
            L += _h2(sub_titles.get(k, _pretty(k)))
            L += _render(v, 2) if isinstance(v, (dict, list)) else _wrap(_scalar(v), 2)
    else:
        L += ["The forensic layer returned no data."]

    geoip, smtp = r.get("geoip"), r.get("smtp_chain")
    L += _h1(7, "Origin and network trace")
    L += _h2("Originating IP and location (GeoIP)")
    L += _render(geoip, 2) if geoip else ["No GeoIP data was available."]
    L += _h2("SMTP delivery chain")
    L += _render(smtp, 2) if smtp else ["No SMTP chain data was available."]
    maps = _map_links(geoip, smtp)
    L += _h2("Map links")
    L += _note("IP geolocation is approximate and shows where the sending mail server is registered, "
               "not where the sender is. Errors of hundreds of kilometres, or the wrong country, are "
               "common for hosting and email-delivery providers.")
    L += [""]
    if maps:
        for m in maps:
            L += _wrap(m["label"], 0, "- ")
            L += _wrap(m["url"], 4)
    else:
        L += ["No coordinates were available for this email."]

    L += _section_generic(8, "Content and intent analysis", {
        "intent_analysis": r.get("nlp_extra"), "explainability": r.get("explainability")},
        "Zero-shot intent classification and the explainability output for the local models.")
    L += _section_generic(9, "Image analysis (OCR, QR codes, brand logos)", r.get("vision"),
                          "Text, QR codes and brand logos found in embedded images. No images are "
                          "reproduced in this document.")
    L += _section_generic(10, "Attachment analysis", r.get("attachments"),
                          "PDF and Office attachments scanned for active content and macros.")

    # ---- 11 Indicator summary --------------------------------------------------
    L += _h1(11, "Indicator summary")
    domains = []
    for d in (parsed.get("from_domain"), str(parsed.get("reply_to") or "").split("@")[-1]):
        if d and "." in str(d) and "REDACTED" not in str(d).upper() and _ascii(d) not in domains:
            domains.append(_ascii(d))
    L += _h2("Domains")
    L += [f"- {d}" for d in domains] or ["None."]
    ips = _collect_ips(geoip, smtp, forensics)
    L += _h2("IP addresses")
    L += [f"- {ip}   ({kind})" for ip, kind in ips] or ["None found."]
    urls = _collect_urls(r)
    L += _h2("URLs found in the analysis")
    if urls:
        for u in urls[:100]:
            L += _wrap(u, 0, "- ")
        if len(urls) > 100:
            L += [f"... and {len(urls) - 100} more."]
    else:
        L += ["None found."]
    L += _h2("Map links")
    L += [m["url"] for m in maps] or ["None."]
    L += [""]
    L += _note("Do not open the URLs above on a normal device; treat them as hostile.")

    # ---- 12 Integrity ----------------------------------------------------------
    L += _h1(12, "Evidence integrity and blockchain anchor")
    chain_id = str(_find(r, ("chain_id",)) or os.environ.get("CHAIN_ID", "11155111"))
    chain_name, explorer = _CHAINS.get(chain_id, (f"Chain ID {chain_id}", ""))
    L += _kv("Analysis ID", analysis_id or "Not assigned")
    anchor_error = _find(r, ("anchor_error",))
    if tx_hash:
        anchor_status = "Confirmed - the report hash is recorded on-chain."
    elif anchor_error:
        anchor_status = (f"FAILED - {_ascii(anchor_error)[:160]}. The report hash below is still "
                         "valid for local verification.")
    else:
        anchor_status = ("PENDING - anchoring is still in progress. Download this report again in "
                         "a minute to include the IPFS and transaction details.")
    L += _kv("Anchor status", anchor_status)
    L += _kv("Report SHA-256 hash", report_hash or "Not available")
    L += _kv("IPFS content ID", ipfs_cid or "Not available")
    if ipfs_cid:
        L += _kv("IPFS link", f"https://ipfs.io/ipfs/{ipfs_cid}")
    L += _kv("Network", chain_name)
    L += _kv("Transaction hash", tx_hash or "Not available")
    if tx_hash and explorer:
        L += _kv("Explorer link", explorer + str(tx_hash))
    L += _h2("How to verify")
    for i, step in enumerate((
            "Download the stored report from the IPFS link above.",
            "Compute its SHA-256 hash with any standard tool.",
            "Compare it with the hash recorded on-chain (GET /verify/<analysis-id> on the "
            "EmailGuard AI API, or the transaction above). They must match exactly.",
            "A match shows the report has not been altered since it was anchored."), 1):
        L += _wrap(step, 0, f"{i}. ")
    if chain_id in _TESTNETS:
        L += [""]
        L += _note("This record is anchored on a public TEST network. It demonstrates tamper-evidence "
                   "but should not be relied on as long-term production evidence.")

    # ---- 13 Methodology --------------------------------------------------------
    L += _h1(13, "Methodology, limitations and legal notice")
    L += _h2("Analysis layers applied")
    for item in (
            "Header and authentication analysis (SPF, DKIM, DMARC, Reply-To and Return-Path consistency)",
            "Link analysis (shortened-URL expansion, look-alike domains, WHOIS age, URL reputation)",
            "GeoIP of the originating server and SMTP chain traversal (multi-hop, forward-confirmed reverse DNS)",
            "Local models: DeBERTa V12 text classifier and XGBoost structural classifier, with SHAP explanations",
            "Zero-shot intent classification of the message body",
            "Image analysis: OCR, QR-code decoding and brand-logo spoofing checks",
            "Attachment scanning: PDF and Office macro analysis",
            "AI analyst (large language model) that reads the verified dossier and issues the final verdict",
            "Validator that audits the analyst against the verified facts",
            "Personal-data masking applied to the report before storage and display"):
        L += _wrap(item, 0, "- ")
    L += _h2("Limitations")
    for item in (
            "The determination is automated. It is an assessment based on the data in the uploaded "
            "message, not a certainty.",
            "Results depend on the headers present in the uploaded file; forwarded or re-saved messages "
            "may have lost original headers.",
            "Third-party services (WHOIS, URL reputation, GeoIP) can be incomplete or out of date.",
            "Where the evidence is insufficient the system routes the message to human review rather "
            "than guessing.",
            "Personal data in this report has been masked; masked values cannot be recovered from it."):
        L += _wrap(item, 0, "- ")
    L += _h2("Legal notice")
    L += _wrap("This report is produced to assist the preservation and review of electronic evidence. "
               "Whether it is admissible, and what weight it carries, is for the court or authority to "
               "decide, and may require a certificate under Section 63(4) of the Bharatiya Sakshya "
               "Adhiniyam, 2023 to be furnished separately. This report is not legal advice.")

    L += ["", "=" * WIDTH, "END OF REPORT".center(WIDTH),
          f"{PRODUCT}  |  {CONTACT}".center(WIDTH), "=" * WIDTH, ""]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(L))