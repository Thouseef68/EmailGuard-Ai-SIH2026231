"""
core/orchestrator.py — runs every layer, merges into ONE report
"""

import logging
import re

from core.eml_parser import parse_eml, ParsedEmail
from layers import text_structural
from layers.forensics import typosquat
from layers.forensics.url_unshortener import run as unshorten_run
from layers.forensics.auth_headers import run as auth_run
from layers.forensics.address_mismatch import run as mismatch_run
from layers.forensics.whois_lookup import run as whois_run
from layers.forensics.url_reputation import run as vt_run
from layers.nlp_extra.zero_shot_intent import run as nli_run
from layers.nlp_extra.pii_masking import mask_report
from layers.geoip.origin_lookup import run as geoip_run
from layers.explainability.shap_heatmap import run as explain_run
from core.image_extractor import extract_images_from_eml
from layers.vision.ocr_extractor import extract_ocr_text
from layers.vision.qr_decoder import decode_qr_codes
from layers.vision.logo_match import detect_brand_spoofing
from layers.forensics.smtp_traversal import analyze_smtp_chain
from core.attachment_extractor import extract_attachments
from layers.attachments.pdf_scan import scan_pdf_attachments
from layers.attachments.office_macro_scan import scan_office_attachments
from layers.llm_analyst import run as llm_run

logger = logging.getLogger(__name__)


def load_all_models():
    text_structural.load()


# A credential flag must mean the email ASKS the reader to hand one over.
# Merely mentioning "password" (e.g. "your statement PDF is password protected")
# or a bank's standard warning ("never share your OTP") is not a request.
_CRED_ASK = re.compile(
    r"\b(enter|share|send|provide|reply with|confirm|verify|update|submit|give|tell|type)\b"
    r"[^.\n]{0,60}?\b(pin|otp|password|passcode|cvv)\b",
    re.I,
)
_NEGATION = re.compile(r"\b(do not|don't|dont|never|not)\b[^.\n]{0,25}$", re.I)


def _asks_for_credentials(text: str) -> bool:
    text = text or ""
    for m in _CRED_ASK.finditer(text):
        if _NEGATION.search(text[max(0, m.start() - 30):m.start()]):
            continue            # "do not share your OTP" is a warning, not a request
        return True
    return False


def _build_flags(parsed: ParsedEmail) -> list:
    flags = []

    if parsed.spf == "fail":
        flags.append("SPF authentication failed")
    if parsed.dkim == "fail":
        flags.append("DKIM signature failed")
    if parsed.dmarc == "fail":
        flags.append("DMARC alignment failed")

    if parsed.reply_to_addr and parsed.reply_to_domain != parsed.from_domain:
        flags.append(f"Reply-To domain ({parsed.reply_to_domain}) differs from From domain ({parsed.from_domain})")
    if parsed.return_path_addr and parsed.return_path_domain != parsed.from_domain:
        flags.append("Return-Path domain differs from From domain")

    txt_lower = parsed.body_text.lower()
    if _asks_for_credentials(parsed.body_text):
        flags.append("Requests sensitive credentials (PIN/OTP/password)")
    if any(w in txt_lower for w in ["immediately", "within 24", "suspend", "expire"]):
        flags.append("Uses urgency/time-pressure language")

    # FIX Bug 3 — removed "not yet scanned"; layers handle their own flags now
    if parsed.attachment_count > 0:
        flags.append(f"Contains {parsed.attachment_count} attachment(s)")
    if parsed.image_parts:
        flags.append(f"Contains {len(parsed.image_parts)} embedded image(s)")

    return flags

def analyze_email(eml_bytes: bytes, source_name: str = "unknown") -> dict:
    parsed  = parse_eml(eml_bytes)
    raw_str = eml_bytes.decode("utf-8", errors="ignore")

    report = {
        "source": source_name,
        "parsed": {
            "subject":          parsed.subject,
            "from_addr":        parsed.from_addr,
            "from_domain":      parsed.from_domain,
            "reply_to":         parsed.reply_to_addr,
            "spf":              parsed.spf,
            "dkim":             parsed.dkim,
            "dmarc":            parsed.dmarc,
            "received_hops":    len(parsed.received_headers),
            "attachment_count": parsed.attachment_count,
        },
    }

    # Flags initialised early so every layer below can safely append
    report["flags"] = _build_flags(parsed)

    # ── Layer 1: Text/Structural (DeBERTa + XGBoost + Fusion) ──────────────
    try:
        report["text_structural"] = text_structural.run(parsed, raw_str)
    except Exception as e:
        report["text_structural"] = {"status": "unavailable", "error": str(e)}

    # ── Layer 2: Forensics ──────────────────────────────────────────────────
    try:
        report["forensics"] = {
            "auth_headers":     auth_run(parsed),
            "address_mismatch": mismatch_run(parsed),
            "typosquat":        typosquat.run(parsed),
            "url_unshorten":    unshorten_run(parsed),
            "whois":            whois_run(parsed),
            "url_reputation":   vt_run(parsed),
        }
    except Exception as e:
        report["forensics"] = {"status": "unavailable", "error": str(e)}

    # ── Layer 3: GeoIP ──────────────────────────────────────────────────────
    try:
        report["geoip"] = geoip_run(parsed)
    except Exception as e:
        report["geoip"] = {"status": "unavailable", "error": str(e)}

    # ── Layer 4: Explainability (SHAP) ──────────────────────────────────────
    try:
        report["explainability"] = explain_run(parsed, raw_str)
    except Exception as e:
        report["explainability"] = {"status": "unavailable", "error": str(e)}

    # ── Layer 5: NLP Extra (Zero-shot NLI intent) ────────────────────────────
    try:
        report["nlp_extra"] = {
            "intent": nli_run(parsed),
        }
    except Exception as e:
        report["nlp_extra"] = {"status": "unavailable", "error": str(e)}

    # ── Vision Layer ────────────────────────────────────────────────────────
    images = extract_images_from_eml(eml_bytes)
    report["vision"] = {}

    try:
        ocr_result = extract_ocr_text(images)
        report["vision"]["ocr"] = ocr_result
        if ocr_result.get("has_image_text"):
            report["flags"].append(
                f"[VISION] Text extracted from {ocr_result['image_count']} image(s) "
                f"— {len(ocr_result['ocr_text'])} chars"
            )
    except Exception as exc:
        report["vision"]["ocr"] = {"error": str(exc)}

    try:
        qr_result = decode_qr_codes(images)
        report["vision"]["qr"] = qr_result
        if qr_result.get("quishing_suspected"):
            report["flags"].append(
                f"[VISION] ⚠ QR-code URLs detected ({len(qr_result['qr_urls'])}) — quishing risk"
            )
            # Re-run url_reputation on QR URLs if that layer is available
            for qr_url in qr_result.get("qr_urls", [])[:3]:    # cap at 3
                try:
                    from layers.forensics.url_reputation import check_url_reputation
                    qr_rep = check_url_reputation(qr_url)
                    report["flags"].append(
                        f"[VISION] QR URL {qr_url[:60]}… → VT malicious={qr_rep.get('malicious_count', '?')}"
                    )
                except Exception:
                    pass
    except Exception as exc:
        report["vision"]["qr"] = {"error": str(exc)}

    try:
        ocr_texts = []
        if "ocr" in report["vision"] and "ocr_text" in report["vision"]["ocr"]:
            ocr_texts = [report["vision"]["ocr"]["ocr_text"]]
        
        # Scoped to match your internal variables
        sender_domain = parsed.from_domain or ""
        logo_result = detect_brand_spoofing(ocr_texts, sender_domain)
        report["vision"]["logo"] = logo_result
        if logo_result.get("spoofing_detected"):
            brands = ", ".join(logo_result.get("spoofing_brands", []))
            report["flags"].append(
                f"[VISION] ⚠ Brand logo spoofing — '{brands}' visible in image "
                f"but sender domain '{sender_domain}' is not trusted"
            )
    except Exception as exc:
        report["vision"]["logo"] = {"error": str(exc)}

    # ── Attachment Layer ────────────────────────────────────────────────────
    try:                                          # FIX Bug 1: was 8 spaces, now 4
        attachments = extract_attachments(eml_bytes)
        report["attachments"] = {}

        try:
            pdf_result = scan_pdf_attachments(attachments)
            report["attachments"]["pdf"] = pdf_result
            if pdf_result["suspicious"]:
                flagged = pdf_result["high_risk_files"] or ["see results"]
                report["flags"].append(f"[ATTACH] ⚠ Suspicious PDF(s): {flagged}")   # FIX Bug 2
            elif pdf_result["pdf_count"] > 0:
                report["flags"].append(f"[ATTACH] {pdf_result['pdf_count']} PDF(s) scanned — CLEAN")
        except Exception as exc:
            report["attachments"]["pdf"] = {"error": str(exc)}

        try:
            office_result = scan_office_attachments(attachments)
            report["attachments"]["office"] = office_result
            if office_result["suspicious"]:
                flagged = office_result["high_risk_files"] or ["see results"]
                report["flags"].append(f"[ATTACH] ⚠ Macro threat in Office file(s): {flagged}")   # FIX Bug 2
            elif office_result["office_count"] > 0:
                report["flags"].append(f"[ATTACH] {office_result['office_count']} Office file(s) scanned — CLEAN")
        except Exception as exc:
            report["attachments"]["office"] = {"error": str(exc)}

    except Exception as exc:
        report["attachments"] = {"error": str(exc)}

    # ── SMTP Chain Traversal ────────────────────────────────────────────────
    try:
        smtp_result = analyze_smtp_chain(eml_bytes)
        report["smtp_chain"] = smtp_result
        for anomaly in smtp_result.get("anomalies", []):
            report["flags"].append(f"[SMTP] {anomaly}")
        if smtp_result.get("chain_suspicious"):
            report["flags"].append(
                f"[SMTP] ⚠ Chain anomalies detected ({len(smtp_result['anomalies'])} issue(s))"
            )
    except Exception as exc:
        report["smtp_chain"] = {"error": str(exc)}

    # ── LLM Analyst (Tier 2) — runs on EVERY email, no gate ─────────────────
    # DeBERTa / XGBoost / fusion output stays in report["text_structural"] as
    # advisory evidence. The LLM verdict (validated against forensic facts)
    # is the final verdict.
    try:
        llm = llm_run(parsed, eml_bytes, report)
    except Exception as exc:
        llm = {
            "status": "fallback", "verdict": "HUMAN_REVIEW", "confidence": 0,
            "reasons": [f"LLM analyst crashed ({type(exc).__name__}); needs human review."],
            "error": str(exc)[:150],
        }

    report["llm_analyst"] = llm
    report["final_verdict"] = llm["verdict"]
    report["final_confidence"] = llm.get("confidence", 0)
    report["decision_reason"] = " ".join(llm.get("reasons", [])[:3]) or "No reason returned."
    for note in llm.get("validation_notes", []) or []:
        report["flags"].append(f"[VALIDATOR] {note}")

    # ── PII Masking (always last) ──────────────────────────────────────────
    report = mask_report(report)

    return report