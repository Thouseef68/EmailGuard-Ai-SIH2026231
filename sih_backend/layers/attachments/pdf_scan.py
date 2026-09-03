# layers/attachments/pdf_scan.py
"""
PDF attachment scanning for malicious indicators.
Two-pass: raw byte keyword search + pikepdf structural validation.
"""
import io
from typing import List, Dict, Any
from core.attachment_extractor import EmailAttachment

# keyword → (risk_weight, human description)
_KEYWORDS: Dict[bytes, tuple] = {
    b'/JS':           (3, 'JavaScript code'),
    b'/JavaScript':   (3, 'JavaScript code'),
    b'/OpenAction':   (3, 'Auto-execute action on open'),
    b'/AA':           (2, 'Additional Actions (auto-trigger)'),
    b'/Launch':       (3, 'External process launch'),
    b'/EmbeddedFile': (1, 'Embedded file — possible dropper'),
    b'/RichMedia':    (1, 'Rich media embed'),
    b'/XFA':          (1, 'XFA form — complex attack surface'),
    b'/ObjStm':       (1, 'Object stream — can conceal objects'),
}


def _keyword_scan(data: bytes) -> Dict[str, Any]:
    hits = {}
    for kw, (weight, desc) in _KEYWORDS.items():
        count = data.count(kw)
        if count > 0:
            hits[kw.decode()] = {
                "count": count,
                "weight": weight,
                "meaning": desc,
            }
    return hits


def _pikepdf_check(data: bytes) -> Dict[str, Any]:
    out = {"openable": None, "encrypted": False, "page_count": None, "error": None}
    try:
        import pikepdf
        pdf = pikepdf.open(io.BytesIO(data))
        out["openable"] = True
        out["encrypted"] = pdf.is_encrypted
        out["page_count"] = len(pdf.pages)
    except Exception as exc:
        err = str(exc).lower()
        if "password" in err or "encrypt" in err:
            out["openable"] = False
            out["encrypted"] = True
            out["error"] = "Password-encrypted PDF"
        else:
            out["openable"] = False
            out["error"] = str(exc)
    return out


def scan_pdf_attachments(attachments: List[EmailAttachment]) -> Dict[str, Any]:
    """
    Scan every PDF attachment.

    Returns:
        {
          "pdf_count": int,
          "results": list,          # per-file detail
          "high_risk_files": list,  # filenames with verdict HIGH_RISK
          "suspicious": bool
        }
    """
    pdfs = [a for a in attachments if a.is_pdf]
    if not pdfs:
        return {"pdf_count": 0, "results": [], "high_risk_files": [], "suspicious": False}

    results = []
    high_risk = []

    for att in pdfs:
        hits = _keyword_scan(att.data)
        pik = _pikepdf_check(att.data)

        score = sum(info["weight"] for info in hits.values())
        reasons = [
            f"{kw} ×{info['count']} — {info['meaning']}"
            for kw, info in hits.items()
        ]

        if pik["encrypted"]:
            score += 2
            reasons.append("Password-encrypted — contents hidden")
        if pik["openable"] is False and not pik["encrypted"]:
            score += 2
            reasons.append("Malformed / unparseable PDF")

        if score >= 7:      # raised from 5 — bank PDFs with links were triggering this
            verdict = "HIGH_RISK"
            high_risk.append(att.filename)
        elif score >= 4:    # raised from 2
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        results.append({
            "filename": att.filename,
            "size_bytes": len(att.data),
            "keyword_hits": hits,
            "pikepdf": pik,
            "risk_score": score,
            "risk_reasons": reasons,
            "verdict": verdict,
        })

    return {
        "pdf_count": len(pdfs),
        "results": results,
        "high_risk_files": high_risk,
        "suspicious": any(r["verdict"] != "CLEAN" for r in results),
    }