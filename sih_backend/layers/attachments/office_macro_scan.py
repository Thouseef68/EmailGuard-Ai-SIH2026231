# layers/attachments/office_macro_scan.py
"""
Office document macro scanning via oletools (olevba).
Flags auto-execute triggers, suspicious API calls, and embedded IOCs.
"""
from typing import List, Dict, Any
from core.attachment_extractor import EmailAttachment

# Function names that fire without user interaction
_AUTO_EXEC = {
    'autoopen', 'auto_open', 'document_open', 'workbook_open',
    'autoclose', 'auto_close', 'document_close', 'workbook_close',
    'autoexit', 'autoexec', 'automacro', 'application_startup',
    'document_beforeclose', 'workbook_beforeclose',
}


def scan_office_attachments(attachments: List[EmailAttachment]) -> Dict[str, Any]:
    """
    Scan every Office attachment for VBA macros.

    Returns:
        {
          "office_count": int,
          "results": list,
          "high_risk_files": list,
          "suspicious": bool
        }
    """
    office_files = [a for a in attachments if a.is_office]
    if not office_files:
        return {"office_count": 0, "results": [], "high_risk_files": [], "suspicious": False}

    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        return {
            "office_count": len(office_files),
            "results": [{"error": "oletools not installed — run: pip install oletools"}],
            "high_risk_files": [],
            "suspicious": False,
        }

    results = []
    high_risk = []

    for att in office_files:
        entry: Dict[str, Any] = {
            "filename": att.filename,
            "size_bytes": len(att.data),
            "has_macros": False,
            "macro_stream_count": 0,
            "auto_exec_triggers": [],
            "olevba_flags": [],          # {"type", "keyword", "description"}
            "iocs": [],                  # IPs / URLs / paths found in macro code
            "risk_score": 0,
            "risk_reasons": [],
            "verdict": "CLEAN",
            "error": None,
        }

        try:
            parser = VBA_Parser(att.filename, data=att.data)
            entry["has_macros"] = parser.detect_vba_macros()

            if not entry["has_macros"]:
                results.append(entry)
                continue

            # Collect all macro source code
            all_code = ""
            for (_, _, _, vba_code) in parser.extract_macros():
                all_code += vba_code + "\n"
                entry["macro_stream_count"] += 1

            # Auto-exec trigger check (name-based)
            code_lower = all_code.lower()
            for trigger in _AUTO_EXEC:
                if trigger in code_lower:
                    entry["auto_exec_triggers"].append(trigger)

            # olevba structured analysis
            for (flag_type, keyword, description) in parser.analyze_macros():
                entry["olevba_flags"].append({
                    "type": flag_type,
                    "keyword": keyword,
                    "description": description,
                })
                if flag_type == "IOC":
                    entry["iocs"].append(keyword)

            # Risk scoring
            score = 0
            reasons = []

            if entry["auto_exec_triggers"]:
                score += 4
                reasons.append(
                    f"Auto-execute triggers: {entry['auto_exec_triggers']}"
                )

            suspicious_flags = [
                f for f in entry["olevba_flags"]
                if f["type"] in ("Suspicious", "AutoExec")
            ]
            score += len(suspicious_flags)
            if suspicious_flags:
                reasons.append(
                    f"{len(suspicious_flags)} suspicious keyword(s): "
                    + ", ".join(f["keyword"] for f in suspicious_flags[:5])
                )

            if entry["iocs"]:
                score += 3
                reasons.append(f"IOCs in macro code: {entry['iocs'][:3]}")

            entry["risk_score"] = score
            entry["risk_reasons"] = reasons

            if score >= 5:
                entry["verdict"] = "HIGH_RISK"
                high_risk.append(att.filename)
            elif score >= 2:
                entry["verdict"] = "SUSPICIOUS"
            else:
                entry["verdict"] = "HAS_MACROS"    # present but no clear red flags

        except Exception as exc:
            entry["error"] = str(exc)
            entry["verdict"] = "ERROR"

        results.append(entry)

    return {
        "office_count": len(office_files),
        "results": results,
        "high_risk_files": high_risk,
        "suspicious": any(r["verdict"] in ("HIGH_RISK", "SUSPICIOUS") for r in results),
    }