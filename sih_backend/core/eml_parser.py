"""
core/eml_parser.py — .eml -> structured ParsedEmail

Single parsing pass shared by ALL layers (text/structural, forensics,
vision, attachments). Every layer reads from the same ParsedEmail object
instead of re-parsing the raw bytes.
"""

import re
import email
import email.policy
from dataclasses import dataclass, field


@dataclass
class ParsedEmail:
    subject: str = ""
    from_addr: str = ""
    from_domain: str = ""
    to_addr: str = ""
    cc_addr: str = ""
    bcc_addr: str = ""
    reply_to_addr: str = ""
    reply_to_domain: str = ""
    message_id: str = ""
    return_path_addr: str = ""
    return_path_domain: str = ""
    received_headers: list = field(default_factory=list)
    authentication_results: str = ""
    dkim_signature: str = ""
    received_spf: str = ""
    spf: str = "none"
    dkim: str = "none"
    dmarc: str = "none"
    body_text: str = ""
    has_html: bool = False
    has_plain: bool = False
    is_multipart: bool = False
    attachment_count: int = 0
    attachment_filenames: list = field(default_factory=list)
    image_parts: list = field(default_factory=list)
    raw_headers: dict = field(default_factory=dict)
    header_block_text: str = ""
    total_email_length: int = 0


def _domain_of(addr: str) -> str:
    if not addr or "@" not in addr:
        return ""
    return addr.strip().lower().split("@")[-1].strip(">")


def _extract_auth_result(auth_header: str, mechanism: str) -> str:
    if not auth_header:
        return "none"
    match = re.search(rf"{mechanism}=(\w+)", auth_header, re.IGNORECASE)
    return match.group(1).lower() if match else "none"


def parse_eml(eml_bytes: bytes) -> ParsedEmail:
    """Parse raw .eml bytes into a ParsedEmail. Shared by every layer."""
    msg = email.message_from_bytes(eml_bytes, policy=email.policy.default)

    parsed = ParsedEmail()

    parsed.total_email_length = len(eml_bytes)
    try:
        decoded = eml_bytes.decode("utf-8", errors="ignore")
        parsed.header_block_text = decoded.split("\n\n", 1)[0]
    except Exception:
        parsed.header_block_text = ""

    parsed.subject = str(msg.get("Subject", "") or "")

    from_hdr = str(msg.get("From", "") or "")
    parsed.from_addr = from_hdr
    parsed.from_domain = _domain_of(from_hdr)

    parsed.to_addr = str(msg.get("To", "") or "")
    parsed.cc_addr = str(msg.get("Cc", "") or "")
    parsed.bcc_addr = str(msg.get("Bcc", "") or "")
    parsed.message_id = str(msg.get("Message-ID", "") or "")

    reply_to_hdr = str(msg.get("Reply-To", "") or "")
    parsed.reply_to_addr = reply_to_hdr
    parsed.reply_to_domain = _domain_of(reply_to_hdr) if reply_to_hdr else parsed.from_domain

    return_path_hdr = str(msg.get("Return-Path", "") or "")
    parsed.return_path_addr = return_path_hdr
    parsed.return_path_domain = _domain_of(return_path_hdr) if return_path_hdr else parsed.from_domain

    parsed.received_headers = msg.get_all("Received", []) or []

    parsed.authentication_results = str(msg.get("Authentication-Results", "") or "")
    parsed.dkim_signature = str(msg.get("DKIM-Signature", "") or "")
    parsed.received_spf = str(msg.get("Received-SPF", "") or "")

    parsed.spf = _extract_auth_result(parsed.authentication_results, "spf")
    parsed.dkim = _extract_auth_result(parsed.authentication_results, "dkim")
    parsed.dmarc = _extract_auth_result(parsed.authentication_results, "dmarc")

    parsed.is_multipart = msg.is_multipart()

    body_parts = []
    attachment_count = 0
    attachment_filenames = []
    image_parts = []
    has_html = False
    has_plain = False

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", "") or "")

            if "attachment" in disposition:
                attachment_count += 1
                filename = part.get_filename() or "unnamed"
                attachment_filenames.append(filename)
                continue

            if content_type.startswith("image/"):
                try:
                    image_parts.append(part.get_payload(decode=True))
                except Exception:
                    pass
                continue

            if content_type == "text/plain":
                has_plain = True
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass
            elif content_type == "text/html":
                has_html = True
                try:
                    html_content = part.get_content()
                    text_only = re.sub(r"<[^>]+>", " ", html_content)
                    body_parts.append(text_only)
                except Exception:
                    pass
    else:
        content_type = msg.get_content_type()
        try:
            content = msg.get_content()
        except Exception:
            content = ""
        if content_type == "text/html":
            has_html = True
            body_parts.append(re.sub(r"<[^>]+>", " ", content))
        else:
            has_plain = True
            body_parts.append(content)

    parsed.body_text = "\n".join(body_parts).strip()
    parsed.has_html = has_html
    parsed.has_plain = has_plain
    parsed.attachment_count = attachment_count
    parsed.attachment_filenames = attachment_filenames
    parsed.image_parts = image_parts
    parsed.raw_headers = {k: str(v) for k, v in msg.items()}

    return parsed


# ── XGBoost V3 feature extraction (42 features + 3 ratio features) ─────────
_URGENT = ["urgent","immediately","alert","verify","suspended","limited",
           "expire","click","confirm","update","locked","unauthorized","security"]
_MONEY  = ["free","win","prize","cash","dollar","rupee","reward","offer"]
_CRED   = ["password","credential","ssn","card"]   # "login"/"account" removed — too broad


def extract_xgb_features(parsed: ParsedEmail, raw_str: str) -> dict:
    """Convert a ParsedEmail into the 45-feature dict for XGBoost V3."""
    fl   = (parsed.subject + " " + parsed.body_text).lower()
    urls = re.findall(r'https?://\S+', fl)
    doms = set(re.findall(r'https?://([^/\s]+)', fl))
    http  = sum(1 for u in urls if u.startswith("http://"))
    https = sum(1 for u in urls if u.startswith("https://"))
    tu    = max(len(urls), 1)
    kb    = max(len(raw_str) / 1000, 1)
    subj  = parsed.subject

    def hdr(h): return 1 if parsed.raw_headers.get(h) else 0

    return {
        "email_length":               len(raw_str),
        "header_length":              len(parsed.header_block_text),
        "body_length":                len(parsed.body_text),
        "subject_length":             len(subj),
        "subject_word_count":         len(subj.split()),
        "subject_exclamation_count":  subj.count("!"),
        "subject_question_count":     subj.count("?"),
        "subject_uppercase_ratio":    sum(1 for c in subj if c.isupper()) / max(len(subj), 1),
        "from_present":               hdr("From"),
        "to_present":                 hdr("To"),
        "cc_present":                 hdr("Cc"),
        "bcc_present":                hdr("Bcc"),
        "reply_to_present":           hdr("Reply-To"),
        "date_present":               hdr("Date"),
        "message_id_present":         hdr("Message-ID"),
        "from_count":                 len(parsed.raw_headers.get("From", "").split(",")),
        "to_count":                   len(parsed.raw_headers.get("To", "").split(",")),
        "cc_count":                   len(parsed.raw_headers.get("Cc", "").split(",")),
        "bcc_count":                  len(parsed.raw_headers.get("Bcc", "").split(",")),
        "received_count":             len(parsed.received_headers),
        "return_path_present":        hdr("Return-Path"),
        "authentication_results_present": hdr("Authentication-Results"),
        "dkim_signature_present":     1 if parsed.dkim_signature else 0,
        "spf_present":                1 if "spf" in fl else 0,
        "mime_version_present":       hdr("MIME-Version"),
        "content_type_present":       hdr("Content-Type"),
        "multipart":                  1 if parsed.is_multipart else 0,
        "attachment_count":           parsed.attachment_count,
        "body_url_count":             len(urls),
        "unique_domain_count":        len(doms),
        "http_url_count":             http,
        "https_url_count":            https,
        "html_present":               1 if parsed.has_html else 0,
        "plain_text_present":         1 if parsed.has_plain else 0,
        "body_exclamation_count":     parsed.body_text.count("!"),
        "body_question_count":        parsed.body_text.count("?"),
        "body_uppercase_ratio":       sum(1 for c in parsed.body_text if c.isupper()) / max(len(parsed.body_text), 1),
        "urgent_word_count":          sum(1 for w in _URGENT if w in fl),
        "money_word_count":           sum(1 for w in _MONEY  if w in fl),
        "credential_word_count":      sum(1 for w in _CRED   if w in fl),
        "login_word_count":           fl.count("login"),
        "verify_word_count":          fl.count("verif"),
        # ── 3 ratio features (V3 new) ──────────────────────────────────
        "https_ratio":                https / tu,
        "url_per_kb":                 len(urls) / kb,
        "dom_per_url":                len(doms) / tu,
    }