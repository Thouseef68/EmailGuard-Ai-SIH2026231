"""
eml_feature_extractor_v4.py
Extracts XGBoost V4-Clean's 20 text-content features from a ParsedEmail
(from core/eml_parser.py). Replaces the old 42-feature V2 extractor.
"""
import re
import numpy as np
from core.eml_parser import ParsedEmail          # already in your backend

URL_RE    = re.compile(r'https?://[^\s<>"\']+', re.I)
DOMAIN_RE = re.compile(r'https?://([^/\s<>"\']+)', re.I)
ENC_WORD  = re.compile(r'=\?[^?]+\?[BbQq]\?[^?]+\?=')

URGENT_KW = ['urgent','immediately','alert','warning','suspended','verify',
             'confirm','expire','expired','action required','limited time',
             'act now','deadline','important notice','your account']
MONEY_KW  = ['prize','won','winner','reward','cash','money','transfer',
             'payment','refund','credit','loan','offer','₹','rs.','inr',
             'lakh','crore','salary','income','earning','compensation']
CRED_KW   = ['password','username','login','credential','otp','pin',
             'cvv','aadhaar','pan number','verify your','update your',
             'confirm your','enter your','provide your']
INDIAN_LEGIT_KW = [
    'zomato','swiggy','paytm','phonepe','google pay','gpay','irctc',
    'sbi','hdfc','icici','kotak','axis bank','naukri','linkedin',
    'amazon','flipkart','myntra','indmoney','groww','zerodha',
    'upstox','jio','airtel','bsnl','ola','uber','makemytrip',
    'yatra','cleartrip','bigbasket','blinkit',
]
SUSPICIOUS_TLDS = [
    '.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top',
    '.click','.download','.stream','.loan','.win','.party',
    '.review','.science','.work','.date','.racing','.cricket',
]

# Must match EXACTLY the order in xgboost_v4_clean_feature_cols.json
FEATURE_COLS = [
    'url_count','unique_domains','has_https','has_http_only',
    'word_count','char_count','avg_word_len',
    'urgent_count','money_count','cred_count',
    'exclamation_count','question_count','caps_ratio',
    'subj_upper_ratio','subj_has_urgent','subj_length_clean',
    'has_noreply','has_reply_to',
    'indian_legit_count','has_suspicious_tld',
]


def _decode_subject(raw: str) -> str:
    """Strip RFC2047 encoded-word wrappers from a subject string."""
    return ENC_WORD.sub(
        lambda m: m.group(0)[m.group(0).index('?', 8) + 1:
                              m.group(0).rindex('?=')],
        raw
    ).strip()[:500]


def extract_v4_features(parsed: ParsedEmail) -> dict:
    """
    Returns a dict {feature_name: value} for XGBoost V4-Clean.
    Pass the full email text (headers + body) through the same
    pipeline used during training.

    Args:
        parsed: ParsedEmail from core/eml_parser.py
    Returns:
        dict with keys matching FEATURE_COLS
    """
    # ── Build a single text blob (header block + decoded body)
    # eml_parser gives us: subject, from_addr, body_text, body_html, raw_headers
    subject_raw = parsed.subject or ''
    body_plain  = parsed.body_text or ''
    body_html   = parsed.body_html or ''

    # Combine: use plain text body first, fall back to HTML
    body_combined = body_plain if body_plain.strip() else body_html

    # Full text as it appeared during CSV training:
    # "Subject: <subject>\n<body>"
    full_text = f"Subject: {subject_raw}\n{body_combined}"
    tl        = full_text.lower()

    # ── Subject
    subj      = _decode_subject(subject_raw)
    subj_l    = subj.lower()
    subj_len  = len(subj)
    subj_alpha = [c for c in subj if c.isalpha()]
    subj_upper_ratio = (sum(c.isupper() for c in subj_alpha) /
                        len(subj_alpha)) if subj_alpha else 0.0
    subj_has_urgent  = int(any(kw in subj_l for kw in URGENT_KW))

    # ── URLs & domains  (scan both plain and HTML body)
    scan_text  = full_text
    urls       = URL_RE.findall(scan_text)
    domains    = DOMAIN_RE.findall(scan_text)
    url_count    = len(urls)
    unique_doms  = len(set(d.lower() for d in domains))
    has_https    = int(any('https://' in u.lower() for u in urls))
    has_http_only= int(any(
        u.lower().startswith('http://') for u in urls
    ))

    # ── Body text (strip HTML tags for word/char counts)
    body_stripped = re.sub(r'<[^>]+>', ' ', body_combined)
    body_stripped = re.sub(r'\s+', ' ', body_stripped).strip()
    words         = body_stripped.split()
    word_count    = len(words)
    char_count    = len(body_stripped)
    avg_wl        = float(np.mean([len(w) for w in words])) if words else 0.0

    # ── Keyword counts  (search full_text lowercased)
    urgent_count = sum(kw in tl for kw in URGENT_KW)
    money_count  = sum(kw in tl for kw in MONEY_KW)
    cred_count   = sum(kw in tl for kw in CRED_KW)

    # ── Punctuation / caps
    excl       = full_text.count('!')
    ques       = full_text.count('?')
    alpha_body = [c for c in body_stripped if c.isalpha()]
    caps_ratio = (sum(c.isupper() for c in alpha_body) /
                  len(alpha_body)) if alpha_body else 0.0

    # ── Header signals  (use raw_headers from parser — more reliable than regex)
    raw_headers_l = (parsed.raw_headers or '').lower()
    has_noreply   = int('no-reply' in raw_headers_l or
                        'noreply'  in raw_headers_l or
                        'donotreply' in raw_headers_l or
                        'no_reply' in raw_headers_l)
    has_reply_to  = int('reply-to:' in raw_headers_l)

    # ── Indian legit brands (search both subject and body)
    indian_legit_count = sum(kw in tl for kw in INDIAN_LEGIT_KW)

    # ── Suspicious TLD
    dom_str      = ' '.join(d.lower() for d in domains)
    has_susp_tld = int(any(tld in dom_str for tld in SUSPICIOUS_TLDS))

    return {
        'url_count'        : url_count,
        'unique_domains'   : unique_doms,
        'has_https'        : has_https,
        'has_http_only'    : has_http_only,
        'word_count'       : word_count,
        'char_count'       : char_count,
        'avg_word_len'     : avg_wl,
        'urgent_count'     : urgent_count,
        'money_count'      : money_count,
        'cred_count'       : cred_count,
        'exclamation_count': excl,
        'question_count'   : ques,
        'caps_ratio'       : caps_ratio,
        'subj_upper_ratio' : subj_upper_ratio,
        'subj_has_urgent'  : subj_has_urgent,
        'subj_length_clean': subj_len,
        'has_noreply'      : has_noreply,
        'has_reply_to'     : has_reply_to,
        'indian_legit_count': indian_legit_count,
        'has_suspicious_tld': has_susp_tld,
    }


def features_as_array(parsed: ParsedEmail) -> np.ndarray:
    """Returns features as a (1, 20) float32 array in FEATURE_COLS order."""
    feat = extract_v4_features(parsed)
    return np.array(
        [[feat[c] for c in FEATURE_COLS]],
        dtype=np.float32
    )