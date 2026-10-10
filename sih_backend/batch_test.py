import os
os.environ["HF_DEACTIVATE_ASYNC_LOAD"] = "1"   # MUST be first â€” fixes Windows crash

import sys, json, re, time
import numpy as np
import torch
import torch.nn as nn
import xgboost as xgb
import email as _email_lib
from transformers import AutoTokenizer, AutoModelForSequenceClassification

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core.eml_parser import ParsedEmail, parse_eml as shared_parse_eml

# â”€â”€ CONFIG â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
EMAIL_DIR      = "sih_phase4_real_100_eml"
V3_MODEL       = "models/xgboost_phishing_v3.json"
V3_CONFIG      = "models/xgboost_feature_cols_v3.json"
V4_MODEL       = "models/xgboost_v4_clean.json"
V4_CONFIG      = "models/xgboost_v4_clean_feature_cols.json"
BACKBONE_DIR   = "models/deberta_phishing_v12_adult_bait/backbone"
HEAD_PATH      = "models/deberta_phishing_v12_adult_bait/v12_hybrid_head.pt"
SCALER_PATH    = "models/deberta_phishing_v12_adult_bait/behavior_feature_scaler.json"
DEVICE         = torch.device("cpu")
FUSION_THRESH  = 0.50
V4_THRESH      = 0.55
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

# â”€â”€ KEYWORD LISTS (V4 extractor) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
URL_RE    = re.compile(r'https?://[^\s<>"\']+', re.I)
DOMAIN_RE = re.compile(r'https?://([^/\s<>"\']+)', re.I)
ENC_WORD  = re.compile(r'=\?[^?]+\?[BbQq]\?[^?]+\?=')
URGENT_KW = ['urgent','immediately','alert','warning','suspended','verify',
             'confirm','expire','expired','action required','limited time',
             'act now','deadline','important notice','your account']
MONEY_KW  = ['prize','won','winner','reward','cash','money','transfer',
             'payment','refund','credit','loan','offer','â‚¹','rs.','inr',
             'lakh','crore','salary','income','earning','compensation']
CRED_KW   = ['password','username','login','credential','otp','pin',
             'cvv','aadhaar','pan number','verify your','update your',
             'confirm your','enter your','provide your']
INDIAN_KW = ['zomato','swiggy','paytm','phonepe','google pay','gpay','irctc',
             'sbi','hdfc','icici','kotak','axis bank','naukri','linkedin',
             'amazon','flipkart','myntra','indmoney','groww','zerodha',
             'upstox','jio','airtel','bsnl','ola','uber','makemytrip',
             'yatra','cleartrip','bigbasket','blinkit']
SUSP_TLDS = ['.xyz','.tk','.ml','.ga','.cf','.gq','.pw','.top',
             '.click','.download','.stream','.loan','.win','.party']

# â”€â”€ V4 FEATURE EXTRACTOR â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def extract_v4(parsed: ParsedEmail) -> dict:
    subj_raw = parsed.subject or ''
    body     = parsed.body_text or parsed.body_html or ''
    full     = f"Subject: {subj_raw}\n{body}"
    tl       = full.lower()

    subj = ENC_WORD.sub(
        lambda m: m.group(0)[m.group(0).index('?',8)+1:m.group(0).rindex('?=')],
        subj_raw).strip()[:500]
    subj_l = subj.lower()
    sa = [c for c in subj if c.isalpha()]
    subj_upper = sum(c.isupper() for c in sa)/len(sa) if sa else 0.0
    subj_urg   = int(any(k in subj_l for k in URGENT_KW))
    subj_len   = len(subj)

    urls    = URL_RE.findall(full)
    domains = DOMAIN_RE.findall(full)
    has_https     = int(any('https://' in u.lower() for u in urls))
    has_http_only = int(any(u.lower().startswith('http://') for u in urls))

    body_stripped = re.sub(r'<[^>]+',' ', body)
    body_stripped = re.sub(r'\s+',' ', body_stripped).strip()
    words = body_stripped.split()
    alpha = [c for c in body_stripped if c.isalpha()]

    hdrs_l = (parsed.raw_headers or '').lower()

    return {
        'url_count'         : len(urls),
        'unique_domains'    : len(set(d.lower() for d in domains)),
        'has_https'         : has_https,
        'has_http_only'     : has_http_only,
        'word_count'        : len(words),
        'char_count'        : len(body_stripped),
        'avg_word_len'      : float(np.mean([len(w) for w in words])) if words else 0.0,
        'urgent_count'      : sum(k in tl for k in URGENT_KW),
        'money_count'       : sum(k in tl for k in MONEY_KW),
        'cred_count'        : sum(k in tl for k in CRED_KW),
        'exclamation_count' : full.count('!'),
        'question_count'    : full.count('?'),
        'caps_ratio'        : sum(c.isupper() for c in alpha)/len(alpha) if alpha else 0.0,
        'subj_upper_ratio'  : subj_upper,
        'subj_has_urgent'   : subj_urg,
        'subj_length_clean' : subj_len,
        'has_noreply'       : int('no-reply' in hdrs_l or 'noreply' in hdrs_l),
        'has_reply_to'      : int('reply-to:' in hdrs_l),
        'indian_legit_count': sum(k in tl for k in INDIAN_KW),
        'has_suspicious_tld': int(any(t in ' '.join(domains).lower() for t in SUSP_TLDS)),
    }

# â”€â”€ DEBERTA V12 HYBRID HEAD â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
class HybridHead(nn.Module):
    def __init__(self):
        super().__init__()
        self.behavior_mlp      = nn.Sequential(nn.Linear(14,32), nn.GELU(),
                                               nn.Linear(32,32), nn.GELU())
        self.fusion_linear     = nn.Linear(1056, 256)
        self.gelu              = nn.GELU()
        self.dropout           = nn.Dropout(0.1)
        self.hybrid_classifier = nn.Linear(256, 2)

    def forward(self, cls_vec, beh):
        x = torch.cat([cls_vec, self.behavior_mlp(beh)], dim=-1)
        return self.hybrid_classifier(self.dropout(self.gelu(self.fusion_linear(x))))

# â”€â”€ LOAD ALL MODELS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("Loading models...")

# V12
print("  DeBERTa V12...")
backbone  = AutoModelForSequenceClassification.from_pretrained(
    BACKBONE_DIR, num_labels=2,
    ignore_mismatched_sizes=True, low_cpu_mem_usage=False
).to(DEVICE).eval()
tokenizer = AutoTokenizer.from_pretrained(BACKBONE_DIR)
head      = HybridHead().to(DEVICE)
head.load_state_dict(torch.load(HEAD_PATH, map_location=DEVICE), strict=False)
head.eval()
with open(SCALER_PATH) as f:
    sc = json.load(f)
SC_MEAN  = np.array(sc['mean'],  dtype=np.float32)
SC_SCALE = np.array(sc['scale'], dtype=np.float32)
print("  V12 âœ…")

# V3
print("  XGBoost V3...")
v3_model = xgb.XGBClassifier()
v3_model.load_model(V3_MODEL)
with open(V3_CONFIG) as f:
    v3_cfg = json.load(f)
V3_COLS = v3_cfg['features'] if isinstance(v3_cfg, dict) else v3_cfg
print(f"  V3 âœ…  ({len(V3_COLS)} features)")

# V4
print("  XGBoost V4-Clean...")
v4_model = xgb.XGBClassifier()
v4_model.load_model(V4_MODEL)
with open(V4_CONFIG) as f:
    v4_cfg = json.load(f)
V4_COLS = v4_cfg['features']
print(f"  V4 âœ…  ({len(V4_COLS)} features)")

# â”€â”€ INFERENCE FUNCTIONS â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
@torch.no_grad()
def v12_prob(parsed: ParsedEmail) -> float:
    text = f"Subject: {parsed.subject or ''}\n{parsed.body_text or parsed.body_html or ''}"[:2000]
    enc  = tokenizer(text, padding='max_length', truncation=True,
                     max_length=512, return_tensors='pt',
                     add_special_tokens=False)
    ids  = enc['input_ids'].to(DEVICE)
    mask = enc['attention_mask'].to(DEVICE)
    tt   = enc.get('token_type_ids')
    if tt is not None: tt = tt.to(DEVICE)
    out     = backbone.deberta(input_ids=ids, attention_mask=mask, token_type_ids=tt)
    cls_vec = backbone.pooler(out.last_hidden_state)
    beh     = torch.zeros(1, 14, device=DEVICE)   # zeroed â€” .eml behavior computed separately
    logits  = head(cls_vec, beh)
    return float(torch.softmax(logits, dim=-1)[0,1])

def v3_prob(parsed: ParsedEmail) -> float:
    from layers.text_structural.xgboost_model import build_xgb_features
    feat = build_xgb_features(parsed)
    arr  = np.array([[feat.get(c, 0) for c in V3_COLS]], dtype=np.float32)
    return float(v3_model.predict_proba(arr)[0,1])

def v4_prob(parsed: ParsedEmail) -> float:
    feat = extract_v4(parsed)
    arr  = np.array([[feat.get(c, 0.0) for c in V4_COLS]], dtype=np.float32)
    return float(v4_model.predict_proba(arr)[0,1])

def fuse(p_v12: float, p_xgb: float) -> tuple:
    f = 0.5*p_v12 + 0.5*p_xgb
    if 0.40 <= f <= 0.65: tag = 'HITL'
    elif f >= FUSION_THRESH: tag = 'PHISH'
    else: tag = 'LEGIT'
    return f, tag

# â”€â”€ PARSE EML â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
def parse_eml(path: str) -> ParsedEmail:
    with open(path, 'rb') as f:
        raw = f.read()
    return shared_parse_eml(raw)

def get_label(fname: str) -> int:
    n = fname.lower()
    if '_phishing' in n or '_spam' in n: return 1
    if '_legitimate' in n or '_legit' in n or '_ham' in n: return 0
    return -1

# â”€â”€ MAIN â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
eml_files = sorted([
    os.path.join(EMAIL_DIR, f)
    for f in os.listdir(EMAIL_DIR) if f.lower().endswith('.eml')
])
print(f"\nRunning on {len(eml_files)} emails...\n")

v3_correct = v4_correct = scored = 0
disagree   = []

print(f"{'#':>3}  {'File':<30} {'True':>5}  "
      f"{'V12':>5} {'V3':>5} {'FusV3':>6} {'V3âœ“':>3}  "
      f"{'V4':>5} {'FusV4':>6} {'V4âœ“':>3}")
print("-"*80)

for i, path in enumerate(eml_files):
    fname = os.path.basename(path)
    true  = get_label(fname)
    if true == -1: continue

    try:    parsed = parse_eml(path)
    except Exception as e: print(f"{i+1:>3}  {fname:<30} PARSE ERROR: {type(e).__name__}: {e}"); continue

    try:    pv12 = v12_prob(parsed)
    except: pv12 = 0.5

    try:    pv3 = v3_prob(parsed)
    except: pv3 = 0.5

    try:    pv4 = v4_prob(parsed)
    except: pv4 = 0.5

    fv3, tv3 = fuse(pv12, pv3)
    fv4, tv4 = fuse(pv12, pv4)

    pred_v3 = 1 if fv3 >= FUSION_THRESH else 0
    pred_v4 = 1 if fv4 >= FUSION_THRESH else 0

    ok3 = 'âœ…' if pred_v3 == true else 'âŒ'
    ok4 = 'âœ…' if pred_v4 == true else 'âŒ'

    if pred_v3 == true: v3_correct += 1
    if pred_v4 == true: v4_correct += 1
    scored += 1

    if ok3 != ok4:
        disagree.append((fname, true, pv12, pv3, pv4, ok3, ok4))

    tstr = 'PHISH' if true == 1 else 'LEGIT'
    print(f"{i+1:>3}  {fname:<30} {tstr:>5}  "
          f"{pv12:.3f} {pv3:.3f} {fv3:.3f}({tv3:<4}) {ok3}  "
          f"{pv4:.3f} {fv4:.3f}({tv4:<4}) {ok4}")

# â”€â”€ SUMMARY â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
print("\n" + "="*80)
print(f"  V3 + V12  :  {v3_correct}/{scored}  ({v3_correct/scored*100:.1f}%)  â† current")
print(f"  V4 + V12  :  {v4_correct}/{scored}  ({v4_correct/scored*100:.1f}%)" if scored else "  V4 + V12  :  NO SCORED EMAILS")
d = v4_correct - v3_correct
msg = 'âœ… V4 is better â€” switch' if d>0 else ('âž¡ï¸ Tied â€” safe to switch' if d==0 else 'âš ï¸ V4 worse â€” keep V3')
print(f"  Î” = {d:+d}  â†’  {msg}")

if disagree:
    print(f"\nDISAGREEMENTS ({len(disagree)}):")
    for fname, true, pv12, pv3, pv4, ok3, ok4 in disagree:
        tstr = 'PHISH' if true==1 else 'LEGIT'
        print(f"  {fname}  TRUE={tstr}  V12={pv12:.3f}  V3={pv3:.3f}({ok3})  V4={pv4:.3f}({ok4})")

print("="*80)



