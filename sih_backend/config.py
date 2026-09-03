"""
config.py — SIH 2026 Backend Configuration

Single source of truth for model paths and locked fusion parameters.
Every layer imports from here instead of hardcoding paths — if you move
the models/ folder, change it once, here.
"""

import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Local Windows:
#   uses ./models
#
# Modal:
#   uses /app/models
MODELS_DIR = os.environ.get(
    "EMAILGUARD_MODEL_DIR",
    os.path.join(BASE_DIR, "models")
)

# ─── Text/Structural layer (LOCKED — Phase 2/3/4 complete, do not retrain) ──
DEBERTA_MODEL_DIR = os.path.join(MODELS_DIR, "deberta_phishing_v12_adult_bait")
DEBERTA_BACKBONE_DIR = os.path.join(DEBERTA_MODEL_DIR, "backbone")
DEBERTA_HEAD_PATH = os.path.join(DEBERTA_MODEL_DIR, "v12_hybrid_head.pt")
DEBERTA_SCALER_PATH = os.path.join(DEBERTA_MODEL_DIR, "behavior_feature_scaler.json")

XGB_MODEL_PATH = os.path.join(
    MODELS_DIR,
    "xgboost_phishing_v3.json"
)

XGB_FEATURES_PATH = os.path.join(
    MODELS_DIR,
    "xgboost_feature_cols_v3.json"
)

FUSION_CONFIG_PATH = os.path.join(MODELS_DIR, "fusion_config.json")

# ─── Locked fusion parameters (Phase 4 — DO NOT change without re-validating) ─
W_DEBERTA = 0.50
W_XGB = 0.50
VETO_HIGH = 0.90
VETO_LOW = 0.30
HITL_LOW = 0.40
HITL_HIGH = 0.65

# ─── Inference settings ─────────────────────────────────────────────────────
MAX_SEQ_LEN = 256
DEVICE = "cuda"  # falls back to cpu automatically in model loaders if unavailable

# ─── API keys for future forensics/reputation layers (Tier 3) ──────────────
# Leave blank until those layers are built — reading os.environ so keys never
# get committed to source control.
# ─── API / external service credentials ───────────────────────────────────

VIRUSTOTAL_API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get("SIH_GSB_API_KEY", "")

# Supabase
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "")

# Pinata IPFS
PINATA_JWT = os.environ.get("PINATA_JWT", "")

# Polygon / blockchain
POLYGON_RPC = os.environ.get("POLYGON_RPC", "")
DEPLOYER_PRIVATE_KEY = os.environ.get("DEPLOYER_PRIVATE_KEY", "")
CONTRACT_ADDRESS = os.environ.get("CONTRACT_ADDRESS", "")
CHAIN_ID = int(os.environ.get("CHAIN_ID", "11155111"))
# Brand name → list of legitimate sending domains
# Used by: address_mismatch.py, logo_match.py, trusted sender override
BRAND_DOMAIN_MAP = {
    # ── Indian Banks ──────────────────────────────────────────────────────
    "au small finance bank":  ["aubank.in", "mail.aubank.in"],
    "au bank":                ["aubank.in"],
    "sbi":                    ["sbi.co.in", "onlinesbi.sbi", "sbicards.com"],
    "state bank":             ["sbi.co.in", "onlinesbi.sbi"],
    "hdfc":                   ["hdfcbank.com", "hdfcbank.net"],
    "hdfc bank":              ["hdfcbank.com"],
    "icici":                  ["icicibank.com"],
    "icici bank":             ["icicibank.com"],
    "axis bank":              ["axisbank.com"],
    "kotak":                  ["kotak.com", "kotakbank.com"],
    "kotak bank":             ["kotak.com", "kotakbank.com"],
    "yes bank":               ["yesbank.in"],
    "indusind":               ["indusind.com"],
    "federal bank":           ["federalbank.co.in"],
    "union bank":             ["unionbankofindia.co.in", "unionbankcrm.bank.in"],
    "pnb":                    ["pnb.co.in"],
    "punjab national bank":   ["pnb.co.in"],
    "bank of baroda":         ["bankofbaroda.in"],
    "canara bank":            ["canarabank.in"],
    "idbi":                   ["idbibank.com"],
    "rbl bank":               ["rbl.co.in"],
    "bandhan bank":           ["bandhanbank.com"],
    "idfc first bank":        ["idfcfirstbank.com"],
    "south indian bank":      ["southindianbank.com"],
    "indian bank":            ["indianbank.in"],
    "central bank":           ["centralbankofindia.co.in"],

    # ── Indian Fintech / Payments ─────────────────────────────────────────
    "paytm":                  ["paytm.com", "paytmbank.com"],
    "phonepe":                ["phonepe.com"],
    "gpay":                   ["google.com"],
    "npci":                   ["npci.org.in"],
    "razorpay":               ["razorpay.com"],
    "cashfree":               ["cashfree.com"],
    "billdesk":               ["billdesk.com"],
    "cred":                   ["cred.club"],
    "groww":                  ["groww.in"],
    "zerodha":                ["zerodha.com"],
    "upstox":                 ["upstox.com"],

    # ── Indian Telecoms ───────────────────────────────────────────────────
    "jio":                    ["jio.com", "jiomoney.com", "jiomail.com"],
    "airtel":                 ["airtel.in", "airtelbank.com"],
    "bsnl":                   ["bsnl.co.in"],
    "vi":                     ["vi.in"],
    "vodafone":               ["vodafone.in"],

    # ── Indian E-commerce / Services ─────────────────────────────────────
    "amazon":                 ["amazon.in", "amazon.com"],
    "flipkart":               ["flipkart.com"],
    "myntra":                 ["myntra.com"],
    "meesho":                 ["meesho.com"],
    "zomato":                 ["zomato.com"],
    "swiggy":                 ["swiggy.com"],
    "ola":                    ["olacabs.com"],
    "uber":                   ["uber.com"],
    "makemytrip":             ["makemytrip.com"],
    "goibibo":                ["goibibo.com"],
    "irctc":                  ["irctc.co.in", "irctc.in"],

    # ── Indian Government ─────────────────────────────────────────────────
    "income tax":             ["incometax.gov.in", "efiling.incometax.gov.in"],
    "uidai":                  ["uidai.gov.in"],
    "epfo":                   ["epfindia.gov.in"],
    "nsdl":                   ["nsdl.co.in", "nsdl.com"],
    "rbi":                    ["rbi.org.in"],
    "sebi":                   ["sebi.gov.in"],
    "nps":                    ["npscra.nsdl.co.in"],
    "passport":               ["passportindia.gov.in"],
    "digilocker":             ["digilocker.gov.in"],

    # ── Global Tech ───────────────────────────────────────────────────────
    "google":                 ["google.com", "gmail.com", "googlemail.com"],
    "microsoft":              ["microsoft.com", "outlook.com", "hotmail.com", "live.com"],
    "apple":                  ["apple.com", "icloud.com"],
    "linkedin":               ["linkedin.com"],
    "github":                 ["github.com"],
    "freelancer":             ["freelancer.com", "notifications.freelancer.com"],
    "zoom":                   ["zoom.us"],
    "slack":                  ["slack.com"],
    "notion":                 ["notion.so"],
    "dropbox":                ["dropbox.com"],

    # ── Indian Educational ────────────────────────────────────────────────
    "dayananda sagar":        ["dayananda.edu", "dsu.edu.in"],
    "vtu":                    ["vtu.ac.in"],
    #social media / other global brands
    "paypal": ["paypal.com"],
    "netflix": ["netflix.com"],
    "meta": ["meta.com", "facebook.com"],
    "instagram": ["instagram.com"],
    "whatsapp": ["whatsapp.com"],
    "adobe": ["adobe.com"],
    "salesforce": ["salesforce.com"],
    "atlassian": ["atlassian.com"],
    "canva": ["canva.com"],
    "coursera": ["coursera.org"],
    "udemy": ["udemy.com"],
    "openai": ["openai.com"],
    "anthropic": ["anthropic.com"],
    "cloudflare": ["cloudflare.com"],
    

    # ── Global Payments / Finance ─────────────────────────────
    "stripe":                 ["stripe.com"],
    "wise":                   ["wise.com"],
    "revolut":                ["revolut.com"],
    "american express":       ["americanexpress.com"],
    "mastercard":             ["mastercard.com"],
    "visa":                   ["visa.com"],

    # ── Cloud / Developer ────────────────────────────────────
    "aws":                    ["amazon.com", "aws.amazon.com"],
    "azure":                  ["azure.com", "microsoft.com"],
    "docker":                 ["docker.com"],
    "gitlab":                 ["gitlab.com"],
    "vercel":                 ["vercel.com"],
    "npm":                    ["npmjs.com"],

    # ── Communication / Productivity ──────────────────────────
    "telegram":               ["telegram.org"],
    "discord":                ["discord.com"],
    "teams":                  ["microsoft.com", "teams.microsoft.com"],
    "trello":                 ["trello.com"],
    "asana":                  ["asana.com"],
    "hubspot":                 ["hubspot.com"],

    # ── Major Indian Services ─────────────────────────────────
    "lic":                    ["licindia.in"],
    "indian railways":        ["indianrailways.gov.in"],
    "digiyatra":              ["digiyatra.com"],
    "mca":                    ["mca.gov.in"],
    "gst":                    ["gst.gov.in"],

    "fedex":                  ["fedex.com"],
    "ups":                    ["ups.com"],
    "dhl":                    ["dhl.com"],
    "usps":                   ["usps.com"],
    "india post":             ["indiapost.gov.in"],
    }

# ── Trusted brand domains ──────────────────────────────────────────────
# These represent actual organizations/brands.
TRUSTED_BRAND_DOMAINS = {
    domain.lower().strip()
    for domains in BRAND_DOMAIN_MAP.values()
    for domain in domains
}

# ── Email infrastructure ──────────────────────────────────────────────
# These services send email on behalf of other organizations.
# They MUST NOT be treated as proof that the sender is the brand itself.
KNOWN_MAIL_INFRASTRUCTURE = {
    "amazonses.com",
    "sendgrid.net",
    "mailchimp.com",
    "mandrillapp.com",
    "postmarkapp.com",
}

# ── Indian domain namespaces ───────────────────────────────────────────
# Handled separately; do NOT treat the suffix itself as a trusted sender.
GOVERNMENT_DOMAIN_SUFFIXES = {
    "gov.in",
    "nic.in",
    "mil.in",
}

EDUCATION_DOMAIN_SUFFIXES = {
    "ac.in",
}

# Backward compatibility for existing layers.
TRUSTED_DOMAINS = TRUSTED_BRAND_DOMAINS