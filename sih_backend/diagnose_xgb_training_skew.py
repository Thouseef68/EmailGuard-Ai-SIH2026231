import json
from pathlib import Path
import xgboost as xgb

BASE = Path(__file__).resolve().parent
MODELS = BASE / "models"

MODEL = MODELS / "xgboost_phishing_v2.json"
META = MODELS / "xgboost_feature_cols_v2.json"
OLD_META = MODELS / "xgboost_feature_cols.json"
IMPORTANCE = MODELS / "xgboost_feature_importance.csv"

print("=" * 90)
print("XGBOOST V2 MODEL INSPECTION")
print("=" * 90)

# ------------------------------------------------------------
# 1. Files
# ------------------------------------------------------------

print("\n--- FILES ---")

for p in [MODEL, META, OLD_META, IMPORTANCE]:
    if p.exists():
        print(f"FOUND : {p.name:<35} {p.stat().st_size:,} bytes")
    else:
        print(f"MISSING: {p.name}")

# ------------------------------------------------------------
# 2. V2 metadata
# ------------------------------------------------------------

print("\n--- V2 METADATA ---")

with open(META, encoding="utf-8") as f:
    meta = json.load(f)

print("version       :", meta.get("version"))
print("feature_count :", meta.get("feature_count"))
print("features      :")

for i, feature in enumerate(meta.get("features", []), 1):
    print(f"  {i:02d}. {feature}")

# ------------------------------------------------------------
# 3. Older metadata — validation/test metrics
# ------------------------------------------------------------

print("\n--- AVAILABLE TRAINING METRICS ---")

if OLD_META.exists():

    with open(OLD_META, encoding="utf-8") as f:
        old = json.load(f)

    for key in [
        "version",
        "validation_metrics",
        "test_metrics",
        "random_seed",
        "label_mapping",
        "phase1_features_reused",
        "new_structural_features",
    ]:
        if key in old:
            print(f"\n{key}:")
            print(json.dumps(old[key], indent=2))

else:
    print("Old metadata not found.")

# ------------------------------------------------------------
# 4. Feature importance CSV
# ------------------------------------------------------------

print("\n--- FEATURE IMPORTANCE CSV ---")

if IMPORTANCE.exists():

    print(IMPORTANCE.read_text(encoding="utf-8"))

else:
    print("Feature importance CSV not found.")

# ------------------------------------------------------------
# 5. Load actual XGBoost model
# ------------------------------------------------------------

print("\n--- MODEL STRUCTURE ---")

booster = xgb.Booster()
booster.load_model(str(MODEL))

print("XGBoost version:", xgb.__version__)
print("Number of trees:", len(booster.get_dump()))

# ------------------------------------------------------------
# 6. Built-in importance
# ------------------------------------------------------------

print("\n--- BUILT-IN MODEL IMPORTANCE ---")

for importance_type in [
    "gain",
    "weight",
    "cover",
]:

    print(f"\n### {importance_type.upper()} ###")

    scores = booster.get_score(
        importance_type=importance_type
    )

    ranked = sorted(
        scores.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for feature, score in ranked:
        print(f"{feature:<35} {score:.6f}")

# ------------------------------------------------------------
# 7. Suspicious features
# ------------------------------------------------------------

SUSPICIOUS = [
    "html_present",
    "received_count",
    "multipart",
    "body_exclamation_count",
    "reply_to_present",
    "body_url_count",
    "unique_domain_count",
    "https_url_count",
    "credential_word_count",
    "verify_word_count",
    "urgent_word_count",
    "login_word_count",
]

print("\n" + "=" * 90)
print("SUSPICIOUS FEATURE IMPORTANCE")
print("=" * 90)

scores = booster.get_score(
    importance_type="gain"
)

for feature in SUSPICIOUS:

    # XGBoost may use f0/f1/... instead of names
    value = scores.get(feature)

    print(
        f"{feature:<35} "
        f"gain={value if value is not None else 0}"
    )

# ------------------------------------------------------------
# 8. Model config
# ------------------------------------------------------------

print("\n" + "=" * 90)
print("MODEL CONFIG")
print("=" * 90)

try:
    print(booster.save_config())
except Exception as e:
    print("Could not read config:", e)

print("\n" + "=" * 90)
print("INSPECTION COMPLETE")
print("=" * 90)