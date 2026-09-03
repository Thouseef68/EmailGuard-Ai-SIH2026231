"""
batch_test.py — Validate the local backend against your 100 labeled real .eml files

Usage:
    python batch_test.py path/to/sih_phase4_real_100_eml

Run this from the sih_backend/ folder (same place as main.py) so imports work.
Does NOT go through the API/curl — calls the same logic directly for speed.
"""

import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.orchestrator import analyze_email, load_all_models


def main(folder_path):
    print("Loading models (one-time)...")
    load_all_models()
    print("Models loaded.\n")

    files = sorted(f for f in os.listdir(folder_path) if f.endswith(".eml"))
    if not files:
        print(f"No .eml files found in {folder_path}")
        return

    print(f"Found {len(files)} files.\n")

    results = []
    correct = 0
    deberta_correct = 0
    xgb_correct = 0

    for fname in files:
        # Label comes from filename: "001_legitimate.eml" or "002_phishing.eml"
        if "phishing" in fname.lower():
            true_label = 1
        elif "legitimate" in fname.lower():
            true_label = 0
        else:
            print(f"SKIP (no label in filename): {fname}")
            continue

        path = os.path.join(folder_path, fname)
        with open(path, "rb") as f:
            eml_bytes = f.read()

        try:
            report = analyze_email(eml_bytes, source_name=fname)
        except Exception as e:
            print(f"ERROR on {fname}: {e}")
            continue

        ts = report["text_structural"]
        deberta_pred = 1 if ts["deberta"]["verdict"] == "PHISHING" else 0
        xgb_pred = 1 if ts["xgboost"]["verdict"] == "PHISHING" else 0
        fusion_verdict = ts["fusion"]["verdict"]

        # For scoring, treat HITL/review as "not auto-correct" but track separately
        if fusion_verdict == "PHISHING":
            fusion_pred = 1
        elif fusion_verdict == "LEGITIMATE":
            fusion_pred = 0
        else:
            fusion_pred = None  # HITL_QUEUE or NEEDS_HUMAN_REVIEW

        deberta_ok = (deberta_pred == true_label)
        xgb_ok = (xgb_pred == true_label)
        fusion_ok = (fusion_pred == true_label) if fusion_pred is not None else None

        if deberta_ok:
            deberta_correct += 1
        if xgb_ok:
            xgb_correct += 1
        if fusion_ok:
            correct += 1

        results.append({
            "file": fname,
            "true_label": "PHISHING" if true_label == 1 else "LEGITIMATE",
            "deberta_prob": ts["deberta"]["probability"],
            "xgb_prob": ts["xgboost"]["probability"],
            "fused_prob": ts["fusion"]["fused_probability"],
            "fusion_status": ts["fusion"]["status"],
            "fusion_verdict": fusion_verdict,
            "deberta_ok": deberta_ok,
            "xgb_ok": xgb_ok,
            "fusion_ok": fusion_ok,
        })

        status_char = "OK" if fusion_ok else ("REVIEW" if fusion_ok is None else "WRONG")
        print(f"{fname:<40} true={results[-1]['true_label']:<12} "
              f"deberta={ts['deberta']['probability']:.3f} "
              f"xgb={ts['xgboost']['probability']:.3f} "
              f"fused={ts['fusion']['fused_probability']:.3f} "
              f"[{fusion_verdict}] {status_char}")

    total = len(results)
    hitl_count = sum(1 for r in results if r["fusion_ok"] is None)
    auto_decided = total - hitl_count
    auto_correct = correct

    print("\n" + "=" * 90)
    print("SUMMARY")
    print("=" * 90)
    print(f"Total files tested        : {total}")
    print(f"DeBERTa standalone acc    : {deberta_correct}/{total} = {deberta_correct/total*100:.1f}%")
    print(f"XGBoost standalone acc    : {xgb_correct}/{total} = {xgb_correct/total*100:.1f}%")
    print(f"Fusion auto-decided count : {auto_decided}/{total}")
    print(f"Fusion HITL/review count  : {hitl_count}/{total}")
    if auto_decided > 0:
        print(f"Fusion accuracy (on auto-decided only): {auto_correct}/{auto_decided} = {auto_correct/auto_decided*100:.1f}%")
    print(f"Fusion accuracy (treating HITL as 'not wrong', i.e. best case): {auto_correct}/{total} = {auto_correct/total*100:.1f}%")

    out_path = os.path.join(os.path.dirname(folder_path), "batch_test_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nFull results saved to: {out_path}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python batch_test.py path/to/sih_phase4_real_100_eml")
        sys.exit(1)
    main(sys.argv[1])
