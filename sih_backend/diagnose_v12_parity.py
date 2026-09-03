"""
diagnose_v12_parity.py — find the FIRST value that diverges from Kaggle

Run this on ONLY 001_legitimate.eml, in BOTH local and Kaggle environments.
Compare the printed values top to bottom — the first line that differs
between the two runs is the actual bug location. Everything above it is
confirmed correct and should not be touched again.

Usage:
    python diagnose_v12_parity.py "path/to/001_legitimate.eml"

To run the SAME script on Kaggle: upload this file alongside pipeline.py,
set the same env-var-style paths at the top (or hardcode /kaggle/working/...
paths), and run it there too. Diff the two outputs line by line.
"""

import sys
import os
os.environ["HF_DEACTIVATE_ASYNC_LOAD"] = "1"  # must be set BEFORE importing transformers

import json
import hashlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import numpy as np
import torch

import config
from core.eml_parser import parse_eml
from layers.text_structural.deberta_model import (
    build_v12_behavior_features,
    HybridClassifierHead,
)
from transformers import AutoTokenizer, AutoModelForSequenceClassification


def sha256_of_tensor(t: torch.Tensor) -> str:
    """Deterministic checksum of a tensor's raw values."""
    arr = t.detach().cpu().numpy().astype(np.float32).tobytes()
    return hashlib.sha256(arr).hexdigest()[:16]


def sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(8192 * 1024):
            h.update(chunk)
    return h.hexdigest()[:16]


def main(eml_path):
    print("=" * 90)
    print("V12 PARITY DIAGNOSTIC")
    print("=" * 90)

    # ── 0. File integrity checks ─────────────────────────────────────────
    print("\n--- 0. FILE CHECKSUMS ---")
    safetensors_path = os.path.join(config.DEBERTA_BACKBONE_DIR, "model.safetensors")
    print(f"model.safetensors sha256[:16] : {sha256_of_file(safetensors_path)}")
    print(f"model.safetensors size (bytes): {os.path.getsize(safetensors_path)}")
    print(f"v12_hybrid_head.pt sha256[:16]: {sha256_of_file(config.DEBERTA_HEAD_PATH)}")
    print(f"v12_hybrid_head.pt size (bytes): {os.path.getsize(config.DEBERTA_HEAD_PATH)}")
    print(f"behavior_feature_scaler.json sha256[:16]: {sha256_of_file(config.DEBERTA_SCALER_PATH)}")

    with open(eml_path, "rb") as f:
        eml_bytes = f.read()
    print(f"\nInput .eml sha256[:16]: {hashlib.sha256(eml_bytes).hexdigest()[:16]}")
    print(f"Input .eml size: {len(eml_bytes)} bytes")

    parsed = parse_eml(eml_bytes)

    # ── 1. Raw 14 behavior features ──────────────────────────────────────
    print("\n--- 1. RAW 14 BEHAVIOR FEATURES ---")
    with open(config.DEBERTA_SCALER_PATH) as f:
        scaler = json.load(f)
    feature_names = scaler["feature_columns"]
    raw_feats = build_v12_behavior_features(parsed)
    for name, val in zip(feature_names, raw_feats):
        print(f"  {name:<20} = {val}")

    # ── 2. Scaled 14 features ────────────────────────────────────────────
    print("\n--- 2. SCALED 14 FEATURES ---")
    mean = np.array(scaler["mean"], dtype=np.float32)
    scale = np.array(scaler["scale"], dtype=np.float32)
    scaled_feats = (raw_feats - mean) / scale
    for name, val in zip(feature_names, scaled_feats):
        print(f"  {name:<20} = {val:.6f}")

    # ── 3. Scaler feature_columns (order) ────────────────────────────────
    print("\n--- 3. SCALER feature_columns (from behavior_feature_scaler.json) ---")
    print(feature_names)

    # ── 4. Tokenizer input ───────────────────────────────────────────────
    print("\n--- 4. TOKENIZER INPUT ---")
    tokenizer = AutoTokenizer.from_pretrained(config.DEBERTA_BACKBONE_DIR)
    enc = tokenizer(
        parsed.body_text, max_length=config.MAX_SEQ_LEN, truncation=True,
        padding="max_length", return_tensors="pt", add_special_tokens=False,
    )
    input_ids = enc["input_ids"]
    attn_mask = enc["attention_mask"]
    print(f"  input_ids sum      : {int(input_ids.sum())}")
    print(f"  input_ids checksum : {sha256_of_tensor(input_ids)}")
    print(f"  attention_mask sum : {int(attn_mask.sum())}")
    print(f"  first 20 token ids : {input_ids[0][:20].tolist()}")
    print(f"  last non-pad token index (seq len used): {int(attn_mask.sum()) - 1}")

    # ── 5. Model load + pooled vector ────────────────────────────────────
    print("\n--- 5. BACKBONE + POOLED VECTOR ---")
    device = "cpu"
    backbone = AutoModelForSequenceClassification.from_pretrained(
        config.DEBERTA_BACKBONE_DIR, num_labels=2, ignore_mismatched_sizes=True,
        low_cpu_mem_usage=False,
    )
    backbone.to(device)
    backbone.eval()

    with torch.no_grad():
        encoder_out = backbone.deberta(**enc)
        pooled = backbone.pooler(encoder_out.last_hidden_state)

    print(f"  pooled shape : {tuple(pooled.shape)}")
    print(f"  pooled mean  : {float(pooled.mean()):.6f}")
    print(f"  pooled std   : {float(pooled.std()):.6f}")
    print(f"  pooled norm  : {float(pooled.norm()):.6f}")
    print(f"  pooled checksum : {sha256_of_tensor(pooled)}")
    print(f"  pooled first 8 values: {pooled[0][:8].tolist()}")

    # ── 6. Hybrid head parameter checksums ───────────────────────────────
    print("\n--- 6. HYBRID HEAD PARAMETER CHECKSUMS ---")
    head_state = torch.load(config.DEBERTA_HEAD_PATH, map_location=device)
    for section_name, sub in head_state.items():
        for k, v in sub.items():
            print(f"  {section_name}.{k:<20} shape={tuple(v.shape)}  checksum={sha256_of_tensor(v)}")

    hybrid_head = HybridClassifierHead()
    hybrid_head.behavior_mlp.load_state_dict(head_state["behavior_mlp"])
    hybrid_head.fusion_linear.load_state_dict(head_state["fusion_linear"])
    hybrid_head.hybrid_classifier.load_state_dict(head_state["hybrid_classifier"])
    hybrid_head.to(device)
    hybrid_head.eval()

    # ── 7. Final logits ───────────────────────────────────────────────────
    print("\n--- 7. FINAL LOGITS ---")
    behavior_tensor = torch.tensor(scaled_feats, dtype=torch.float32, device=device).unsqueeze(0)
    with torch.no_grad():
        logits = hybrid_head(pooled, behavior_tensor)
    print(f"  logits: {logits[0].tolist()}")

    # ── 8. Final probability ─────────────────────────────────────────────
    print("\n--- 8. FINAL PHISHING PROBABILITY ---")
    with torch.no_grad():
        probs = torch.softmax(logits, dim=-1)[0]
    print(f"  legit prob    : {float(probs[0]):.6f}")
    print(f"  phishing prob : {float(probs[1]):.6f}")

    print("\n" + "=" * 90)
    print("DIAGNOSTIC COMPLETE — run this same script on Kaggle and diff line by line")
    print("=" * 90)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python diagnose_v12_parity.py path/to/001_legitimate.eml")
        sys.exit(1)
    main(sys.argv[1])