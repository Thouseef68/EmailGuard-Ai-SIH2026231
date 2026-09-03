"""
layers/text_structural/deberta_model.py — DeBERTa V12 hybrid model

Loads the backbone + hybrid fusion head exactly as trained:
    backbone (DeBERTa-v3-large, LoRA-merged) -> [CLS] pooled (1024-dim)
    behavior_mlp: 14 raw email features -> 32-dim
    fusion_linear: concat(1024+32=1056) -> 256
    hybrid_classifier: 256 -> 2 (legit/phishing logits)

LOCKED — this architecture must not change without re-validating Phase 4.
"""

import os
os.environ["HF_DEACTIVATE_ASYNC_LOAD"] = "1"

import re
import json
import numpy as np
import torch
import torch.nn as nn
from transformers import AutoTokenizer, AutoModelForSequenceClassification

import config
from core.eml_parser import ParsedEmail

V12_BEHAVIOR_FEATURES = [
    "url_count", "unique_domains", "urgent_count", "html_tag_count",
    "exclamation_count", "question_count", "word_count", "char_count",
    "avg_word_len", "subj_upper_ratio", "subj_has_re", "subj_has_fwd",
    "subj_length", "ip_count",
]


class HybridClassifierHead(nn.Module):
    def __init__(self):
        super().__init__()
        self.behavior_mlp = nn.Sequential(
            nn.Linear(14, 32), nn.GELU(),
            nn.Linear(32, 32), nn.GELU(),
        )
        self.fusion_linear    = nn.Linear(1056, 256)
        self.act              = nn.GELU()
        self.dropout          = nn.Dropout(0.2)
        self.hybrid_classifier = nn.Linear(256, 2)

    def forward(self, pooled_output, behavior_features):
        behavior_out = self.behavior_mlp(behavior_features)
        fused = torch.cat([pooled_output, behavior_out], dim=-1)
        fused = self.act(self.fusion_linear(fused))
        fused = self.dropout(fused)
        return self.hybrid_classifier(fused)


def build_v12_behavior_features(parsed: ParsedEmail) -> np.ndarray:
    """Raw (unscaled) 14 behavioral features — order matches behavior_feature_scaler.json."""
    text      = parsed.body_text
    subj      = parsed.subject
    txt_lower = text.lower()

    url_count      = txt_lower.count("http") + txt_lower.count("www.")
    domain_matches = re.findall(r"https?://([^/\s]+)|www\.([^/\s]+)", txt_lower)
    unique_domains = len({d1 or d2 for d1, d2 in domain_matches})
    urgent_count   = sum(w in txt_lower for w in
                         ["urgent","immediately","action required","expire","suspend","verify now"])
    html_tag_count    = len(re.findall(r"<[a-zA-Z]+", text))
    exclamation_count = text.count("!")
    question_count    = text.count("?")
    word_count        = len(text.split())
    char_count        = len(text)
    avg_word_len      = len(text.replace(" ","")) / max(word_count, 1)
    subj_upper_ratio  = sum(1 for c in subj if c.isupper()) / max(len(subj), 1)
    subj_has_re       = int(subj.lower().startswith("re:"))
    subj_has_fwd      = int(subj.lower().startswith("fwd:"))
    subj_length       = len(subj)
    ip_count          = len(re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text))

    return np.array([
        url_count, unique_domains, urgent_count, html_tag_count,
        exclamation_count, question_count, word_count, char_count,
        avg_word_len, subj_upper_ratio, subj_has_re, subj_has_fwd,
        subj_length, ip_count,
    ], dtype=np.float32)


class DebertaEngine:
    def __init__(self):
        self.device        = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer     = None
        self.backbone      = None
        self.hybrid_head   = None
        self.scaler_mean   = None
        self.scaler_scale  = None
        self._loaded       = False

    def load(self):
        if self._loaded:
            return

        print(f"[deberta] device = {self.device}")
        print(f"[deberta] loading backbone from {config.DEBERTA_BACKBONE_DIR} ...")
        self.tokenizer = AutoTokenizer.from_pretrained(config.DEBERTA_BACKBONE_DIR)
        self.backbone  = AutoModelForSequenceClassification.from_pretrained(
            config.DEBERTA_BACKBONE_DIR,
            num_labels=2,
            ignore_mismatched_sizes=True,
            low_cpu_mem_usage=False,
        )
        self.backbone.to(self.device).eval()

        print(f"[deberta] loading hybrid head from {config.DEBERTA_HEAD_PATH} ...")
        head_state = torch.load(config.DEBERTA_HEAD_PATH, map_location=self.device)
        self.hybrid_head = HybridClassifierHead()
        self.hybrid_head.behavior_mlp.load_state_dict(head_state["behavior_mlp"])
        self.hybrid_head.fusion_linear.load_state_dict(head_state["fusion_linear"])
        self.hybrid_head.hybrid_classifier.load_state_dict(head_state["hybrid_classifier"])
        self.hybrid_head.to(self.device).eval()

        with open(config.DEBERTA_SCALER_PATH) as f:
            scaler = json.load(f)
        self.scaler_mean  = np.array(scaler["mean"],  dtype=np.float32)
        self.scaler_scale = np.array(scaler["scale"], dtype=np.float32)

        self._loaded = True
        print("[deberta] ready.")

    def predict(self, parsed: ParsedEmail) -> float:
        """Returns phishing probability (0–1)."""
        if not self._loaded:
            self.load()

        # ── KEY FIX: include Subject prefix — matches Kaggle validated tokenization
        full_text = f"Subject: {parsed.subject}\n\n{parsed.body_text}"
        if not full_text.strip():
            return 0.0

        enc = self.tokenizer(
            full_text, max_length=config.MAX_SEQ_LEN, truncation=True,
            padding="max_length", return_tensors="pt",
            add_special_tokens=False,
        ).to(self.device)

        behavior_raw = build_v12_behavior_features(parsed)
        scaled       = (behavior_raw - self.scaler_mean) / self.scaler_scale
        behavior_t   = torch.tensor(scaled, dtype=torch.float32, device=self.device).unsqueeze(0)

        with torch.no_grad():
            encoder_out = self.backbone.deberta(**enc)
            pooled      = self.backbone.pooler(encoder_out.last_hidden_state)
            logits      = self.hybrid_head(pooled, behavior_t)
            probs       = torch.softmax(logits, dim=-1)[0]

        return float(probs[1])