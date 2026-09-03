"""
core/report_schema.py — pydantic response models for /analyze

Keeps the API response shape documented and validated. As new layers
(vision, forensics, attachments, etc.) get built, add their section here
so the frontend has a stable contract to code against.
"""

from typing import Optional, List
from pydantic import BaseModel


class ParsedSummary(BaseModel):
    subject: str
    from_addr: str
    from_domain: str
    reply_to: str
    spf: str
    dkim: str
    dmarc: str
    received_hops: int
    attachment_count: int


class ModelResult(BaseModel):
    probability: float
    verdict: str


class FusionResult(BaseModel):
    fused_probability: float
    status: str  # AUTO_DECIDED | HIGH_DISAGREEMENT_REVIEW | HITL_QUEUE
    verdict: str


class TextStructuralSection(BaseModel):
    deberta: ModelResult
    xgboost: ModelResult
    fusion: FusionResult
    agreement: bool


class AnalyzeResponse(BaseModel):
    source: str
    parsed: ParsedSummary
    text_structural: TextStructuralSection
    flags: List[str]
    final_verdict: str
    # Future layers slot in here as they're built:
    # forensics: Optional[dict] = None
    # vision: Optional[dict] = None
    # attachments: Optional[dict] = None