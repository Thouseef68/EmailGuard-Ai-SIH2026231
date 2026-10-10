"""
core/report_schema.py — pydantic response models for /analyze

Keeps the API response shape documented and validated. The final verdict now
comes from the LLM analyst (validated against forensic facts); DeBERTa /
XGBoost / fusion output is kept as advisory evidence.
"""

from typing import Optional, List, Any
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
    status: str  # advisory only — no longer decides the final verdict
    verdict: str


class TextStructuralSection(BaseModel):
    deberta: ModelResult
    xgboost: ModelResult
    fusion: FusionResult
    agreement: bool


class ForensicFinding(BaseModel):
    id: str
    severity: str  # HIGH | MEDIUM | LOW | INFO
    text: str


class HighFindingResponse(BaseModel):
    id: str
    stance: str  # confirmed | rebutted
    why: str = ""


class LlmAnalystSection(BaseModel):
    model: str
    status: str  # ok | fallback
    verdict: str  # PHISHING | LEGITIMATE | HUMAN_REVIEW (after validation)
    llm_verdict_raw: Optional[str] = None  # what the LLM said before validation
    confidence: int = 0
    reasons: List[str] = []
    cited_findings: List[str] = []
    validation_notes: List[str] = []  # audit notes (advisory) or the reason a verdict was downgraded (enforce)
    high_findings: List[HighFindingResponse] = []  # the LLM's answer to each HIGH finding
    re_asked: bool = False  # the LLM ignored a HIGH finding and was asked once more
    validator_mode: str = "advisory"  # advisory = LLM verdict is final | enforce = validator may downgrade
    forensic_findings: List[ForensicFinding] = []
    error: Optional[str] = None
    latency_ms: int = 0


class AnalyzeResponse(BaseModel):
    source: str
    parsed: ParsedSummary
    text_structural: Optional[TextStructuralSection] = None
    llm_analyst: Optional[LlmAnalystSection] = None
    flags: List[str]
    final_verdict: str  # PHISHING | LEGITIMATE | HUMAN_REVIEW
    final_confidence: Optional[int] = None
    decision_reason: Optional[str] = None
    forensics: Optional[Any] = None
    vision: Optional[Any] = None
    attachments: Optional[Any] = None