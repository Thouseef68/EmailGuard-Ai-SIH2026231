# infra/supabase_client.py
"""
Supabase (PostgreSQL) client.
Handles storing analysis results, audit logs, and HITL queue entries.
"""
import logging
from supabase import create_client, Client
from config import SUPABASE_URL, SUPABASE_SERVICE_KEY

logger = logging.getLogger(__name__)

_client: Client = None


def get_client() -> Client:
    global _client
    if _client is None:
        _client = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
    return _client


# ── Analyses ─────────────────────────────────────────────────────────────────

def save_analysis(
    analysis_id:    str,
    source_filename: str,
    report:         dict,
    report_hash:    str,
    final_verdict:  str,
    deberta_score:  float = None,
    xgboost_score:  float = None,
    fused_score:    float = None,
    ipfs_cid:       str   = None,
    tx_hash:        str   = None,
    blockchain_anchored: bool = False,
    anchor_error:   str   = None,
) -> dict:
    """Insert one analysis row. Returns the inserted row."""
    client = get_client()
    row = {
        "id":                   analysis_id,
        "source_filename":      source_filename,
        "final_verdict":        final_verdict,
        "deberta_score":        deberta_score,
        "xgboost_score":        xgboost_score,
        "fused_score":          fused_score,
        "report_json":          report,
        "report_hash":          report_hash,
        "ipfs_cid":             ipfs_cid,
        "tx_hash":              tx_hash,
        "blockchain_anchored":  blockchain_anchored,
        "anchor_error":         anchor_error,
    }
    result = client.table("analyses").insert(row).execute()
    return result.data[0] if result.data else {}


def update_blockchain_fields(
    analysis_id: str,
    ipfs_cid:    str,
    tx_hash:     str,
    anchored:    bool,
    error:       str = None,
):
    """Update IPFS + blockchain fields after async anchoring completes."""
    client = get_client()
    client.table("analyses").update({
        "ipfs_cid":             ipfs_cid,
        "tx_hash":              tx_hash,
        "blockchain_anchored":  anchored,
        "anchor_error":         error,
    }).eq("id", analysis_id).execute()


def get_analysis(analysis_id: str) -> dict:
    client = get_client()
    result = client.table("analyses").select("*").eq("id", analysis_id).execute()
    return result.data[0] if result.data else {}


# ── Audit Log ────────────────────────────────────────────────────────────────

def log_audit(
    action:      str,
    analysis_id: str = None,
    user_id:     str = None,
    ip_address:  str = None,
    metadata:    dict = None,
):
    """Fire-and-forget audit log. Never raises — audit failure must not break analysis."""
    try:
        client = get_client()
        client.table("audit_log").insert({
            "action":      action,
            "analysis_id": analysis_id,
            "user_id":     user_id,
            "ip_address":  ip_address,
            "metadata":    metadata or {},
        }).execute()
    except Exception as exc:
        logger.warning(f"Audit log failed (non-critical): {exc}")


# ── HITL Queue ───────────────────────────────────────────────────────────────

def add_to_hitl_queue(
    analysis_id:       str,
    fused_probability: float,
    deberta_score:     float,
    xgboost_score:     float,
    flagged_reason:    str,
):
    client = get_client()
    client.table("hitl_queue").insert({
        "analysis_id":       analysis_id,
        "fused_probability": fused_probability,
        "deberta_score":     deberta_score,
        "xgboost_score":     xgboost_score,
        "flagged_reason":    flagged_reason,
        "status":            "pending",
    }).execute()