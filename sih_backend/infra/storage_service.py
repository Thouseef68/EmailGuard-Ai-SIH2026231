# infra/storage_service.py
"""
Ties together: Supabase save → IPFS upload → Sepolia anchor.
Blockchain runs in a background thread — API response is never delayed.
Report is saved to Supabase immediately; IPFS/blockchain fields are updated when done.
"""
import uuid
import logging
import threading
from typing import Optional

from infra.supabase_client import (
    save_analysis,
    update_blockchain_fields,
    add_to_hitl_queue,
    log_audit,
)
from infra.ipfs_client       import upload_to_ipfs
from infra.blockchain_anchor import compute_report_hash, anchor_on_chain

logger = logging.getLogger(__name__)


def _anchor_worker(
    analysis_id: str,
    report:      dict,
    report_hash: str,
    verdict:     str,
):
    print(f"\n{'='*60}")
    print(f"[BLOCKCHAIN] Thread started → {analysis_id}")
    print(f"[BLOCKCHAIN] Verdict       → {verdict}")
    print(f"[BLOCKCHAIN] Hash          → {report_hash[:20]}...")

    # ── Step 1: IPFS ─────────────────────────────────────────────────────────
    ipfs_cid = None
    try:
        from config import PINATA_JWT
        jwt_ok = bool(PINATA_JWT and len(PINATA_JWT) > 20)
        print(f"[BLOCKCHAIN] Pinata JWT present: {jwt_ok}")
        if not jwt_ok:
            raise ValueError("PINATA_JWT is empty or too short in config.py")

        print(f"[BLOCKCHAIN] Uploading to IPFS...")
        ipfs_cid = upload_to_ipfs(report, analysis_id)
        print(f"[BLOCKCHAIN] ✅ IPFS OK → {ipfs_cid}")

    except Exception as exc:
        print(f"[BLOCKCHAIN] ❌ IPFS FAILED → {exc}")
        logger.error(f"[{analysis_id}] IPFS failed: {exc}")
        update_blockchain_fields(
            analysis_id=analysis_id,
            ipfs_cid=None,
            tx_hash=None,
            anchored=False,
            error=f"IPFS error: {exc}",
        )
        print(f"{'='*60}\n")
        return   # stop here — no point anchoring without IPFS CID

    # ── Step 2: Blockchain ────────────────────────────────────────────────────
    try:
        from config import POLYGON_RPC, CONTRACT_ADDRESS, CHAIN_ID, DEPLOYER_PRIVATE_KEY
        key_ok      = bool(DEPLOYER_PRIVATE_KEY and len(DEPLOYER_PRIVATE_KEY) > 10)
        contract_ok = bool(CONTRACT_ADDRESS and CONTRACT_ADDRESS.startswith("0x"))
        print(f"[BLOCKCHAIN] RPC URL         → {POLYGON_RPC}")
        print(f"[BLOCKCHAIN] Contract set    → {contract_ok} ({CONTRACT_ADDRESS[:10]}...)")
        print(f"[BLOCKCHAIN] Private key set → {key_ok}")
        print(f"[BLOCKCHAIN] Chain ID        → {CHAIN_ID}")

        if not key_ok:
            raise ValueError("DEPLOYER_PRIVATE_KEY is empty in config.py")
        if not contract_ok:
            raise ValueError("CONTRACT_ADDRESS is empty or invalid in config.py")

        print(f"[BLOCKCHAIN] Anchoring on Sepolia...")
        anchor  = anchor_on_chain(analysis_id, report_hash, ipfs_cid, verdict)
        tx_hash = anchor["tx_hash"]
        print(f"[BLOCKCHAIN] ✅ Anchored → {anchor['polygonscan_url']}")
        logger.info(f"[{analysis_id}] Blockchain anchor OK → {anchor['polygonscan_url']}")

        # ── Step 3: Update Supabase ───────────────────────────────────────────
        print(f"[BLOCKCHAIN] Updating Supabase...")
        update_blockchain_fields(
            analysis_id=analysis_id,
            ipfs_cid=ipfs_cid,
            tx_hash=tx_hash,
            anchored=True,
        )
        print(f"[BLOCKCHAIN] ✅ Supabase updated")

    except Exception as exc:
        print(f"[BLOCKCHAIN] ❌ CHAIN FAILED → {exc}")
        logger.error(f"[{analysis_id}] Blockchain anchor failed: {exc}")
        update_blockchain_fields(
            analysis_id=analysis_id,
            ipfs_cid=ipfs_cid,
            tx_hash=None,
            anchored=False,
            error=f"Chain error: {exc}",
        )

    print(f"[BLOCKCHAIN] Thread complete")
    print(f"{'='*60}\n")


def persist_analysis(
    report:          dict,
    source_filename: str,
    user_id:         Optional[str] = None,
    client_ip:       Optional[str] = None,
) -> dict:
    """
    Called from FastAPI /analyze endpoint after analyze_email() returns.

    Flow:
      1. Compute SHA-256 hash of full report
      2. Save to Supabase immediately (user gets response now)
      3. Fire background thread → IPFS upload → Sepolia anchor → Supabase update
      4. Return report enriched with analysis_id + hash + anchoring status
    """
    analysis_id   = str(uuid.uuid4())
    final_verdict = report.get("final_verdict", "UNKNOWN")

    # Extract model scores
    ts            = report.get("text_structural", {})
    deberta_score = ts.get("deberta", {}).get("probability")
    xgboost_score = ts.get("xgboost", {}).get("probability")
    fused_score   = ts.get("fusion",  {}).get("fused_probability")

    # Hash computed BEFORE blockchain fields added — keeps it stable
    report_hash_hex, _ = compute_report_hash(report)

    # ── Save to Supabase immediately ──────────────────────────────────────────
    try:
        save_analysis(
            analysis_id=analysis_id,
            source_filename=source_filename,
            report=report,
            report_hash=report_hash_hex,
            final_verdict=final_verdict,
            deberta_score=deberta_score,
            xgboost_score=xgboost_score,
            fused_score=fused_score,
            blockchain_anchored=False,
        )
        print(f"[STORAGE] ✅ Saved to Supabase → {analysis_id}")
    except Exception as exc:
        print(f"[STORAGE] ❌ Supabase save failed → {exc}")
        logger.error(f"Supabase save failed: {exc}")

    # ── HITL queue ────────────────────────────────────────────────────────────
    if final_verdict == "HITL_QUEUE":
        try:
            add_to_hitl_queue(
                analysis_id=analysis_id,
                fused_probability=fused_score   or 0.0,
                deberta_score=deberta_score      or 0.0,
                xgboost_score=xgboost_score      or 0.0,
                flagged_reason=ts.get("fusion", {}).get("reason", "Uncertainty band"),
            )
            print(f"[STORAGE] ✅ Added to HITL queue → {analysis_id}")
        except Exception as exc:
            logger.warning(f"HITL queue insert failed: {exc}")

    # ── Audit log ─────────────────────────────────────────────────────────────
    log_audit(
        action="ANALYZE",
        analysis_id=analysis_id,
        user_id=user_id,
        ip_address=client_ip,
        metadata={"verdict": final_verdict, "filename": source_filename},
    )

    # ── Start background anchor thread ────────────────────────────────────────
    thread = threading.Thread(
        target=_anchor_worker,
        args=(analysis_id, report, report_hash_hex, final_verdict),
        daemon=True,
    )
    thread.start()
    print(f"[STORAGE] Background anchor thread started → {analysis_id}")

    # ── Enrich report with blockchain metadata ────────────────────────────────
    report["blockchain"] = {
        "analysis_id":     analysis_id,
        "report_hash":     report_hash_hex,
        "ipfs_cid":        None,          # populated by background thread
        "tx_hash":         None,          # populated by background thread
        "polygonscan_url": None,          # populated by background thread
        "status":          "anchoring",   # frontend shows spinner until /analysis/{id} confirms
        "verify_url":      f"/verify/{analysis_id}",
        "law_reference": [
            "Bharatiya Sakshya Adhiniyam (BSA) 2023 — Section 63 (Electronic Records)",
            "DPDP Act 2023 — Article 4 (Data Minimisation via PII Masking)",
            "Indian Evidence Act 1872 (as amended) — Section 65B",
        ]
    }

    return report