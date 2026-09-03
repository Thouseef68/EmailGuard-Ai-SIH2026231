"""
main.py — SIH 2026 Backend Entry Point

Run:
    pip install -r requirements.txt
    uvicorn main:app --host 0.0.0.0 --port 8000

Endpoints:
    GET  /health                    — liveness + layer status
    POST /analyze                   — upload .eml → full report + blockchain anchor
    GET  /analysis/{analysis_id}    — retrieve saved analysis by ID
    GET  /verify/{analysis_id}      — verify report hash on blockchain
"""

import os
os.environ.setdefault("HF_DEACTIVATE_ASYNC_LOAD", "1")   # Windows fix

from fastapi import FastAPI, UploadFile, File, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from core.orchestrator       import analyze_email, load_all_models
from infra.storage_service   import persist_analysis
from infra.supabase_client   import get_analysis
from infra.blockchain_anchor import verify_on_chain

app = FastAPI(
    title       = "SIH 2026 — AI-Powered Email Threat Detection",
    description = (
        "Upload a raw .eml file to get a fused DeBERTa V12 + XGBoost V3 "
        "phishing verdict with blockchain-anchored forensic report."
    ),
    version = "2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins  = ["*"],
    allow_methods  = ["*"],
    allow_headers  = ["*"],
)

_models_loaded = False


@app.on_event("startup")
def _startup():
    global _models_loaded
    load_all_models()
    _models_loaded = True


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {
        "status": "ok" if _models_loaded else "loading",
        "layers_active": [
            "text_structural (DeBERTa V12 + XGBoost V3 + Fusion Gate)",
            "forensics (auth, mismatch, typosquat, url_unshorten, whois, vt)",
            "geoip (origin IP → country/city/ISP)",
            "explainability (SHAP heatmap)",
            "nlp_extra (zero-shot intent, PII masking)",
            "vision (OCR + QR + logo match)",
            "attachments (pdf_scan + office_macro_scan)",
            "smtp_traversal (multi-hop + FCrDNS)",
        ],
        "storage": {
            "database":   "Supabase (PostgreSQL)",
            "ipfs":       "Pinata",
            "blockchain": "Polygon Amoy Testnet / Hardhat local",
        }
    }


# ── Analyze ───────────────────────────────────────────────────────────────────

@app.post("/analyze")
async def analyze(request: Request, file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".eml", ".msg", ".txt")):
        raise HTTPException(
            status_code = 400,
            detail      = "Please upload a .eml file (raw email source, headers + body).",
        )

    eml_bytes = await file.read()
    if not eml_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    try:
        # ── Step 1: Run all 18 analysis components ──────────────────────────
        report = analyze_email(eml_bytes, source_name=file.filename)

        # ── Step 2: Save to Supabase + async IPFS/blockchain anchor ─────────
        report = persist_analysis(
            report          = report,
            source_filename = file.filename,
            client_ip       = request.client.host,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {e}")

    return report


# ── Retrieve saved analysis ───────────────────────────────────────────────────

@app.get("/analysis/{analysis_id}")
def get_saved_analysis(analysis_id: str):
    """
    Fetch a previously saved analysis from Supabase by its UUID.
    Blockchain fields (ipfs_cid, tx_hash) will be populated if anchoring has completed.
    """
    try:
        row = get_analysis(analysis_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

    if not row:
        raise HTTPException(status_code=404, detail="Analysis not found.")

    return row


# ── Blockchain verification ───────────────────────────────────────────────────

@app.get("/verify/{analysis_id}")
def verify_analysis(analysis_id: str):
    """
    Reads the anchored record directly from the smart contract.
    Anyone can call this — no transaction, no gas, read-only.

    Returns the on-chain hash. Compare it against SHA-256 of the
    downloaded IPFS report to prove the report was never tampered with.
    """
    try:
        on_chain = verify_on_chain(analysis_id)
    except Exception as e:
        raise HTTPException(
            status_code = 404,
            detail      = f"Record not found on chain or blockchain unreachable: {e}"
        )

    return {
        "analysis_id":      analysis_id,
        "on_chain_record":  on_chain,
        "verification_note": (
            "Download the IPFS file at the returned ipfs_cid. "
            "Compute its SHA-256. It must match report_hash exactly. "
            "If it does, the report has not been modified since analysis. "
            "Legal basis: BSA 2023 Section 63, Indian Evidence Act Section 65B."
        )
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)