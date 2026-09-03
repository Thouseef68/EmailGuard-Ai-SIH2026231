# infra/ipfs_client.py
"""
Upload analysis reports to IPFS via Pinata.
Free tier: 500MB storage, plenty for JSON reports (~50-100KB each).
"""
import json
import requests
from config import PINATA_JWT


PINATA_URL = "https://api.pinata.cloud/pinning/pinJSONToIPFS"


def upload_to_ipfs(report: dict, analysis_id: str) -> str:
    """
    Upload the full report JSON to IPFS.
    Returns the IPFS CID (Content Identifier) — permanent, content-addressed.
    Raises on failure.
    """
    payload = {
        "pinataContent": report,
        "pinataMetadata": {
            "name": f"emailguard-analysis-{analysis_id}",
            "keyvalues": {
                "analysis_id": analysis_id,
                "verdict":      report.get("final_verdict", "UNKNOWN"),
            }
        },
        "pinataOptions": {
            "cidVersion": 1    # CIDv1 — shorter, URL-safe
        }
    }

    headers = {
        "Authorization": f"Bearer {PINATA_JWT}",
        "Content-Type":  "application/json",
    }

    response = requests.post(
        PINATA_URL,
        headers=headers,
        data=json.dumps(payload),
        timeout=30,
    )
    response.raise_for_status()
    cid = response.json()["IpfsHash"]
    return cid


def get_ipfs_url(cid: str) -> str:
    """Public gateway URL to view/download the report."""
    return f"https://gateway.pinata.cloud/ipfs/{cid}"