# infra/blockchain_anchor.py
import hashlib
import json
import logging
import os
import time
from web3 import Web3

logger = logging.getLogger(__name__)

# ── Multiple fallback RPCs — tries each until one works ──────────────────────
RPC_FALLBACKS = [
    "https://sepolia.drpc.org",
    "https://eth-sepolia.public.blastapi.io",
    "https://endpoints.omniatech.io/v1/eth/sepolia/public",
    "https://rpc2.sepolia.org",
    "https://1rpc.io/sepolia",
    "https://gateway.tenderly.co/public/sepolia",
]

_abi_path = os.path.join(os.path.dirname(__file__), "contract_abi.json")
with open(_abi_path) as _f:
    CONTRACT_ABI = json.load(_f)

_w3       = None
_contract = None
_account  = None


def _get_web3():
    """Try each RPC fallback until one connects."""
    global _w3, _contract, _account

    # If already connected and still working, reuse
    if _w3 is not None:
        try:
            _w3.eth.block_number  # ping
            return _w3, _contract, _account
        except Exception:
            _w3 = None  # connection dropped, reconnect

    from config import DEPLOYER_PRIVATE_KEY, CONTRACT_ADDRESS

    for rpc_url in RPC_FALLBACKS:
        try:
            logger.info(f"Trying RPC: {rpc_url}")
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 30}))
            if w3.is_connected():
                _w3      = w3
                _account = w3.eth.account.from_key(DEPLOYER_PRIVATE_KEY)
                _contract= w3.eth.contract(
                    address=Web3.to_checksum_address(CONTRACT_ADDRESS),
                    abi=CONTRACT_ABI,
                )
                logger.info(f"Connected via {rpc_url}")
                print(f"[BLOCKCHAIN] RPC connected → {rpc_url}")
                return _w3, _contract, _account
        except Exception as e:
            logger.warning(f"RPC {rpc_url} failed: {e}")
            continue

    raise ConnectionError("All RPC endpoints failed. Check internet connection.")


def compute_report_hash(report: dict) -> tuple:
    canonical = json.dumps(report, sort_keys=True, ensure_ascii=True)
    digest    = hashlib.sha256(canonical.encode("utf-8")).digest()
    return digest.hex(), digest


def anchor_on_chain(
    analysis_id:     str,
    report_hash_hex: str,
    ipfs_cid:        str,
    verdict:         str,
) -> dict:
    from config import DEPLOYER_PRIVATE_KEY, CHAIN_ID

    # Retry up to 3 times across different RPCs on rate-limit errors
    last_error = None
    for attempt in range(3):
        try:
            global _w3
            if attempt > 0:
                _w3 = None   # force reconnect on retry → picks next RPC
                time.sleep(2 * attempt)

            w3, contract, account = _get_web3()
            report_hash_bytes = bytes.fromhex(report_hash_hex)

            nonce = w3.eth.get_transaction_count(account.address)
            tx    = contract.functions.anchorHash(
                analysis_id,
                report_hash_bytes,
                ipfs_cid,
                verdict,
            ).build_transaction({
                "from":     account.address,
                "nonce":    nonce,
                "gas":      250_000,
                "gasPrice": w3.eth.gas_price,
                "chainId":  CHAIN_ID,
            })

            signed  = w3.eth.account.sign_transaction(tx, DEPLOYER_PRIVATE_KEY)
            tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            tx_hex  = tx_hash.hex()
            print(f"[BLOCKCHAIN] TX sent → {tx_hex}")

            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            status  = "success" if receipt.status == 1 else "reverted"

            return {
                "tx_hash":         tx_hex,
                "block_number":    receipt.blockNumber,
                "gas_used":        receipt.gasUsed,
                "status":          status,
                "polygonscan_url": f"https://sepolia.etherscan.io/tx/{tx_hex}",
            }

        except Exception as e:
            last_error = e
            err_str = str(e).lower()
            # Rate limit or RPC error → retry with different RPC
            if "rate" in err_str or "limit" in err_str or "jsonrpc" in err_str or "unexpected" in err_str:
                print(f"[BLOCKCHAIN] RPC rate-limited (attempt {attempt+1}) → retrying with next RPC")
                _w3 = None
                continue
            else:
                raise  # non-rate-limit error → don't retry

    raise Exception(f"All RPC attempts failed: {last_error}")


def verify_on_chain(analysis_id: str) -> dict:
    _, contract, _ = _get_web3()
    report_hash, ipfs_cid, verdict, timestamp, submitter = \
        contract.functions.verifyRecord(analysis_id).call()
    return {
        "report_hash": report_hash.hex(),
        "ipfs_cid":    ipfs_cid,
        "verdict":     verdict,
        "timestamp":   timestamp,
        "submitter":   submitter,
    }