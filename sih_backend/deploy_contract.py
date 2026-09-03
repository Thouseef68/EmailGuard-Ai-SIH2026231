"""
deploy_contract.py
Compiles and deploys EmailForensicsRegistry to Sepolia.
Run once: python deploy_contract.py
Copy the printed contract address into config.py
"""
from solcx import compile_source, install_solc
from web3 import Web3
import os

# ── Config ────────────────────────────────────────────────────────────────────
PRIVATE_KEY  = "a161be1df7f5a021bba1b2045763fd3dda69277dcecb3cd68a954fbdb28cf821"
WALLET_ADDR  = "0x1bdf7809705bd2198556cd814e2e5C37cdceD872"
RPC_URL = "https://1rpc.io/sepolia"

# ── Contract source ───────────────────────────────────────────────────────────
CONTRACT_SOURCE = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract EmailForensicsRegistry {

    struct Record {
        bytes32 reportHash;
        string  ipfsCID;
        uint256 timestamp;
        address submitter;
        string  verdict;
    }

    mapping(string => Record) private _records;
    address public owner;

    event HashAnchored(
        string  indexed analysisId,
        bytes32         reportHash,
        string          ipfsCID,
        string          verdict,
        uint256         timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function anchorHash(
        string  calldata analysisId,
        bytes32          reportHash,
        string  calldata ipfsCID,
        string  calldata verdict
    ) external onlyOwner {
        require(_records[analysisId].timestamp == 0, "Already anchored");
        _records[analysisId] = Record(
            reportHash,
            ipfsCID,
            block.timestamp,
            msg.sender,
            verdict
        );
        emit HashAnchored(analysisId, reportHash, ipfsCID, verdict, block.timestamp);
    }

    function verifyRecord(string calldata analysisId)
        external view
        returns (
            bytes32 reportHash,
            string  memory ipfsCID,
            string  memory verdict,
            uint256 timestamp,
            address submitter
        )
    {
        Record storage r = _records[analysisId];
        require(r.timestamp != 0, "Record not found");
        return (r.reportHash, r.ipfsCID, r.verdict, r.timestamp, r.submitter);
    }
}
"""

def main():
    # Step 1 — Install solc compiler
    print("Installing Solidity compiler 0.8.19...")
    install_solc("0.8.19")
    print("Compiler ready.")

    # Step 2 — Compile contract
    print("Compiling contract...")
    compiled = compile_source(
        CONTRACT_SOURCE,
        output_values=["abi", "bin"],
        solc_version="0.8.19",
    )
    contract_id    = "<stdin>:EmailForensicsRegistry"
    contract_abi   = compiled[contract_id]["abi"]
    contract_bin   = compiled[contract_id]["bin"]
    print(f"Compiled. Bytecode length: {len(contract_bin)} chars")

    # Step 3 — Connect to Sepolia
    print(f"Connecting to Sepolia via {RPC_URL}...")
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    if not w3.is_connected():
        print("❌ Cannot connect to Sepolia RPC. Try a different RPC URL.")
        return
    print(f"✅ Connected. Chain ID: {w3.eth.chain_id}")

    # Check balance
    balance = w3.eth.get_balance(WALLET_ADDR)
    balance_eth = w3.from_wei(balance, "ether")
    print(f"Wallet balance: {balance_eth} ETH")
    if balance == 0:
        print("❌ Wallet has 0 ETH. Cannot deploy.")
        return

    # Step 4 — Deploy
    print("Deploying contract...")
    Contract   = w3.eth.contract(abi=contract_abi, bytecode=contract_bin)
    nonce      = w3.eth.get_transaction_count(WALLET_ADDR)
    tx         = Contract.constructor().build_transaction({
        "from":     WALLET_ADDR,
        "nonce":    nonce,
        "gas":      1_500_000,
        "gasPrice": w3.eth.gas_price,
        "chainId":  11155111,
    })
    signed     = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash    = w3.eth.send_raw_transaction(signed.raw_transaction)
    print(f"Transaction sent: {tx_hash.hex()}")
    print("Waiting for confirmation (~15-30 seconds)...")

    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)

    if receipt.status == 1:
        print(f"\n✅ CONTRACT DEPLOYED SUCCESSFULLY")
        print(f"   Contract address : {receipt.contractAddress}")
        print(f"   Transaction hash : {tx_hash.hex()}")
        print(f"   Etherscan link   : https://sepolia.etherscan.io/tx/{tx_hash.hex()}")
        print(f"\n📋 Copy this into config.py:")
        print(f"   CONTRACT_ADDRESS = \"{receipt.contractAddress}\"")

        # Save ABI to file for blockchain_anchor.py
        import json
        with open("infra/contract_abi.json", "w") as f:
            json.dump(contract_abi, f, indent=2)
        print(f"   ABI saved to infra/contract_abi.json")
    else:
        print("❌ Deployment failed — transaction reverted.")

if __name__ == "__main__":
    main()