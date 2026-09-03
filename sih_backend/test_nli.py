from solcx import compile_source, install_solc
import json, os

# Read the deployment script
with open('deploy_contract.py', 'r', encoding='utf-8') as f:
    SOURCE = f.read()

# Extract the contract source securely
try:
    start = SOURCE.index('pragma solidity')
    # Finds the closing triple quotes after the start of the contract
    end = SOURCE.index('"""', start)
    contract_code = SOURCE[start:end]
    print("Extraction successful!")
    print(contract_code[:100] + "...") # Preview the first 100 chars
except ValueError as e:
    print(f"Error finding markers: {e}")
