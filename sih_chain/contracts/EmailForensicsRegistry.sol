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