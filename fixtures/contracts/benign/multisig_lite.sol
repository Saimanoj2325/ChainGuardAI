// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract MultiSigLite {
    struct Proposal {
        address to;
        uint256 value;
        uint256 approvals;
        bool executed;
    }

    address[3] public signers;
    uint256 public constant THRESHOLD = 2;
    Proposal[] public proposals;
    mapping(uint256 => mapping(address => bool)) public approved;

    constructor(address a, address b, address c) {
        require(a != b && b != c && a != c, "distinct signers");
        signers = [a, b, c];
    }

    modifier onlySigner() {
        require(msg.sender == signers[0] || msg.sender == signers[1] || msg.sender == signers[2], "not signer");
        _;
    }

    receive() external payable {}

    function propose(address to, uint256 value) external onlySigner returns (uint256 id) {
        proposals.push(Proposal(to, value, 0, false));
        id = proposals.length - 1;
    }

    function approve(uint256 id) external onlySigner {
        require(id < proposals.length, "no proposal");
        require(!approved[id][msg.sender], "already approved");
        approved[id][msg.sender] = true;
        proposals[id].approvals += 1;
    }

    function execute(uint256 id) external onlySigner {
        Proposal storage p = proposals[id];
        require(!p.executed, "executed");
        require(p.approvals >= THRESHOLD, "threshold");
        p.executed = true;
        (bool ok, ) = p.to.call{value: p.value}("");
        require(ok, "call failed");
    }
}
