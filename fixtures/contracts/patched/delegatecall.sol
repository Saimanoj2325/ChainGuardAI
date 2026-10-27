// SPDX-License-Identifier: MIT
// SYNTHETIC ChainGuard AI test fixture. Not benchmark data.
pragma solidity 0.8.24;

contract ProxyWallet {
    address public owner;
    uint256 public nonce;
    mapping(address => bool) public approvedModules;

    constructor() {
        owner = msg.sender;
    }

    function approveModule(address module, bool approved) external {
        require(msg.sender == owner, "not owner");
        approvedModules[module] = approved;
    }

    function execute(address target, bytes calldata data) external payable returns (bytes memory) {
        require(msg.sender == owner, "not owner");
        require(approvedModules[target], "module not approved");
        nonce += 1;
        (bool ok, bytes memory result) = target.delegatecall(data);
        require(ok, "delegatecall failed");
        return result;
    }
}
